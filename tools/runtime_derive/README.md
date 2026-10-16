# runtime_derive — 不用 boot.img、不用逐内核 profile，在设备上现推偏移

对应 issue：https://github.com/YuKongA/ghostlock-app/issues/567

## 解决什么

上游 `tools/extract_rs` 生成 profile 的两个前提：

1. profile 按 `uname -r` 精确匹配，一份内核一个 `.conf`；
2. 生成 profile 需要目标内核镜像（boot.img / OTA / xbl_config.img）。

⇒ 只要 OTA 换一个 build，或者用户拿不到镜像，就只能显示"不支持"。

本目录的工具把 `offset {}` 里的字段改成**在目标机上现推**，输入只有两样：

1. `/proc/kallsyms` 的"名字 + 顺序"（`kptr_restrict=2` 时地址被抹零也能读，普通 shell 权限即可）；
2. 一次内核读（拿到 kallsyms 的 token 表 / names / offsets / num_syms 之后即可自举；脚本里对应 `read_mem()`，离线时用内核 Image 当模拟内存）。

产出是与上游同 schema 的 `.conf`。

## 原理（三步，均已过字节级验证）

1. **token 表定位**：内核 kallsyms 的 token 编码 = **贪心最长匹配**（例如 `t_head` → `ff 68 65 c3`，与镜像逐字节相同）⇒ 用已知符号名当探针 `memmem` 定位 token 表与 names。
   注意 `token_table` 与 `token_index` **不紧贴**（Σ(token_len+1)=897 vs 表长 1024，差 127 字节），所以必须靠"解码自证"来选起点，不能按偏移硬算。
2. **names → 符号名**：按贪心编码解码，再与 `/proc` 里的顺序抽样对账（本例 429/429）。
3. **offsets**：`num_syms`（本例 138408）在 names 之前；offsets 数组用"**`_text` 那项必须为 0**"来钉死 4 字节错位。
   **不需要 relative_base**：偏移取两条目之差 ⇒ 与 KASLR 无关。

## 用法

### A. 离线（在 PC 上，用内核镜像模拟内存）

```bash
python3 boot_unpack.py <boot.img> <out_Image>            # 解出未压缩内核 Image（Android boot v2）
python3 runtime_profile.py <Image> <ksym_order.txt> <out.conf> <uname -r>
```

`ksym_order.txt` 从设备上取（普通 shell 权限即可，地址被抹零不影响）：

```bash
adb shell 'awk "{print \$2, \$3}" /proc/kallsyms' > ksym_order.txt
```

### B. 在线（在目标设备上，只要有一次内核读原语）

把 `runtime_profile.py` 里的 `read_mem()` 换成你的读原语，其余不动；`ksym_order.txt` 直接读 `/proc/kallsyms`（名字 + 顺序）。

### 其余工具

| 文件 | 作用 |
|---|---|
| `ksym_runtime3.py` | 自举原型：定位 token 表 / names / num_syms / offsets，输出"名字 → `_text` 偏移"（依赖最小） |
| `runtime_profile.py` | 产出上游 schema 的 `.conf`（A 类符号偏移 + D 类物理地址公式） |
| `derive_consts.py` | 移植上游 `derive.rs` 的判据推导（rtmutex 判据、cred 布局按值推） |
| `rtmutex_check.py` | 钉死 rtmutex-UAF 判据不是误报（窗口是否被截断、`mrs` 是否在函数体内） |
| `pselect_layout_mine.py` | 尝试用"代码常量挖掘"替代 `derive_pselect_layout()` 的符号 + BTF 硬依赖 |
| `gen_target.py` | 离线路径：`vmlinux-to-elf` 重建符号 ELF → 生成 `target.h` |

（`derive_consts.py` / `rtmutex_check.py` / `pselect_layout_mine.py` 复用了 `runtime_profile.py` 的解析逻辑，文件头会覆写 `sys.argv` 来复用它，默认路径见文件内注释。）

## 验证数据（测试内核 `4.19.113-perf-gec90c723c482`）

- **双路径互证 12/12 一致**（离线：boot.img → `vmlinux-to-elf` → 重建符号表；在线：`/proc/kallsyms` 顺序 + 一次内核读）：

```
init_task            0x2d9be80        ashmem_fops        0x1e8b1d0
ashmem_ioctl         0xc9fe00         ashmem_mmap        0xca0780
ashmem_open          0xca08f8         ashmem_release     0xca0970
anon_pipe_buf_ops    0x18e32c0        noop_llseek        0x23ce28
selinux_state        0x3ae0000        security_hook_heads 0x25b92e8
kmalloc_caches       0x25b8de8        root_task_group    0x3045c00
```

- **4 个字段靠名字语义解析救回**（上游 6.x 模板里这 4 个名字在本内核都不存在）：

```
selinux_enforcing    → selinux_state
slide_nfulnl_logger  → nfulnl_logger
slide_boot_id        → sysctl_bootid
slide_loggers_0_1    → loggers
```

- `selinux_blob_sizes`：本内核没有这个机制 ⇒ 如实置 `null`。
- **物理基址免 root**：`/proc/device-tree/memory/reg` 普通权限可读 ⇒ `kernel_phys_offset = 0x80000000`（与上游 Pixel profile 里 `P0_PHYS_OFFSET == P0_KERNEL_PHYS_LOAD` 同义）。
- **cred 偏移按值推**：读 `init_cred` 的 cap 掩码定宽 ⇒ 本内核是 38 位（不是模板里写死的 41 位）。

样例产物见 `samples/4.19.113-perf-gec90c723c482.conf`。

## 顺带发现的两个上游问题

1. `ensure_rtmutex_43499_unpatched` 的反汇编窗口是 `min(start + 0x2000, 下一个符号)`。
   如果函数很短、下一个符号很远，`mrs xN, sp_el0` 可能落在后面的函数里 ⇒ 误报。
   建议收成 `min(下一个符号, 首条 ret)`。
   （本例不是误报：`remove_waiter` 真实大小 0x228，首条 `ret` 在第 113 条，`mrs x20, sp_el0` 在 `+0x30`，确在函数体内。）
2. `derive_pselect_layout()` 硬依赖 `futex_wait_requeue_pi` 符号 + BTF：符号被内联 / 无 BTF 时直接失败，
   但 PI 那套机器其实都在（`remove_waiter`、`task_blocks_on_rt_mutex`、`rt_mutex_adjust_prio_chain`、`rt_mutex_*_proxy_lock`、`futex_lock_pi*`…）。
   建议按 `tcp_zerocopy_receive_inlined` 的做法改成功能判据：定位内联块（`FUTEX_WAIT_REQUEUE_PI = 11` → opcode 11/12 + 块内 `add xN, sp, #imm`）。

## 边界

只解决"配置 / 偏移"这一层，**不扩展 route 的代际覆盖**。
本例三条上游路线均不适用：multicast 没有 `ip_setsockopt` 的复制窗口；`tcp_zerocopy` 的符号不存在；pselect 入口即失败（见上）。

## Requirements

python3（核心流程无第三方依赖）；只有反汇编相关脚本需要 `capstone`（`pip install capstone`）。
所有脚本的默认路径都可以用 argv 覆盖。
