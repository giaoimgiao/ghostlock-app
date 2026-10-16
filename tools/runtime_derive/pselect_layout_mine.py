#!/usr/bin/env python3
# pselect_layout_mine.py —— 用"代码常量挖掘"替代他们的 (符号名 + BTF) 要求（离线）
#
# 他们需要:  futex_wait_requeue_pi 符号 + BTF 里的 rt_mutex_waiter.pi_tree/wake_state
# 本机现实:  该函数被内联(符号消失) + 无 BTF
# 我们的替代:
#   1) 在 do_futex 里找 FUTEX_WAIT_REQUEUE_PI(=9) 的分支  → 定位内联的 requeue-PI 代码块
#   2) 在该块里找 `add xN, sp, #imm`（waiter 局部变量的栈槽）
#   3) 紧跟其后的 `add xM, xN, #K` 里的常数 K = rt_mutex_waiter 的字段偏移（pi_tree/task/wake_state…）
import sys, re, importlib.util
from collections import Counter

spec = importlib.util.spec_from_file_location('rp', '/tmp/ourpy/runtime_profile.py')
rp = importlib.util.module_from_spec(spec)
sys.argv = ['runtime_profile.py', '/tmp/umi_Image', '/sdcard/Download/ksym_order.txt',
            '/tmp/out_ignore3.conf', '4.19.113-perf-gec90c723c482']
spec.loader.exec_module(rp)
BLOB = rp.BLOB
SYMS = {n: rp.offs[i] - rp.t_off for n, i in rp.idx_of.items()}
SORTED = sorted(SYMS.values())
INV = {}
for n, o in SYMS.items():
    INV.setdefault(o, n)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dis(fn, cap=0x8000):
    if fn not in SYMS:
        return None
    a = SYMS[fn]
    nx = next((o for o in SORTED if o > a), a + cap)
    b = min(a + cap, nx)
    out = []
    for ins in md.disasm(BLOB[a:b], a):
        out.append((ins.address, ins.mnemonic, ins.op_str))
    return out

d = dis('do_futex')
print('[*] do_futex: %s 条指令' % (len(d) if d else 0))
if d:
    # 1) 找 op == 9 的分支（cmp/subs w?, #9 或 mov w?, #9）
    branches = []
    for i, (a, m, o) in enumerate(d):
        if m in ('cmp', 'subs') and re.search(r',\s*#0x9$', o):
            branches.append(i)
    print('[*] `#0x9`(FUTEX_WAIT_REQUEUE_PI) 相关比较: %d 处 -> 行号 %s' % (len(branches), branches[:6]))

    # 2/3) 在整段 do_futex 里挖 waiter 栈槽与字段偏移
    sp_add = [(i, a, o) for i, (a, m, o) in enumerate(d) if m == 'add' and re.match(r'x\d+, sp, #0x[0-9a-f]+$', o)]
    print('[*] add xN, sp, #imm 共 %d 处' % len(sp_add))
    cand = []
    for i, a, o in sp_add:
        reg, imm = o.split(',')[0], int(o.split('#')[-1], 16)
        if imm < 0x20 or imm > 0x200:
            continue
        fields = []
        for j in range(i + 1, min(i + 60, len(d))):
            m2, o2 = d[j][1], d[j][2]
            if m2 == 'add':
                mm = re.match(r'x\d+, %s, #0x([0-9a-f]+)$' % re.escape(reg), o2)
                if mm:
                    fields.append(int(mm.group(1), 16))
        cand.append((imm, reg, fields))
    print('[*] 候选 waiter 栈槽（imm 0x20..0x200）:')
    for imm, reg, fields in cand[:12]:
        print('    sp+%#05x (%s)  后继字段常数: %s' % (imm, reg, [hex(f) for f in fields[:8]]))

    # 汇总所有字段常数（pi_tree 等在代码里会反复出现）
    allf = Counter()
    for imm, reg, fields in cand:
        for f in fields:
            allf[f] += 1
    print('[*] 字段常数频度 Top8: %s' % [(hex(k), v) for k, v in allf.most_common(8)])

# 对照：multicast 路线要的 ip_setsockopt 里的 copy 窗口
ip = dis('ip_setsockopt', cap=0x6000)
if ip:
    movs = [(a, o) for a, m, o in ip if m in ('mov', 'movz') and o.startswith('w2, #0x')]
    adds = [(a, o) for a, m, o in ip if m == 'add' and re.match(r'x\d+, sp, #0x[0-9a-f]+$', o)]
    print('[*] ip_setsockopt: mov w2,#imm %d 处 %s ; add xN,sp,#imm %d 处 %s' %
          (len(movs), [o for _, o in movs[:4]], len(adds), [o for _, o in adds[:4]]))