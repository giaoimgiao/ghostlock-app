#!/usr/bin/env python3
# rtmutex_check.py —— 把他们的 rtmutex 判据钉到 4.19 上（离线，逐字节看）
#
# 要回答两个问题：
#   A. 反汇编窗口里那条 `mrs xN, sp_el0` 到底在不在 remove_waiter() 体内（还是后面的函数）？
#   B. remove_waiter() 的真实形状：调用了谁？（rt_mutex_adjust_prio_chain 等）
import sys, re, importlib.util

spec = importlib.util.spec_from_file_location('rp', '/tmp/ourpy/runtime_profile.py')
rp = importlib.util.module_from_spec(spec)
sys.argv = ['runtime_profile.py', '/tmp/umi_Image', '/sdcard/Download/ksym_order.txt',
            '/tmp/out_ignore2.conf', '4.19.113-perf-gec90c723c482']
spec.loader.exec_module(rp)

BLOB = rp.BLOB
SYMS = {n: rp.offs[i] - rp.t_off for n, i in rp.idx_of.items()}
INV = {}
for n, o in SYMS.items():
    INV.setdefault(o, n)
SORTED = sorted(SYMS.values())

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def next_sym(off):
    for o in SORTED:
        if o > off:
            return o, INV.get(o, '?')
    return None, None

def disasm_range(a, b):
    return [(ins.address - a, '%s %s' % (ins.mnemonic, ins.op_str))
            for ins in md.disasm(BLOB[a:b], a)]

CAP = 0x2000
for fn in ('remove_waiter', 'task_blocks_on_rt_mutex', 'rt_mutex_adjust_prio_chain'):
    if fn not in SYMS:
        print('[%s] 不在符号表' % fn); continue
    start = SYMS[fn]
    nx, nxname = next_sym(start)
    size = (nx - start) if nx else None
    stop = min(start + CAP, nx if nx else start + CAP)
    ins = disasm_range(start, stop)
    rets = [i for i, (o, t) in enumerate(ins) if re.match(r'^ret\b', t)]
    first_ret = rets[0] if rets else None
    mrs_hits = [(i, o, t) for i, (o, t) in enumerate(ins)
                if re.match(r'(?i)^mrs\s+x\d+,\s*(sp_el0|s3_0_c4_c1_0)$', t)]
    print('=== %s ===' % fn)
    print('    起点 %#x  下一个符号 %s@%#x  真实大小 %s  反汇编 %d 条(窗口 %#x)' %
          (start, nxname, nx or 0, hex(size) if size else '?', len(ins), stop - start))
    print('    首条 ret 在第 %s 条（=函数体大致结束处）' % (first_ret if first_ret is not None else '无'))
    for i, off, t in mrs_hits:
        inside = (first_ret is None) or (i < first_ret)
        print('    mrs 命中: 第 %d 条 (+%#x)  %s   ⇒ %s' %
              (i, off, t, '★在 %s 体内' % fn if inside else '✗ 在首条 ret 之后 ⇒ 属于后续函数，判据误报'))
    # 调用关系
    calls = [(o, t) for o, t in ins if t.startswith('bl ')]
    named = []
    for o, t in calls[:200]:
        tgt = int(t.split()[-1], 16) if t.split()[-1].startswith('0x') else None
        if tgt is not None and tgt in INV:
            named.append(INV[tgt])
    print('    调用的具名函数: %s' % (named[:8] if named else '（都是内联/静态，无符号）'))
    print()