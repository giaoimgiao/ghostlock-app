#!/usr/bin/env python3
# ksym_runtime3.py —— 运行期自解析（最终形态）
#
# 只用两样输入：
#   ① /proc/kallsyms 的顺序(类型+名字)  ← 无权限即可读，地址被抹零不影响
#   ② 一个"读内核内存"的能力            ← 离线用镜像模拟，线上换成 exp 的读写原语
#
# 路径：
#   A. 找 kallsyms_token_index 候选 (u16 递增, 首项0)
#   B. 对每个候选 token 表起点 B：把已知名字【贪心编码】成 token 索引字节 → memmem 定位 kallsyms_names
#      （已证：内核的编码就是贪心最长匹配，与镜像逐字节一致）
#   C. 从 names 往前退：num_syms(u64) / relative_base(u64) / kallsyms_offsets[N](u32)
#   D. address = relative_base + offsets[i]；偏移 = 与 _text 项作差（⇒ 与 KASLR 无关）
#   E. 与离线 ELF(gen_target.py) 交叉验证
import sys, struct, re, os

IMG = sys.argv[1] if len(sys.argv) > 1 else '/tmp/umi_Image'
ORDER = sys.argv[2] if len(sys.argv) > 2 else '/sdcard/Download/ksym_order.txt'
ELF_H = '/sdcard/Download/ugirl/2026-10-12/umi_target.h'
BLOB = open(IMG, 'rb').read()
LIM = len(BLOB)

pool = []
for ln in open(ORDER, errors='replace'):
    p = ln.split()
    if len(p) >= 2:
        pool.append((p[0], p[1]))
print('[*] /proc 顺序符号 %d 条' % len(pool))

# ---------- A. token_index 候选 ----------
def index_candidates(cap=40):
    out = []
    for pi in range(0x100000, min(LIM, 0x3000000) - 512, 2):
        h = struct.unpack_from('<4H', BLOB, pi)
        if h[0] != 0 or not (0 < h[1] <= 8) or not (h[1] < h[2] < h[3] <= 64):
            continue
        idx = struct.unpack_from('<256H', BLOB, pi)
        ok = True
        for k in range(1, 256):
            if idx[k] <= idx[k - 1] or idx[k] > 0x4000:
                ok = False; break
        if ok:
            out.append((pi, idx))
            if len(out) >= cap:
                break
    return out

CAND = index_candidates()
print('[*] token_index 候选 %d 个' % len(CAND))

def build_tokens(B, idx):
    toks = []
    for k in range(256):
        s = B + idx[k]
        if s + 1 > LIM:
            return None
        e = BLOB.find(b'\x00', s, min(s + 80, LIM))
        if e < 0:
            return None
        t = BLOB[s:e]
        if any(c < 0x20 or c > 0x7e for c in t):
            return None
        toks.append(t)
    return toks

def greedy(toks, name):
    nb = name.encode('latin1')
    out = bytearray(); i = 0
    while i < len(nb):
        best = None
        for k, t in enumerate(toks):
            if t and nb.startswith(t, i):
                if best is None or len(t) > len(toks[best]):
                    best = k
        if best is None:
            return None
        out.append(best); i += len(toks[best])
    return bytes(out)

def find_names(toks):
    pats = []
    for j in range(4):
        b = greedy(toks, pool[j][0] + pool[j][1])
        if b is None:
            return None
        pats.append(bytes([len(b)]) + b)
    return BLOB.find(b''.join(pats))

hit = None
for pi, idx in CAND:
    for B in range(pi - 4096, pi - 200, 4):
        toks = build_tokens(B, idx)
        if toks is None:
            continue
        pos = find_names(toks)
        if pos is not None and pos >= 0:
            hit = (B, pi, toks, idx, pos)
            break
    if hit:
        break
if not hit:
    print('[!] 未定位到 kallsyms_names'); sys.exit(1)
B, pi, toks, idx, names_off = hit
print('[+] token_table=%#x  token_index=%#x  names=%#x' % (B, pi, names_off))

# ---------- C. 解码全部名字 ----------
def decode_all(p, cap=400000):
    out = []
    i = p
    while i < LIM and len(out) < cap:
        L = BLOB[i]; i += 1
        if L & 0x80:
            if i >= LIM: break
            L = ((L & 0x7f) << 8) | BLOB[i]; i += 1
        if L == 0 or L > 64 or i + L > LIM:
            break
        s = bytearray()
        for k in range(L):
            s += toks[BLOB[i + k]]
        i += L
        out.append(bytes(s))
    return out, i

dec, names_end = decode_all(names_off)
print('[+] 解出符号 %d 条；names 块 = %#x..%#x (%d 字节)' % (len(dec), names_off, names_end, names_end - names_off))
same = sum(1 for j in range(0, min(len(dec), 3000), 7)
           if dec[j][1:].decode('latin1') == pool[j][1] and chr(dec[j][0]) == pool[j][0])
tot = len(range(0, min(len(dec), 3000), 7))
print('[+] 与 /proc 顺序抽样一致 %d/%d' % (same, tot))

N = len(dec)

# ---------- C2. 往前退: num_syms / relative_base / offsets ----------
found = None
for back in range(8, 4096, 8):
    p = names_off - back
    if p < 0:
        break
    v = struct.unpack_from('<Q', BLOB, p)[0]
    if v == N:                                   # kallsyms_num_syms
        rb_pos = p - 8
        if rb_pos < 8:
            continue
        rb = struct.unpack_from('<Q', BLOB, rb_pos)[0]
        if not (0xffffff0000000000 <= rb <= 0xffffffff00000000):
            continue
        off_pos = rb_pos - 4 * N
        if off_pos < 0:
            continue
        found = (p, rb_pos, rb, off_pos)
        break
if not found:
    print('[!] 没找到 num_syms/relative_base/offsets'); sys.exit(1)
ns_pos, rb_pos, rb, off_pos = found
print('[+] num_syms@%#x = %d ; relative_base@%#x = %#x ; offsets@%#x' % (ns_pos, N, rb_pos, rb, off_pos))

offs = struct.unpack_from('<%dI' % N, BLOB, off_pos)
addr = [rb + o for o in offs]

# ---------- D/E. 输出偏移(相对 _text) 并交叉验证 ----------
idx_of = {}
for i in range(N):
    nm = dec[i][1:].decode('latin1')
    if nm not in idx_of:
        idx_of[nm] = i
i_text = idx_of.get('_text')
if i_text is None:
    print('[!] 名字表里没有 _text'); sys.exit(1)
print('[+] _text 地址 = %#x  (KASLR 后)' % addr[i_text])

want = ['init_task', 'ashmem_fops', 'ashmem_ioctl', 'ashmem_mmap', 'ashmem_open', 'ashmem_release',
        'ashmem_show_fdinfo', 'anon_pipe_buf_ops', 'noop_llseek', 'generic_file_splice_read',
        'selinux_state', 'security_hook_heads', 'kmalloc_caches', 'root_task_group']
NAME2DEF = {'init_task': 'INIT_TASK', 'ashmem_fops': 'ASHMEM_FOPS', 'ashmem_ioctl': 'ASHMEM_IOCTL',
            'ashmem_mmap': 'ASHMEM_MMAP', 'ashmem_open': 'ASHMEM_OPEN', 'ashmem_release': 'ASHMEM_RELEASE',
            'ashmem_show_fdinfo': 'ASHMEM_SHOW_FDINFO', 'anon_pipe_buf_ops': 'ANON_PIPE_BUF_OPS',
            'noop_llseek': 'NOOP_LLSEEK', 'generic_file_splice_read': 'COPY_SPLICE_READ',
            'selinux_state': 'SELINUX_ENFORCING', 'security_hook_heads': 'SECURITY_HOOK_HEADS',
            'kmalloc_caches': 'KMALLOC_CACHES', 'root_task_group': 'ROOT_TASK_GROUP'}
elf = {}
if os.path.exists(ELF_H):
    for ln in open(ELF_H):
        m = re.match(r'#define\s+(\w+)_OFF\s+(0x[0-9a-f]+)ULL', ln)
        if m:
            elf[m.group(1)] = int(m.group(2), 16)

print('[*] 运行期解析 vs 离线 ELF:')
ok = 0
for w in want:
    i = idx_of.get(w)
    if i is None:
        print('    %-24s 未找到' % w); continue
    rt = addr[i] - addr[i_text]
    e = elf.get(NAME2DEF.get(w))
    flag = '' if e is None else ('一致' if rt == e else '不同(差 %+d)' % (rt - e))
    if e is not None and rt == e:
        ok += 1
    print('    %-24s 运行期=%#x  离线=%s  %s' % (w, rt, hex(e) if e else '-', flag))
print('[=] 逐项一致 %d/%d' % (ok, len([w for w in want if NAME2DEF.get(w) in elf])))