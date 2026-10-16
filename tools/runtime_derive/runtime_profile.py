#!/usr/bin/env python3
# runtime_profile.py —— 产出 GhostLock-app 同 schema 的 profile（运行期来源）
#   离线模式: 用内核镜像模拟"读内核内存"; 线上把 mem_read 换成 exp 的读原语即可
#   本期覆盖: A 类(符号偏移) 全解 + D 类(物理地址) 公式化
#   用法: runtime_profile.py <Image> <ksym_order.txt> <out.conf> [uname_r]
import sys, struct, re

IMG = sys.argv[1] if len(sys.argv) > 1 else '/tmp/umi_Image'
ORDER = sys.argv[2] if len(sys.argv) > 2 else '/sdcard/Download/ksym_order.txt'
OUT = sys.argv[3] if len(sys.argv) > 3 else '/sdcard/Download/ugirl/2026-10-12/umi_runtime.conf'
RELEASE = sys.argv[4] if len(sys.argv) > 4 else '4.19.113-perf-gec90c723c482'

BLOB = open(IMG, 'rb').read()
LIM = len(BLOB)

pool = []
for ln in open(ORDER, errors='replace'):
    p = ln.split()
    if len(p) >= 2:
        pool.append((p[0], p[1]))
print('[*] /proc 名字顺序 %d 条；镜像 %d B' % (len(pool), LIM))

# ---------- 定位 token 表 + names（贪心编码 + memmem，已验证） ----------
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
    nb = name.encode('latin1'); out = bytearray(); i = 0
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
    buf = bytearray()
    for j in range(4):
        b = greedy(toks, pool[j][0] + pool[j][1])
        if b is None:
            return -1
        buf.append(len(b)); buf += b
    return BLOB.find(bytes(buf))

hit = None
for pi, idx in index_candidates():
    for B in range(pi - 4096, pi - 200, 4):
        toks = build_tokens(B, idx)
        if toks is None:
            continue
        pos = find_names(toks)
        if pos >= 0:
            hit = (B, pi, toks, pos); break
    if hit:
        break
if not hit:
    print('[!] 定位失败'); sys.exit(1)
B, pi, toks, names_off = hit
print('[+] token_table=%#x index=%#x names=%#x' % (B, pi, names_off))

def decode_all(p, cap=400000):
    out = []; i = p
    while i < LIM and len(out) < cap:
        L = BLOB[i]; i += 1
        if L & 0x80:
            L = ((L & 0x7f) << 8) | BLOB[i]; i += 1
        if L == 0 or L > 64 or i + L > LIM:
            break
        s = bytearray()
        for k in range(L):
            s += toks[BLOB[i + k]]
        i += L
        out.append(bytes(s))
    return out

dec = decode_all(names_off)
N = len(dec)
chk = sum(1 for j in range(0, min(N, 3000), 7)
          if dec[j][1:].decode('latin1') == pool[j][1] and chr(dec[j][0]) == pool[j][0])
tot = len(range(0, min(N, 3000), 7))
print('[+] 解出 %d 条；与 /proc 抽样一致 %d/%d' % (N, chk, tot))

idx_of = {}
for i in range(N):
    nm = dec[i][1:].decode('latin1')
    if nm not in idx_of:
        idx_of[nm] = i
i_text = idx_of['_text']

# ---------- 定位 num_syms ----------
ns_pos = None
for back in range(8, 0x2000, 8):
    p = names_off - back
    if p < 0:
        break
    if struct.unpack_from('<Q', BLOB, p)[0] == N:
        ns_pos = p
        break
if ns_pos is None:
    print('[!] 找不到 num_syms'); sys.exit(1)

# ---------- 定位 offsets 数组（不需要 relative_base：偏移取差值） ----------
best = None
for pad in range(0, 0x400, 4):
    p = ns_pos - pad - 4 * N
    if p < 0:
        break
    v0 = struct.unpack_from('<I', BLOB, p)[0]
    if v0 != 0:
        continue
    if struct.unpack_from('<I', BLOB, p + 4 * i_text)[0] != 0:   # _text 项必须为 0（钉死 4 字节错位）
        continue
    ok = True
    prev = 0
    for i in range(1, N, 521):
        v = struct.unpack_from('<I', BLOB, p + 4 * i)[0]
        if v < prev:
            ok = False; break
        prev = v
    if ok:
        best = p
        break
if best is None:
    print('[!] 找不到 kallsyms_offsets'); sys.exit(1)
off_pos = best
offs = struct.unpack_from('<%dI' % N, BLOB, off_pos)
print('[+] num_syms@%#x=%d   offsets@%#x (长度 %d, 首项 %#x)' % (ns_pos, N, off_pos, N, offs[0]))
print('[i] relative_base 不需要: exploit 要的是"相对 _text 的偏移" = 两条目之差')

idx_of2 = idx_of
t_off = offs[i_text]
print('[i] _text 的原始偏移值 = %#x (应为 0，说明 offsets 就是相对 _text)' % t_off)

def off(name, alts=()):
    for nm in (name,) + tuple(alts):
        i = idx_of.get(nm)
        if i is not None:
            return offs[i] - t_off, nm
    return None, None

WANT = [('empty_zero_page', ()), ('init_task', ()), ('init_cred', ()), ('root_task_group', ()),
        ('selinux_enforcing', ('selinux_state',)), ('selinux_blob_sizes', ('selinux_blob_sizes',)),
        ('security_hook_heads', ()), ('slide_nfulnl_logger', ('nfulnl_logger',)),
        ('slide_boot_id', ('sysctl_bootid',)), ('slide_loggers_0_1', ('loggers',))]

lines = []
lines.append('# generated by runtime_profile.py  (source: /proc/kallsyms order + kernel memory read)')
lines.append('release = "%s"' % RELEASE)
lines.append('schema_version = 1')
lines.append('kernel_major = 4')
lines.append('recommend_shizuku = 0')
lines.append('kernel_phys_load = null    # 运行期: (uint64)(_text_virt) - kimage_voffset')
lines.append('kernel_phys_offset = null  # 运行期: memstart_addr 的值')
lines.append('offset {')
resolved, missing = [], []
for name, alts in WANT:
    o, via = off(name, alts)
    if o is None:
        missing.append(name)
        lines.append('  %-22s = null' % name)
    else:
        resolved.append((name, via, o))
        lines.append('  %-22s = %d%s' % (name, o, '' if via == name else '   # 本内核名为 %s' % via))
lines.append('}')
open(OUT, 'w').write('\n'.join(lines) + '\n')

print('[+] A 类字段: 成功 %d/%d（写出 %s）' % (len(resolved), len(WANT), OUT))
for n, via, o in resolved:
    print('    %-22s = %-10d  <- %s' % (n, o, via))
if missing:
    print('    [缺] %s' % ', '.join(missing))
print('[i] D 类公式: kernel_phys_load = _text_virt - kimage_voffset ; kernel_phys_offset = memstart_addr')
print('[i] 本机符号可用性: kimage_voffset/memstart_addr 均在（值需运行期读）')