#!/usr/bin/env python3
# gen_target.py —— 「通用偏移表生成器」
#   输入: 由内核 Image 重建出的 vmlinux.elf（vmlinux-to-elf / 任何带符号的 ELF）
#   输出: target.h —— 与 IonStack 公开 exp 同形状的偏移表（KIMAGE_TEXT_BASE + 各符号 _OFF）
#   意义: 替代"每个设备/每个 build 手写一张表"，任何能拿到内核镜像的设备都能自动生成
import sys, re
from elftools.elf.elffile import ELFFile

ELF = sys.argv[1] if len(sys.argv) > 1 else '/tmp/umi_vmlinux.elf'
OUT = sys.argv[2] if len(sys.argv) > 2 else '/tmp/umi_target.h'

# 需要解析的名字 -> 候选内核符号（第一个命中者胜出；None 表示允许缺失）
WANT = [
    ('ASHMEM_MISC_FOPS',    ['ashmem_misc_fops', 'ashmem_fops']),
    ('ASHMEM_FOPS',         ['ashmem_fops']),
    ('ASHMEM_IOCTL',        ['ashmem_ioctl']),
    ('ASHMEM_COMPAT_IOCTL', ['ashmem_compat_ioctl']),
    ('ASHMEM_MMAP',         ['ashmem_mmap']),
    ('ASHMEM_OPEN',         ['ashmem_open']),
    ('ASHMEM_RELEASE',      ['ashmem_release']),
    ('ASHMEM_SHOW_FDINFO',  ['ashmem_show_fdinfo']),
    ('CONFIGFS_READ_ITER',  ['configfs_read_iter']),
    ('CONFIGFS_BIN_WRITE_ITER', ['configfs_bin_write_iter']),
    ('COPY_SPLICE_READ',    ['copy_splice_read', 'generic_file_splice_read']),
    ('NOOP_LLSEEK',         ['noop_llseek']),
    ('INIT_TASK',           ['init_task']),
    ('ROOT_TASK_GROUP',     ['root_task_group']),
    ('SELINUX_BLOB_SIZES',  ['selinux_blob_sizes', 'blob_sizes']),
    ('SELINUX_ENFORCING',   ['selinux_enforcing', 'selinux_state']),
    ('SECURITY_HOOK_HEADS', ['security_hook_heads']),
    ('KMALLOC_CACHES',      ['kmalloc_caches']),
    ('ANON_PIPE_BUF_OPS',   ['anon_pipe_buf_ops']),
    ('SLIDE_NFULNL_LOGGER', ['nfulnl_logger', 'nfulnl_net_ops']),
    ('SLIDE_RANDOM_BOOT_ID_DATA', ['random_boot_id', 'boot_id_data', 'sysctl_bootid']),
    ('SLIDE_SYSCTL_BOOTID', ['sysctl_bootid', 'boot_id']),
]

f = open(ELF, 'rb')
e = ELFFile(f)
symtab = e.get_section_by_name('.symtab')
if symtab is None:
    print('[!] 没有 .symtab'); sys.exit(1)

table = {}
for s in symtab.iter_symbols():
    n = s.name
    if n and n not in table and s['st_value']:
        table[n] = s['st_value']
print('[*] ELF 符号 %d 个' % len(table))

base = table.get('_text') or table.get('_stext')
if not base:
    print('[!] 找不到 _text'); sys.exit(1)
print('[*] _text = %#x' % base)

lines = ['#ifndef OFFSET_H', '#define OFFSET_H',
         '/* 自动生成: gen_target.py <vmlinux.elf>  —— 由设备自身内核镜像推导, 无需厂商数据 */',
         '#define KIMAGE_TEXT_BASE %#xULL' % base]
found, missing = [], []
for define, cands in WANT:
    hit = None
    for c in cands:
        if c in table:
            hit = (c, table[c]); break
    if not hit:
        missing.append(define); continue
    name, addr = hit
    off = addr - base
    if off < 0 or off > 0x10000000:
        missing.append('%s(越界 %#x)' % (define, off)); continue
    lines.append('#define %-24s %#xULL        /* %s */' % (define + '_OFF', off, name))
    lines.append('#define %-24s (KIMAGE_TEXT_BASE + %s_OFF)' % (define, define))
    found.append((define, name, off))
lines += ['#endif', '']
open(OUT, 'w').write('\n'.join(lines))

print('[*] 解析成功 %d / %d，缺失 %d' % (len(found), len(WANT), len(missing)))
for d, n, o in found:
    print('    %-24s %#010x   <- %s' % (d, o, n))
if missing:
    print('    [缺失] %s' % ', '.join(missing))
print('[+] 写出 %s' % OUT)