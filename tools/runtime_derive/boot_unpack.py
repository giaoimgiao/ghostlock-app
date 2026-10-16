#!/usr/bin/env python3
# boot_unpack.py —— 从 Android boot 镜像里抠出内核 Image（不依赖 magiskboot）
#   支持 header v0/v1/v2：magic 'ANDROID!'，kernel 位于 page_size 偏移；自动识别 gzip/lz4/zstd/xz/raw
import struct, sys, os, gzip, io, subprocess

SRC = sys.argv[1] if len(sys.argv) > 1 else '/sdcard/Download/umi_boot.img'
OUT = sys.argv[2] if len(sys.argv) > 2 else '/tmp/umi_Image'

d = open(SRC, 'rb').read()
print('[*] 文件 %d 字节' % len(d))
if d[:8] != b'ANDROID!':
    print('[!] 不是 ANDROID! 头: %r' % d[:16])
    tail = d.rfind(b'\x1f\x8b\x08')
    print('    尝试直接找 gzip 头: %s' % tail)
    sys.exit(1)

ksize, kaddr, rsize, raddr, ssize, saddr, tags, page = struct.unpack('<8I', d[8:40])
hv = struct.unpack('<I', d[40:44])[0] if len(d) >= 44 else 0
print('[+] kernel_size=%d (%.2f MB) page=%d header_version=%d ramdisk=%d' % (ksize, ksize / 1048576, page, hv, rsize))

kern = d[page:page + ksize]
open('/tmp/umi_kernel.raw', 'wb').write(kern)
print('[+] 已保存原始内核块 /tmp/umi_kernel.raw (%d B)，前 16 字节: %s' % (len(kern), kern[:16].hex()))

def try_decomp(blob):
    if blob[:2] == b'\x1f\x8b':
        try:
            out = gzip.decompress(blob)
            return 'gzip', out
        except Exception as e:
            print('    gzip 失败: %s' % e)
    if blob[:4] == b'\x04\x22\x4d\x18':
        for cmd in (['lz4', '-d', '-c'], ['python3', '-c',
                    'import lz4.frame,sys;sys.stdout.buffer.write(lz4.frame.decompress(sys.stdin.buffer.read()))']):
            try:
                p = subprocess.run(cmd, input=blob, capture_output=True, timeout=180)
                if p.returncode == 0 and len(p.stdout) > 1024:
                    return 'lz4', p.stdout
            except Exception:
                pass
    if blob[:4] == b'\x28\xb5\x2f\xfd':
        try:
            p = subprocess.run(['zstd', '-d', '-c'], input=blob, capture_output=True, timeout=180)
            if p.returncode == 0:
                return 'zstd', p.stdout
        except Exception:
            pass
    if blob[:6] == b'\xfd7zXZ\x00':
        try:
            p = subprocess.run(['xz', '-d', '-c'], input=blob, capture_output=True, timeout=180)
            if p.returncode == 0:
                return 'xz', p.stdout
        except Exception:
            pass
    return 'raw', blob

kind, img = try_decomp(kern)
print('[+] 压缩方式: %s -> %d 字节' % (kind, len(img)))
open(OUT, 'wb').write(img)
print('[+] 内核 Image 已保存 %s' % OUT)
print('    magic@56 = %r   (arm64 内核应为 b"ARM\\x64")' % img[56:60])
print('    _text 前 8 字节 = %s' % img[:8].hex())