# Replay-Jasmine

## Challenge

The challenge gives us:

```text
chall.json
_aux.py
```

The goal is to recover the plaintext stored in the `finally` field of `chall.json`.

The challenge has three main parts:

1. Recover two hidden vectors from small-error modular systems.
2. Pack those vectors in the exact byte format expected by the challenge.
3. Derive the encryption key with scrypt and decrypt the final blob.

The recovered flag is:

```text
LYKNCTF{Connect_The_World}
```

## Recognizing the two LWE systems

The useful fields in `chall.json` are:

| Field | Size | Meaning |
|---|---:|---|
| `Alcginlcgchall` | `32 x 20` | first matrix |
| `donttimebabybob` | `32` | first target vector |
| `timeforR` | `28 x 18` | second matrix |
| `c` | `28` | second target vector |
| `finally` | hex string | encrypted flag |

The values in the first system are between `0` and `768`, giving:

```text
q1 = 769
```

The values in the second system are between `0` and `502`, giving:

```text
q2 = 503
```

The systems can be written as:

```text
b1 = A1s1 + e1 mod 769
b2 = A2s2 + e2 mod 503
```

The vectors `e1` and `e2` contain very small errors.

Both systems have more equations than unknowns:

```text
32 > 20
28 > 18
```

This makes them good targets for a lattice closest-vector attack.

## Turning the problem into CVP

For a matrix `A` modulo `q`, build the lattice:

```text
L = qZ^m + AZ^n
```

The public vector satisfies:

```text
b = v + e
```

where `v` belongs to the lattice and `e` is small.

Finding the closest lattice vector to `b` gives:

```text
v = A s mod q
```

We can then solve for `s` over `GF(q)`.

The Sage function used for both systems is:

```python
from sage.all import *


def centered(x, q):
    x = int(x) % q
    return x - q if x > q // 2 else x


def recover_lwe(A_raw, b_raw, q):
    A = Matrix(ZZ, A_raw)
    b = vector(ZZ, b_raw)
    m, n = A.dimensions()

    generators = (q * identity_matrix(ZZ, m)).stack(
        A.transpose()
    )

    lattice = IntegerLattice(
        generators,
        lll_reduce=True,
    )

    closest = vector(
        ZZ,
        lattice.closest_vector(b),
    )

    field = GF(q)

    secret_mod = A.change_ring(field).solve_right(
        vector(
            field,
            [int(x) % q for x in closest],
        )
    )

    secret = [
        centered(int(x), q)
        for x in secret_mod
    ]

    error = [
        centered(
            b[i] - sum(
                int(A[i, j]) * secret[j]
                for j in range(n)
            ),
            q,
        )
        for i in range(m)
    ]

    return secret, error
```

## First secret

Solving the first system modulo `769` gives:

```text
s1 = [
  -1,  3,  3,  1,  2,  3,  2,  3,  2,  0,
   3, -1,  3,  0,  3,  2, -1, -2, -2,  1
]
```

The error vector is:

```text
e1 = [
   0,  1, -1, -2,  0,  0,  1, -2,
   1,  1,  0,  2, -2,  1, -2, -2,
   1,  0,  1, -2, -2, -1, -1, -2,
   0, -1, -2, -1,  2,  2, -2,  2
]
```

Every value satisfies:

```text
|e1[i]| <= 2
```

That confirms the recovered secret is correct.

## Second secret

Solving the second system modulo `503` gives:

```text
s2 = [
  -2, -2,  1, -1, -2,  2,  2,  0, -1,
  -2, -2,  0,  1,  0, -1,  0, -1,  2
]
```

The error vector is:

```text
e2 = [
   1,  1,  1, -1,  0,  0,  0,  0,
   1,  0,  1, -1,  0,  0,  1,  0,
   1,  1,  0,  1,  1,  0, -1,  0,
   0,  1, -1, -1
]
```

Every value satisfies:

```text
|e2[i]| <= 1
```

## Correct secret serialization

Recovering the vectors is not enough. They have to be converted into bytes exactly the same way as the challenge.

The correct format is:

```python
password = struct.pack(
    "<38i",
    *(s1 + s2),
)
```

This packs all 38 values as:

```text
little-endian signed 32-bit integers
```

Other formats such as JSON, decimal strings, signed bytes, `int16`, and `int64` do not produce the correct key.

## Scrypt parameters

The KDF section of the JSON is:

```json
{
  "alg": "i_love_ltc_coin",
  "subset_sum_problem?": 16384,
  "r": 8,
  "p": 4000,
  "eww_too_salty": "736869696e612d6374662d32303235",
  "dklen": 32
}
```

The fake field names map to scrypt parameters:

```text
N     = 16384
r     = 8
p     = 4000
dklen = 32
```

The salt decodes to:

```text
shiina-ctf-2025
```

The key is derived with:

```python
master_key = hashlib.scrypt(
    password=password,
    salt=bytes.fromhex(
        "736869696e612d6374662d32303235"
    ),
    n=16384,
    r=8,
    p=4000,
    dklen=32,
)
```

The resulting key is:

```text
b502f41599a0c55ef15bd3ab7282bf0ce58aadaafa73aa34a96975e589c4b1b6
```

## Final decryption

The custom cipher is implemented in `_aux.py` as:

```text
Shiina256PIGE
```

There is no need to break the cipher because the decryption code is already provided.

The encrypted blob has the form:

```text
96-byte nonce || ciphertext || 64-byte HMAC-SHA512 tag
```

Using the recovered master key:

```python
from _aux import Shiina256PIGE

blob = bytes.fromhex(chall["finally"])
plaintext = Shiina256PIGE(master_key).decrypt(blob)

print(plaintext)
```

Output:

```text
b'LYKNCTF{Connect_The_World}'
```

## Full solver

Run this script with SageMath:

```python
#!/usr/bin/env sage

import hashlib
import json
import struct

from sage.all import *

from _aux import Shiina256PIGE


def centered(x, q):
    x = int(x) % q
    return x - q if x > q // 2 else x


def recover_lwe(A_raw, b_raw, q):
    A = Matrix(ZZ, A_raw)
    b = vector(ZZ, b_raw)
    m, n = A.dimensions()

    generators = (
        q * identity_matrix(ZZ, m)
    ).stack(A.transpose())

    lattice = IntegerLattice(
        generators,
        lll_reduce=True,
    )

    closest = vector(
        ZZ,
        lattice.closest_vector(b),
    )

    field = GF(q)

    secret_mod = A.change_ring(field).solve_right(
        vector(
            field,
            [int(x) % q for x in closest],
        )
    )

    secret = [
        centered(int(x), q)
        for x in secret_mod
    ]

    error = [
        centered(
            b[i] - sum(
                int(A[i, j]) * secret[j]
                for j in range(n)
            ),
            q,
        )
        for i in range(m)
    ]

    return secret, error


with open("chall.json", "r") as file:
    chall = json.load(file)


s1, e1 = recover_lwe(
    chall["Alcginlcgchall"],
    chall["donttimebabybob"],
    769,
)

s2, e2 = recover_lwe(
    chall["timeforR"],
    chall["c"],
    503,
)

print("s1 =", s1)
print("max |e1| =", max(map(abs, e1)))

print("s2 =", s2)
print("max |e2| =", max(map(abs, e2)))


password = struct.pack(
    "<38i",
    *(s1 + s2),
)

kdf = chall["kdf"]

master_key = hashlib.scrypt(
    password=password,
    salt=bytes.fromhex(
        kdf["eww_too_salty"]
    ),
    n=kdf["subset_sum_problem?"],
    r=kdf["r"],
    p=kdf["p"],
    dklen=kdf["dklen"],
)

print("master key =", master_key.hex())


blob = bytes.fromhex(chall["finally"])

plaintext = Shiina256PIGE(
    master_key
).decrypt(blob)

print(plaintext.decode())
```

## Flag

```text
LYKNCTF{Connect_The_World}
```