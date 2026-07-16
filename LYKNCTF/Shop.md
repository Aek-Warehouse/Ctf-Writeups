# Shop — LYKNCTF Write-up

## Challenge

**Category:** Reverse Engineering / Binary Exploitation  
**Description:**

> I find the shop to buy something. But I don't have enough money to buy the flag. Can you help me?

The challenge provides both Linux and Windows versions of a small shop program. The flag is listed as an item, but its price is far above the available balance.

---

## Initial Analysis

Running the Linux binary displays the shop catalog:

```text
Welcome to the Integer Overflow Shop!
You have 100 coins. The flag is... a little out of budget.

=== CATALOG ===
  [0] Sticker      18 coin
  [1] Coffee Mug   36 coin
  [2] Hoodie       1836 coin
  [3] The Flag     36363636 coin  (the good stuff)
Balance: 1836 coin
```

The program lets us choose an item and enter any integer as the quantity. It then calculates:

```c
total_cost = item_price * quantity;
```

The result is stored in a signed 32-bit integer. A signed 32-bit integer can only hold values from:

```text
-2,147,483,648 to 2,147,483,647
```

If the multiplication exceeds that maximum, the value wraps around and can become negative.

---

## Finding the Vulnerability

The flag costs:

```text
36,363,636 coins
```

Buying `60` flags gives the real mathematical total:

```text
36,363,636 × 60 = 2,181,818,160
```

This is larger than the maximum signed 32-bit integer, so it wraps around:

```text
2,181,818,160 - 2^32 = -2,113,149,136
```

The program only checks whether the calculated cost is greater than our balance:

```c
if (total_cost > balance) {
    puts("Not enough coins.");
}
```

Because the overflowed total is negative, it is not greater than the balance. The purchase is therefore accepted.

The program then subtracts the negative cost from the balance:

```c
balance -= total_cost;
```

Subtracting a negative number increases the balance, and since the selected item is the flag with a positive quantity, the program prints the flag.

---

## Exploit

Select the buy option, choose item `3`, and enter a quantity of `60`:

```text
[c]atalog  [b]uy  [q]uit > b
Item index: 3
Quantity: 60
Total cost: -2113149136 coin
Purchased 60 x The Flag. New balance: 2113150972 coin

Here is your flag:
LYKNCTF{wr4p_wr4p_wr4p}
```

The same interaction can be automated on Linux with:

```bash
printf 'b\n3\n60\nq\n' | ./shop
```

---

## Flag

```text
LYKNCTF{wr4p_wr4p_wr4p}
```

## Remediation

The program should reject non-positive or excessively large quantities and perform the multiplication using a wider integer type before checking the result:

```c
if (quantity <= 0) {
    return;
}

long long total_cost = (long long)item_price * quantity;

if (total_cost > balance) {
    puts("Not enough coins.");
    return;
}
```