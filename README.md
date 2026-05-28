# Group 3 Cipher - Known Plaintext Attack

## Results
- **Key** = `4z1j`
- **M2** = `book` (given)
- **M1** = `heir` (decrypted)

## How to Run

### Step 1 — Find the key using KPA brute force
```bash
python3 crack_v10.py
```

### Step 2 — Step-by-step decryption of C1
```bash
python3 decrypt_c1.py
```

### Step 3 — Bit-for-bit verification of both C1 and C2
```bash
python3 final_verify.py
```

## Cipher Algorithm

| Round | Poker Deck A | Poker Deck B | Permutation | Score Seed |
|-------|-------------|-------------|-------------|------------|
| Round 1 | sm ^ 0x1111 | sm ^ 0x2222 | sm ^ 0x3333 | sum(ASCII(key+"R1")) |
| Round 2 | sm ^ 0x2222 | sm ^ 0x4444 | sm ^ 0x6666 | sum(ASCII(key+"R2")) |

Pattern: Round N uses N×0x1111, N×0x2222, N×0x3333 as XOR constants.
