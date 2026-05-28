"""
Full decryption of C1 using discovered algorithm:
Key = '4z1j'
Round 1: poker(0x1111,0x2222) -> perm(0x3333) -> score_tree(ssv(key,'R1'))
Round 2: poker(0x2222,0x4444) -> perm(0x6666) -> score_tree(ssv(key,'R2'))
"""
import hashlib, heapq

CHARS = '0123456789abcdefghijklmnopqrstuvwxyz'
CHAR_TO_VAL = {c: i for i, c in enumerate(CHARS)}
VAL_TO_CHAR = {i: c for i, c in enumerate(CHARS)}

def lcg_next(s): return (s * 1664525 + 1013904223) & 0xFFFFFFFF

def key_to_sm(key):
    r = 0
    for c in key: r = r * 36 + CHAR_TO_VAL[c]
    return r

def make_deck(seed):
    d = list(range(36)); s = seed
    for i in range(35, -1, -1):
        s = lcg_next(s); j = s % (i+1); d[i], d[j] = d[j], d[i]
    return d

def get_perm(seed, n):
    s = seed; scores = []
    for _ in range(n): s = lcg_next(s); scores.append(s % 10000)
    return sorted(range(n), key=lambda i: scores[i])

def aperm(text, p):
    return ''.join(text[p[i]] for i in range(len(text)))

def inv_aperm(text, p):
    inv = [0]*len(p)
    for i, v in enumerate(p): inv[v] = i
    return ''.join(text[inv[i]] for i in range(len(text)))

def scores_for(seed):
    return [((i+1)*seed+17) % 997 for i in range(36)]

def build_huff(scores):
    ctr = [0]
    def push(h, sc, nd): heapq.heappush(h, (sc, ctr[0], nd)); ctr[0] += 1
    h = []
    for i, s in enumerate(scores): push(h, s, i)
    while len(h) > 1:
        s1, _, n1 = heapq.heappop(h); s2, _, n2 = heapq.heappop(h)
        push(h, s1+s2, (n1, n2))
    return h[0][2]

def get_codes(node, prefix='', codes=None):
    if codes is None: codes = {}
    if isinstance(node, int): codes[node] = prefix or '0'
    else: get_codes(node[0], prefix+'0', codes); get_codes(node[1], prefix+'1', codes)
    return codes

def upd_seed(seed, char):
    return int(hashlib.sha256(str(seed ^ ord(char)).encode()).hexdigest(), 16)

def encode(text, init_seed):
    seed = init_seed; bits = ''
    for c in text:
        codes = get_codes(build_huff(scores_for(seed)))
        bits += codes[CHAR_TO_VAL[c]]
        seed = upd_seed(seed, c)
    return bits

def decode(bits, init_seed, n_chars):
    """Decode exactly n_chars from bits. Returns (chars, bits_consumed) or None."""
    seed = init_seed; pos = 0; result = []
    for _ in range(n_chars):
        root = build_huff(scores_for(seed))
        node = root
        while isinstance(node, tuple):
            if pos >= len(bits): return None
            node = node[0] if bits[pos] == '0' else node[1]
            pos += 1
        result.append(VAL_TO_CHAR[node])
        seed = upd_seed(seed, VAL_TO_CHAR[node])
    return ''.join(result), pos

def poker_fwd(text, sm, xA, xB, init_prev=None):
    dA = make_deck(sm ^ xA); dB = make_deck(sm ^ xB)
    prev = (sm % 36) if init_prev is None else init_prev
    out = []
    for i, c in enumerate(text):
        v = CHAR_TO_VAL[c]; off = (i+1+prev) % 36; idx = (v+off) % 36
        rv = (dA if i%2==0 else dB)[idx]; prev = rv; out.append(VAL_TO_CHAR[rv])
    return ''.join(out)

def poker_inv(cipher_text, sm, xA, xB, init_prev=None):
    """Inverse poker: recover plaintext from ciphertext."""
    dA = make_deck(sm ^ xA); dB = make_deck(sm ^ xB)
    # Build inverse decks: inv_deck[rv] = idx
    inv_dA = [0]*36
    for idx, rv in enumerate(dA): inv_dA[rv] = idx
    inv_dB = [0]*36
    for idx, rv in enumerate(dB): inv_dB[rv] = idx

    prev = (sm % 36) if init_prev is None else init_prev
    out = []
    for i, c in enumerate(cipher_text):
        rv = CHAR_TO_VAL[c]
        inv_deck = inv_dA if i%2==0 else inv_dB
        idx = inv_deck[rv]
        off = (i+1+prev) % 36
        v = (idx - off) % 36
        out.append(VAL_TO_CHAR[v])
        prev = rv  # prev = output of forward step (which is rv)
    return ''.join(out)

KEY = '4z1j'
sm = key_to_sm(KEY)
seed_r1 = sum(ord(c) for c in KEY + 'R1')  # = 460
seed_r2 = sum(ord(c) for c in KEY + 'R2')  # = 461

TARGET_C2 = ('001110110110110000011100011101011001101111000111100010010101100001001110111010001'
             '101000011110000101100111111011011110101111')
TARGET_C1 = ('001100111000111000100001111001100100101000101111111101100100101010100001010100010'
             '00001110010100001010011111111101111101100001111110111101110')

print(f"=== Verifying C2 decryption ===")
print(f"key='{KEY}', sm={sm}, seed_r1={seed_r1}, seed_r2={seed_r2}")

# Verify C2 -> "book"
# Step 1: Decode C2 using R2 score_tree to get T2_perm (after perm)
n_r1_book = 22  # known from forward computation
r2_decoded = decode(TARGET_C2, seed_r2, n_r1_book)
if r2_decoded:
    t2_perm, bits_used = r2_decoded
    print(f"\nC2 decoded to {n_r1_book} chars: '{t2_perm}' ({bits_used} bits)")

    # Step 2: Inverse perm
    perm2 = get_perm(sm ^ 0x6666, n_r1_book)
    t2 = inv_aperm(t2_perm, perm2)
    print(f"After inverse perm(0x6666): '{t2}'")

    # Step 3: Inverse poker R2 (0x2222, 0x4444)
    r1 = poker_inv(t2, sm, 0x2222, 0x4444)
    print(f"After inverse poker(0x2222,0x4444): '{r1}' (R1)")

    # Verify R1 is binary
    is_binary = all(c in '01' for c in r1)
    print(f"R1 is binary: {is_binary}")

    # Step 4: Decode R1 using R1 score_tree to get t1_perm (4 chars)
    r1_decoded = decode(r1, seed_r1, 4)
    if r1_decoded:
        t1_perm, bits_used_r1 = r1_decoded
        print(f"\nR1 decoded to 4 chars: '{t1_perm}' ({bits_used_r1}/{len(r1)} bits)")

        # Step 5: Inverse perm R1
        perm1 = get_perm(sm ^ 0x3333, 4)
        t1 = inv_aperm(t1_perm, perm1)
        print(f"After inverse perm(0x3333): '{t1}'")

        # Step 6: Inverse poker R1 (0x1111, 0x2222)
        m2_decrypted = poker_inv(t1, sm, 0x1111, 0x2222)
        print(f"After inverse poker(0x1111,0x2222): '{m2_decrypted}'")
        print(f"\nDecrypted M2: '{m2_decrypted}' (expected 'book')")
        if m2_decrypted == 'book':
            print("✓ VERIFICATION SUCCESSFUL!")
        else:
            print("✗ MISMATCH!")
    else:
        print("Could not decode R1 to 4 chars!")

print(f"\n{'='*60}")
print(f"=== Decrypting C1 ===")
print(f"C1 length: {len(TARGET_C1)} bits")

# Try all possible R1 lengths for C1
for try_len in range(18, 32):
    result = decode(TARGET_C1, seed_r2, try_len)
    if result is None:
        continue
    t2_perm_c1, bits_used_c1 = result
    if bits_used_c1 != len(TARGET_C1):
        continue

    print(f"\nC1 decodes to {try_len} chars: '{t2_perm_c1}'")

    # Inverse perm
    perm2_c1 = get_perm(sm ^ 0x6666, try_len)
    t2_c1 = inv_aperm(t2_perm_c1, perm2_c1)

    # Inverse poker R2
    r1_c1 = poker_inv(t2_c1, sm, 0x2222, 0x4444)

    is_bin = all(c in '01' for c in r1_c1)
    print(f"  R1 for C1: '{r1_c1}' (binary={is_bin})")

    if not is_bin:
        continue

    # Decode R1 to 4 chars
    r1_decoded_c1 = decode(r1_c1, seed_r1, 4)
    if r1_decoded_c1 is None:
        print(f"  Cannot decode R1 ({len(r1_c1)} bits) to 4 chars")
        continue
    t1_perm_c1, bits_r1_c1 = r1_decoded_c1
    if bits_r1_c1 != len(r1_c1):
        print(f"  R1 decode used {bits_r1_c1}/{len(r1_c1)} bits (not all)")
        continue

    print(f"  T1 (permuted): '{t1_perm_c1}'")

    # Inverse perm R1
    t1_c1 = inv_aperm(t1_perm_c1, get_perm(sm ^ 0x3333, 4))

    # Inverse poker R1
    m1 = poker_inv(t1_c1, sm, 0x1111, 0x2222)
    print(f"\n*** PLAINTEXT M1 = '{m1}' ***")

    # Check if it looks like an English word
    is_alpha = m1.isalpha()
    print(f"  All letters: {is_alpha}")
