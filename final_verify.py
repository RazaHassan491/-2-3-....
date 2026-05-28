"""
Complete end-to-end verification:
Encrypt M1='heir' and M2='book' with key='4z1j' and verify they equal C1 and C2.
Print each step clearly.
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

def poker_sub(text, sm, xA, xB):
    dA = make_deck(sm ^ xA); dB = make_deck(sm ^ xB)
    prev = sm % 36; out = []
    for i, c in enumerate(text):
        v = CHAR_TO_VAL[c]; off = (i+1+prev) % 36; idx = (v+off) % 36
        rv = (dA if i%2==0 else dB)[idx]; prev = rv; out.append(VAL_TO_CHAR[rv])
    return ''.join(out)

def get_perm(seed, n):
    s = seed; scores = []
    for _ in range(n): s = lcg_next(s); scores.append(s % 10000)
    return sorted(range(n), key=lambda i: scores[i])

def aperm(text, p):
    return ''.join(text[p[i]] for i in range(len(text)))

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

def score_tree_encode(text, init_seed):
    seed = init_seed; bits = ''
    for c in text:
        codes = get_codes(build_huff(scores_for(seed)))
        bits += codes[CHAR_TO_VAL[c]]
        seed = upd_seed(seed, c)
    return bits

def encrypt(plaintext, key):
    sm = key_to_sm(key)
    seed_r1 = sum(ord(c) for c in key + 'R1')
    seed_r2 = sum(ord(c) for c in key + 'R2')
    n = len(plaintext)

    print(f"  sm = {sm}, seed_R1 = {seed_r1}, seed_R2 = {seed_r2}")

    # Round 1
    s1 = poker_sub(plaintext, sm, 0x1111, 0x2222)
    print(f"  R1 Step1 poker(0x1111,0x2222): '{plaintext}' -> '{s1}'")

    p1 = get_perm(sm ^ 0x3333, n)
    t1 = aperm(s1, p1)
    print(f"  R1 Step2 perm(sm^0x3333={sm^0x3333}): '{s1}' -> '{t1}'  [perm={p1}]")

    r1 = score_tree_encode(t1, seed_r1)
    print(f"  R1 Step3 score_tree(seed={seed_r1}): '{t1}' -> '{r1}' ({len(r1)} bits)")

    # Round 2
    s2 = poker_sub(r1, sm, 0x2222, 0x4444)
    print(f"  R2 Step1 poker(0x2222,0x4444): -> '{s2}'")

    p2 = get_perm(sm ^ 0x6666, len(r1))
    t2 = aperm(s2, p2)
    print(f"  R2 Step2 perm(sm^0x6666={sm^0x6666}): -> '{t2}'")

    ciphertext = score_tree_encode(t2, seed_r2)
    print(f"  R2 Step3 score_tree(seed={seed_r2}): -> ciphertext ({len(ciphertext)} bits)")

    return ciphertext

KEY = '4z1j'
C2_EXPECTED = ('001110110110110000011100011101011001101111000111100010010101100001001110111010001'
               '101000011110000101100111111011011110101111')
C1_EXPECTED = ('001100111000111000100001111001100100101000101111111101100100101010100001010100010'
               '00001110010100001010011111111101111101100001111110111101110')

print("="*65)
print(f"KEY = '{KEY}'")
print("="*65)

print(f"\n--- Encrypting M2 = 'book' ---")
c2 = encrypt('book', KEY)
print(f"\n  Result:   {c2}")
print(f"  Expected: {C2_EXPECTED}")
ok2 = c2 == C2_EXPECTED
print(f"  Match: {'YES ✓' if ok2 else 'NO ✗'}")

print(f"\n--- Encrypting M1 = 'heir' ---")
c1 = encrypt('heir', KEY)
print(f"\n  Result:   {c1}")
print(f"  Expected: {C1_EXPECTED}")
ok1 = c1 == C1_EXPECTED
print(f"  Match: {'YES ✓' if ok1 else 'NO ✗'}")

print("\n" + "="*65)
print("SUMMARY")
print("="*65)
print(f"  Key:    {KEY}")
print(f"  M2:     book  (given)")
print(f"  M1:     heir  (decrypted)")
print(f"  C2 ok:  {'YES' if ok2 else 'NO'}")
print(f"  C1 ok:  {'YES' if ok1 else 'NO'}")
