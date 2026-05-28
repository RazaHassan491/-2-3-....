"""
Known Plaintext Attack on Group 3 custom cipher.
Finds the key using C2 (ciphertext) and M2='book' (known plaintext).
Then uses the key to confirm M1 from C1.

Algorithm:
  Round 1: poker(sm^0x1111, sm^0x2222) -> perm(sm^0x3333) -> score_tree(ssv(key,'R1'))
  Round 2: poker(sm^0x2222, sm^0x4444) -> perm(sm^0x6666) -> score_tree(ssv(key,'R2'))

Self-contained: no external files required.
"""
import hashlib, heapq, multiprocessing, time

CHARS = '0123456789abcdefghijklmnopqrstuvwxyz'
CHAR_TO_VAL = {c: i for i, c in enumerate(CHARS)}
VAL_TO_CHAR = {i: c for i, c in enumerate(CHARS)}

TARGET_C2 = ('001110110110110000011100011101011001101111000111100010010101100001001110111010001'
             '101000011110000101100111111011011110101111')
TARGET_C1 = ('001100111000111000100001111001100100101000101111111101100100101010100001010100010'
             '00001110010100001010011111111101111101100001111110111101110')

# ── Core cipher primitives ──────────────────────────────────────────────────

def lcg_next(state):
    return (state * 1664525 + 1013904223) & 0xFFFFFFFF

def key_to_sm(key):
    r = 0
    for c in key: r = r * 36 + CHAR_TO_VAL[c]
    return r

def make_deck(seed):
    d = list(range(36)); s = seed
    for i in range(35, -1, -1):
        s = lcg_next(s); j = s % (i + 1); d[i], d[j] = d[j], d[i]
    return d

def get_perm(seed, n):
    s = seed; scores = []
    for _ in range(n): s = lcg_next(s); scores.append(s % 10000)
    return sorted(range(n), key=lambda i: scores[i])

def aperm(text, p):
    return ''.join(text[p[i]] for i in range(len(text)))

def scores_for(seed):
    return [((i + 1) * seed + 17) % 997 for i in range(36)]

def build_huff(scores):
    ctr = [0]
    def push(h, sc, nd): heapq.heappush(h, (sc, ctr[0], nd)); ctr[0] += 1
    h = []
    for i, s in enumerate(scores): push(h, s, i)
    while len(h) > 1:
        s1, _, n1 = heapq.heappop(h); s2, _, n2 = heapq.heappop(h)
        push(h, s1 + s2, (n1, n2))
    return h[0][2]

def get_codes(node, prefix='', codes=None):
    if codes is None: codes = {}
    if isinstance(node, int): codes[node] = prefix or '0'
    else: get_codes(node[0], prefix + '0', codes); get_codes(node[1], prefix + '1', codes)
    return codes

def upd_seed(seed, char):
    return int(hashlib.sha256(str(seed ^ ord(char)).encode()).hexdigest(), 16)

def ssv(key, label):
    return sum(ord(c) for c in key + label)

# ── T2 set generation (backwards decode C2 to find all valid intermediate strings) ──

def generate_t2_sets(target_bits):
    """Decode target_bits backwards with all (seed, update) combos to find valid T2 strings."""
    def upd_val(seed, char):
        return int(hashlib.sha256(str(seed ^ CHAR_TO_VAL[char]).encode()).hexdigest(), 16)
    def upd_none(seed, char): return seed
    def upd_addval(seed, char):
        return int(hashlib.sha256(str(seed + CHAR_TO_VAL[char]).encode()).hexdigest(), 16)
    def upd_lcg(seed, char): return lcg_next(seed ^ ord(char))
    def upd_xor_ord(seed, char): return seed ^ ord(char)
    def upd_xor_val(seed, char): return seed ^ CHAR_TO_VAL[char]

    update_fns = [upd_seed, upd_val, upd_none, upd_addval, upd_lcg, upd_xor_ord, upd_xor_val]

    t2_sets = {}  # length -> set of strings
    for target_len in range(20, 31):
        found = set()
        for fn in update_fns:
            for eff_seed in range(997):
                seed = eff_seed; pos = 0; result = []
                ok = True
                for _ in range(target_len):
                    root = build_huff(scores_for(seed))
                    node = root
                    while isinstance(node, tuple):
                        if pos >= len(target_bits): ok = False; break
                        node = node[0] if target_bits[pos] == '0' else node[1]
                        pos += 1
                    if not ok: break
                    result.append(VAL_TO_CHAR[node])
                    seed = fn(seed, VAL_TO_CHAR[node])
                if ok and pos == len(target_bits):
                    found.add(''.join(result))
        if found:
            t2_sets[target_len] = found
    return t2_sets

# ── XOR pairs and perm constants to try ────────────────────────────────────

XOR_PAIRS = list(set(
    [(xa * 0x1111, xb * 0x1111) for xa in range(0, 10) for xb in range(0, 10)]
))
PERM_CONSTS = [k * 0x1111 for k in range(10)]

# ── Per-key search function ─────────────────────────────────────────────────

def try_key(args):
    key, t2_sets_items = args
    # Reconstruct T2_SETS from passed items (multiprocessing safe)
    T2_SETS = {length: set(strings) for length, strings in t2_sets_items}

    sm = key_to_sm(key)

    # Round 1: encrypt 'book'
    prev = sm % 36
    dA = make_deck(sm ^ 0x1111); dB = make_deck(sm ^ 0x2222)
    s1 = []
    for i, c in enumerate('book'):
        v = CHAR_TO_VAL[c]; off = (i + 1 + prev) % 36; idx = (v + off) % 36
        rv = (dA if i % 2 == 0 else dB)[idx]; prev = rv; s1.append(VAL_TO_CHAR[rv])
    s1 = ''.join(s1)
    t1 = aperm(s1, get_perm(sm ^ 0x3333, 4))

    seed = ssv(key, 'R1'); r1 = ''
    for c in t1:
        codes = get_codes(build_huff(scores_for(seed)))
        r1 += codes[CHAR_TO_VAL[c]]
        seed = upd_seed(seed, c)

    r1_len = len(r1)
    t2_set = T2_SETS.get(r1_len)
    if not t2_set:
        return None

    perms = {pc: get_perm(sm ^ pc, r1_len) for pc in PERM_CONSTS}

    for xA, xB in XOR_PAIRS:
        dA2 = make_deck(sm ^ xA)
        dB2 = make_deck(sm ^ xB) if xA != xB else dA2
        for init_prev in [sm % 36, 0]:
            prev2 = init_prev; pk = []
            for i, c in enumerate(r1):
                v = CHAR_TO_VAL[c]; off = (i + 1 + prev2) % 36; idx = (v + off) % 36
                rv = (dA2 if i % 2 == 0 else dB2)[idx]; prev2 = rv; pk.append(VAL_TO_CHAR[rv])
            pk = ''.join(pk)

            if pk in t2_set:
                return key
            for perm in perms.values():
                if ''.join(pk[perm[i]] for i in range(r1_len)) in t2_set:
                    return key
    return None

# ── Worker for multiprocessing ──────────────────────────────────────────────

T2_SETS_GLOBAL = None

def worker_init(t2_sets_items):
    global T2_SETS_GLOBAL
    T2_SETS_GLOBAL = {length: set(strings) for length, strings in t2_sets_items}

def worker_chunk(chunk):
    global T2_SETS_GLOBAL
    T2_SETS = T2_SETS_GLOBAL
    for length, key_num in chunk:
        key = ''
        k = key_num
        for _ in range(length):
            key = CHARS[k % 36] + key
            k //= 36
        sm = key_to_sm(key)
        prev = sm % 36
        dA = make_deck(sm ^ 0x1111); dB = make_deck(sm ^ 0x2222)
        s1 = []
        for i, c in enumerate('book'):
            v = CHAR_TO_VAL[c]; off = (i + 1 + prev) % 36; idx = (v + off) % 36
            rv = (dA if i % 2 == 0 else dB)[idx]; prev = rv; s1.append(VAL_TO_CHAR[rv])
        s1 = ''.join(s1)
        t1 = aperm(s1, get_perm(sm ^ 0x3333, 4))
        seed = ssv(key, 'R1'); r1 = ''
        for c in t1:
            codes = get_codes(build_huff(scores_for(seed)))
            r1 += codes[CHAR_TO_VAL[c]]
            seed = upd_seed(seed, c)
        r1_len = len(r1)
        t2_set = T2_SETS.get(r1_len)
        if not t2_set:
            continue
        perms = {pc: get_perm(sm ^ pc, r1_len) for pc in PERM_CONSTS}
        for xA, xB in XOR_PAIRS:
            dA2 = make_deck(sm ^ xA)
            dB2 = make_deck(sm ^ xB) if xA != xB else dA2
            for init_prev in [sm % 36, 0]:
                prev2 = init_prev; pk = []
                for i, c in enumerate(r1):
                    v = CHAR_TO_VAL[c]; off = (i + 1 + prev2) % 36; idx = (v + off) % 36
                    rv = (dA2 if i % 2 == 0 else dB2)[idx]; prev2 = rv; pk.append(VAL_TO_CHAR[rv])
                pk = ''.join(pk)
                if pk in t2_set:
                    return key
                for perm in perms.values():
                    if ''.join(pk[perm[i]] for i in range(r1_len)) in t2_set:
                        return key
    return None

def iter_keys():
    for length in range(1, 5):
        for key_num in range(36 ** length):
            yield (length, key_num)

def main():
    total = sum(36**i for i in range(1, 5))
    ncpu = multiprocessing.cpu_count()
    print(f"Known Plaintext Attack | Keys to try: {total:,} | CPUs: {ncpu}", flush=True)

    print("Step 1: Pre-computing valid T2 candidate strings from C2...", flush=True)
    t0 = time.time()
    T2_SETS = generate_t2_sets(TARGET_C2)
    t2_sizes = {k: len(v) for k, v in T2_SETS.items()}
    print(f"  Done in {time.time()-t0:.1f}s | T2 lengths found: {t2_sizes}", flush=True)

    t2_sets_items = [(length, list(strings)) for length, strings in T2_SETS.items()]

    print(f"\nStep 2: Brute-forcing all {total:,} keys...", flush=True)
    CHUNK = 500
    keys_list = list(iter_keys())
    chunks = [keys_list[i:i+CHUNK] for i in range(0, len(keys_list), CHUNK)]
    found_key = None
    t1 = time.time()
    done = 0
    with multiprocessing.Pool(ncpu, initializer=worker_init, initargs=(t2_sets_items,)) as pool:
        for result in pool.imap_unordered(worker_chunk, chunks, chunksize=2):
            done += CHUNK
            if result is not None:
                found_key = result
                pool.terminate()
                break
            if done % 200000 < CHUNK:
                pct = min(100, done / total * 100)
                print(f"  {done:,}/{total:,} ({pct:.1f}%) elapsed={time.time()-t1:.0f}s", flush=True)

    elapsed = time.time() - t1
    if not found_key:
        print(f"\nKey not found in {elapsed:.1f}s")
        return

    print(f"\n{'='*55}")
    print(f"KEY FOUND: '{found_key}'  (in {elapsed:.1f}s)")
    print(f"{'='*55}")
    print(f"\nStep 3: Verifying key and decrypting C1...")

    # Full verify + decrypt using final_verify logic inline
    key = found_key
    sm = key_to_sm(key)
    seed_r1 = ssv(key, 'R1')
    seed_r2 = ssv(key, 'R2')

    def poker_fwd(text, xA, xB):
        dA = make_deck(sm ^ xA); dB = make_deck(sm ^ xB)
        prev = sm % 36; out = []
        for i, c in enumerate(text):
            v = CHAR_TO_VAL[c]; off=(i+1+prev)%36; idx=(v+off)%36
            rv=(dA if i%2==0 else dB)[idx]; prev=rv; out.append(VAL_TO_CHAR[rv])
        return ''.join(out)

    def poker_inv(text, xA, xB):
        dA = make_deck(sm ^ xA); dB = make_deck(sm ^ xB)
        inv_dA = [0]*36; inv_dB = [0]*36
        for idx, rv in enumerate(dA): inv_dA[rv] = idx
        for idx, rv in enumerate(dB): inv_dB[rv] = idx
        prev = sm % 36; out = []
        for i, c in enumerate(text):
            rv = CHAR_TO_VAL[c]
            idx = (inv_dA if i%2==0 else inv_dB)[rv]
            out.append(VAL_TO_CHAR[(idx - (i+1+prev)) % 36])
            prev = rv
        return ''.join(out)

    def encode(text, seed):
        bits = ''
        for c in text:
            codes = get_codes(build_huff(scores_for(seed)))
            bits += codes[CHAR_TO_VAL[c]]
            seed = upd_seed(seed, c)
        return bits

    def decode(bits, seed, n):
        pos = 0; result = []
        for _ in range(n):
            root = build_huff(scores_for(seed)); node = root
            while isinstance(node, tuple):
                node = node[0] if bits[pos]=='0' else node[1]; pos += 1
            result.append(VAL_TO_CHAR[node]); seed = upd_seed(seed, VAL_TO_CHAR[node])
        return ''.join(result) if pos == len(bits) else None

    def inv_aperm(text, p):
        inv = [0]*len(p)
        for i, v in enumerate(p): inv[v] = i
        return ''.join(text[inv[i]] for i in range(len(text)))

    # Verify C2 -> 'book'
    _s1 = poker_fwd('book', 0x1111, 0x2222)
    _t1 = aperm(_s1, get_perm(sm ^ 0x3333, 4))
    _r1 = encode(_t1, seed_r1)
    _s2 = poker_fwd(_r1, 0x2222, 0x4444)
    _t2 = aperm(_s2, get_perm(sm ^ 0x6666, len(_r1)))
    c2_check = encode(_t2, seed_r2)

    # Decrypt C1
    m1 = None
    for try_len in range(18, 32):
        t2p = decode(TARGET_C1, seed_r2, try_len)
        if t2p is None: continue
        t2 = inv_aperm(t2p, get_perm(sm^0x6666, try_len))
        r1c = poker_inv(t2, 0x2222, 0x4444)
        if not all(c in '01' for c in r1c): continue
        t1p = decode(r1c, seed_r1, 4)
        if t1p is None: continue
        t1 = inv_aperm(t1p, get_perm(sm^0x3333, 4))
        m1 = poker_inv(t1, 0x1111, 0x2222)
        break

    print(f"  encrypt('book', '{key}') == C2 : {'YES' if c2_check == TARGET_C2 else 'NO'}")
    print(f"  decrypt(C1,     '{key}') == M1 : '{m1}'")
    print(f"\n{'='*55}")
    print(f"  KEY = {key}")
    print(f"  M2  = book  (given plaintext)")
    print(f"  M1  = {m1}  (decrypted plaintext)")
    print(f"{'='*55}")

if __name__ == '__main__':
    main()
