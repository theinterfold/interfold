# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
"""Evidence for DESIGN.md: how close each family of priorities is to the ideal mechanism, and what the
bilinear rank of its per-level indicator is.

    python3 research/alternatives.py

A family is a list of priority arrays `pi_u` (the level of the least priority in `[s, b]` is the
agreed one, `u` uniform). The ideal law is uniform on `[s, b]`. The rank is the rank over F_257 of the
matrix `M_i[(s, a), (b, c)] = [winner(pi_{a + c}, s, b) == i]`: the number of ciphertext lanes that a
program without rotations needs for the level `i` (DESIGN.md, "What a program can compute").
"""
import math
import sys

T = 257


def winner(pr, s, b):
    return min(range(s, b + 1), key=lambda i: pr[i])


def likelihood(perms, g):
    k = len(perms)
    law = {}
    for s in range(g):
        for b in range(s, g):
            cnt = [0] * g
            for pr in perms:
                cnt[winner(pr, s, b)] += 1
            law[(s, b)] = [c / k for c in cnt]
    return law


def metrics(law, g):
    pairs = list(law)
    max_tv = mean_tv = 0.0
    for (s, b), pv in law.items():
        n = b - s + 1
        tv = 0.5 * sum(abs(pv[i] - (1 / n if s <= i <= b else 0)) for i in range(g))
        max_tv = max(max_tv, tv)
        mean_tv += tv / len(pairs)
    marginal = [sum(law[k][p] for k in pairs) / len(pairs) for p in range(g)]
    mi = sum(
        law[k][p] / len(pairs) * math.log2(law[k][p] / marginal[p])
        for k in pairs
        for p in range(g)
        if law[k][p] > 0
    )
    return max_tv, mean_tv, mi


def ideal_mi(g):
    law = {(s, b): [1 / (b - s + 1) if s <= p <= b else 0 for p in range(g)] for s in range(g) for b in range(s, g)}
    return metrics(law, g)[2]


def rank_mod(m):
    m = [[x % T for x in r] for r in m]
    rows, cols, r = len(m), len(m[0]), 0
    for c in range(cols):
        piv = next((i for i in range(r, rows) if m[i][c]), None)
        if piv is None:
            continue
        m[r], m[piv] = m[piv], m[r]
        inv = pow(m[r][c], T - 2, T)
        m[r] = [x * inv % T for x in m[r]]
        for i in range(rows):
            if i != r and m[i][c]:
                f = m[i][c]
                m[i] = [(x - f * y) % T for x, y in zip(m[i], m[r])]
        r += 1
        if r == rows:
            break
    return r


def rank_family(g, k, pri_of, share):
    """Largest rank over the levels. `share(a, c)` gives the pointer index from the two shares."""
    best = 0
    for i in range(g):
        m = []
        for s in range(g):
            for a in range(k):
                row = []
                for b in range(g):
                    for c in range(k):
                        row.append(1 if s <= i <= b and winner(pri_of(share(a, c)), s, b) == i else 0)
                m.append(row)
        best = max(best, rank_mod(m))
    return best


def trie(g):  # the chosen family: pi_u(i) = i xor u
    return [[i ^ u for i in range(g)] for u in range(g)]


def cyclic(g):
    return [[(i + u) % g for i in range(g)] for u in range(g)]


def golden(g, k):
    phi = (math.sqrt(5) - 1) / 2
    sig = [int(k * ((i * phi) % 1)) for i in range(g)]
    return [[(sig[i] + u) % k for i in range(g)] for u in range(k)]


def affine(g, p):
    return [[(a * (i + 1) + b) % p for i in range(g)] for a in range(1, p) for b in range(p)]


def row(name, g, perms, rank):
    max_tv, mean_tv, mi = metrics(likelihood(perms, g), g)
    print(f"{name:44} K={len(perms):<4} maxTV={max_tv:.3f} meanTV={mean_tv:.3f} excess={mi - ideal_mi(g):.3f} bits  rank={rank}")


if __name__ == "__main__":
    g = 16
    print(f"levels = {g}, all {g * (g + 1) // 2} intervals, uniform prior\n")
    row("xor trie (chosen)", g, trie(g), "16 (measured at 8 levels: 8)")
    row("cyclic shift of the levels", g, cyclic(g), "2K (measured at 8 levels: 16)")
    row("golden-ratio cyclic shift, K=128", g, golden(g, 128), "hundreds (K=16, 8 levels: 46)")
    row("affine (a*l+b) mod 17", g, affine(g, 17), "full (6 levels, mod 7: 126 of 252)")
    if "--rank" in sys.argv:
        print("\nmeasured ranks (slow):")
        print(" xor trie, 8 levels:", rank_family(8, 8, lambda u: [i ^ u for i in range(8)], lambda a, c: a ^ c))
        print(" cyclic, 8 levels:", rank_family(8, 8, lambda u: [(i + u) % 8 for i in range(8)], lambda a, c: (a + c) % 8))
        k = 16
        print(" golden K=16, 8 levels:", rank_family(8, k, lambda u: golden(8, k)[u], lambda a, c: (a + c) % k))
