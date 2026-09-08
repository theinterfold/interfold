# Secure circuit arithmetic: review arguments and limits

Status: experimental source. This document records the proposed arithmetic arguments. See
[the benchmark notes](README.md) for results and test status. Selected negative execution tests are
not a complete malicious-prover analysis. An independent cryptographic review remains required. This
is not a formal proof or an audit certificate.

## Scope and invariants

The normal circuit paths select these arithmetic routines for the secure configuration. They use
degree 8192, the existing coefficient primes, the existing message modulus, and the existing secret
and error bounds. Committee coordinates remain consecutive `1..P`, with `(P,T,H)` equal to
`(3,1,2)`, `(9,4,5)`, or `(19,9,10)`. Generated configuration and parity files are not edited.

Public inputs, their order, return values, and public commitment algorithms stay the same for each
corresponding leaf. C6 retains its public 128-bit domain limbs. The existing private entry-point
layouts remain; compact quotients are derived inside the circuit. Polynomial checking transcripts
change. Matching public interfaces DO NOT make old verification keys, proofs, recursive folds,
browser artifacts, or on-chain verifiers compatible with new circuits.

All cryptographic validity statements depend on the soundness of the actual compiled proof system,
the collision resistance of the unchanged commitments, and the checking-challenge assumptions.
Secret-bearing leaves must continue to use zero-knowledge proof modes. No candidate removes an inner
proof verification from a recursive circuit.

## Bounded commitment openings

The original packing function combines several signed coefficients arithmetically into one field
value before hashing. An unbounded opening can compensate one coefficient change with another and
preserve the packed value. A hash digest alone therefore does not establish independent coefficient
bounds. The new C1, C2, C4, C6, C7, and P3 entry points check the relevant openings locally. These
checks can increase the gate count relative to an insufficiently bounded original circuit. A valid
security repair is not counted as a performance win.

The C1 smudging-noise bound and commitment encoding remain as configured. Its Rust generator already
reverses and centers each noise residue modulo its coefficient prime. The candidate proves that the
configured global bound contains each centered interval, then checks the narrower canonical
interval. Thus the original numeric bound is implied, not removed. C2b opens the same digest using
reversed and centered native residues. This pass does not constitute an audit of the wider threshold
noise distribution, the sampling process, or the global statistical-security argument.

## Exact intervals near powers of two

For a bound `q = 2^K + gap`, a value `v` is checked with a flag `b` and low part `r=v-b*2^K`:

- `b` is one bit.
- `r` has K bits.
- `gap-1-b*r` has G bits, where `0<gap<2^G`.

For `b=0`, this accepts `0<=v<2^K`. For `b=1`, it accepts `2^K<=v<2^K+gap`. Negative values fail
because their wrapped field representatives cannot fit these narrow ranges. The maximum intermediate
magnitude is far below the native prime. This is an exact union of two intervals, not truncation or
an approximation near a power of two.

The three threshold primes equal `2^57` plus positive gaps below `2^25`. Centered coefficients are
shifted by `(q-1)/2` and checked in `[0,q)`. Canonical native/centered conversions constrain a
one-bit flag AND the output interval. With a bounded input this determines the representation
uniquely.

Challenge-local packing uses at most 253 bits per carrier, strictly below the BN254 scalar prime.
Every packed digit is range-checked first. Public commitment packing is deliberately not changed.

## Direct evaluation of a reduced product

Arrays use descending degree order. Let `K_j(x)` be the evaluation of `X^(N-1-j) U(X) mod (X^N+1)`.
Then

```
K_(N-1)(x) = U(x)
K_(N-1-j)(x) = x*K_(N-j)(x) - (x^N+1)*u_(j-1)    for j=1..N-1
```

It follows that `sum_j a_j K_j(x)` equals the evaluation of `A*U mod (X^N+1)`. The kernel is
computed by constrained arithmetic; it is not an independently chosen product hint. The old
high-degree quotient multiplying `X^N+1` is unnecessary in this representation.

A legacy length-`2N-1` quotient R converts to a length-N quotient as

```
short[0] = R[N-1]
short[j] = R[N-1+j] - R[j-1]   for j>=1.
```

All independent values entering the new equations are fixed by a transcript commitment before
selecting the checking point. The per-limb residual polynomials have degree below N. For a fixed
nonzero residual, the field root fraction is at most `(N-1)/p`; Fiat-Shamir use additionally
requires its usual random-oracle/cryptographic analysis and does not mean a prover can choose the
challenge. Sharing a checking point across independently asserted limbs does not allow errors to
cancel.

Integer coefficient bounds prevent native-field wrap from turning false integer identities into true
field identities. Tests independently bound the C6 residual below the prime and the P3 ct0 residual
for all allowed global-error widths up to 180. Those models do not inspect compiled gates.

## Circuit C1

The relation becomes `pk0 = -(a*sk mod (X^N+1)) + eek + q*short`. The fixed CRP `a` comes from the
pinned configuration, not a private caller argument in the supplied entry point. It is the same
public polynomial as before. No hash of that constant is needed in the new checking transcript. The
three returned commitments remain unchanged.

With `|a_j|<q/2`, `|sk_j|<=1`, `|eek_j|<=20`, and canonical `pk0`, the quotient magnitude is
below 8192. An offset-8192 14-bit encoding covers it, including worst-case nonrandom coefficients.
The canonical noise-residue checks imply the configured smudging bound after the constant
containment check. They do not assert that the GLOBAL noise is small or change its sampler. For a
configured B-bit global bound, two (B+1)-bit per-coefficient ranges become an 83-bit near-power
range per residue, plus constant containment checks. Hash encoding still uses the old B-bit layout.
The supplied guard expects the existing small key-generation error bound 20 and rejects a differing
configuration.

## Circuits C2a/C2b: finite differences

A sequence of evaluations at consecutive field coordinates `0,1,...,P` has degree at most T exactly
when every sliding `(T+1)`-st finite difference vanishes:

```
D_s = sum(j=0..T+1) (-1)^j * binom(T+1,j) * y_(s+j) = 0 mod q,
s = 0..P-T-1.
```

This is the same polynomial evaluation code as the parity matrix, because `q>P` and the consecutive
coordinates are distinct; the interpolation denominators are nonzero. It is not valid as a generic
replacement for arbitrary or nonconsecutive party coordinates. No probabilistic batching is used.

Native shares lie in `[0,q)`; the SK secret can additionally be -1. Add `2^(T+1)*q` to D_s. The
resulting positive integer is below `2^(T+2)*q`. Its divisibility quotient therefore needs only
`T+2` bits: 3, 6, or 11 instead of a generic 64-bit quotient. The sum stays below 128 bits, so the
u128 hint division is exact. Its value is verified by a range check and integer-valid field
equality.

The first y slot duplicates the separately committed secret. The normal entry point retains this
slot and checks its equality to the secret before selecting the remaining party evaluations. The
finite-difference routine uses the secret directly. Commitments to each recipient's share use the
original reverse order and hash format. The original parity-matrix path remains for insecure
parameters. The secure path assumes the configured consecutive coordinates, not an arbitrary matrix.

## Circuit C3

The secure arithmetic is in the existing share-encryption type. The public message-scaling
identities, 27/19/14/14-bit carry encodings, local ranges, and public commitments remain as
benchmarked. The C3 helper constants are checked against the supplied secure DKG configuration.

The existing r1 and p1 arrays are reduced inside the circuit. For limb l, the ct0 quotient is
`fold(r1_l) + ALPHA_l * message - BETA_l * rounding_carry(message)`. The ct1 quotient is
`fold(p1_l)`. The first ct0 quotient and the difference between the second and first are
range-checked before they enter the transcript. Conversion uses constrained arithmetic, not a new
hint. The candidate's integer-model results are historical evidence, not a new validation of this
integration.

Those identities depend on the DKG plaintext modulus and its two primes. They are NOT reused for
threshold user-data encryption, which has different primes, plaintext modulus, and a large error.

## Circuit C4

Only the secure minimum committee selects this C4 path. Larger committees retain the original
implementation because the measured micro-committee candidate increased gates.

C4 inputs are canonical native shares. With H<=10, their sum S satisfies `0<=S<H*q`. The rounded
carry `k=floor((S+(q-1)/2)/q)` is at most H and fits four bits. The output `S-q*k` is independently
constrained to the centered interval, fixing it uniquely. Reversal and aggregate commitment stay
unchanged.

The separate C0 and C5 candidates are not selected. They increased the measured gate counts. Their
proposed local canonical-opening checks need a separate security-hardening review.

## Circuit C6

C6 uses canonical per-modulus SK and error SHARE aggregates; these are not ternary secrets or
20-bounded errors. Each limb therefore gets its own kernel. The direct relation is

```
d = ct0 + (ct1*sk mod (X^N+1)) + esm + q*short.
```

For `h=(q-1)/2`, the quotient magnitude is at most `(N*h*h+3*h)/q`, below `2^69`. An offset-`2^69`
70-bit encoding is sufficient. This is not C3's much smaller quotient encoding.

The full d polynomial remains in the checking transcript, even though only its first K low-degree
native coefficients are committed for C7. The existing native-tail witness remains and is checked
against d. The secure routine derives the same tail from bounded centered d for its commitment. The
public ciphertext and both aggregate commitments remain checked. Both 128-bit domain inputs remain
public and are also passed from the entry point into the new checking transcript.

## P3 ct0

The old relation uses per-modulus error e_l and an error quotient k_l with
`global_e = e_l + q_l*k_l`. The combined short quotient is `fold(old_r1_l) - old_error_quotient_l`.
The new relation is

```
ct0_l = (pk0_l*u mod (X^N+1)) + global_e + k0_l*k1 + q_l*short_l.
```

It directly uses the configured bounded GLOBAL threshold-encryption error. The entry point retains
the error-limb and error-quotient arrays, and their original consistency check still runs. The
compact quotient is derived from them inside the circuit, then bounded and used in the new equation.
The old e0 and k1 bounds and all four public commitments are retained.

The candidate requires `BIT_E0<=180`, `BIT_K<=22`, `|u|<=1`, and `0<=k0_l<q_l`. A signed width
`R=max(26,BIT_E0-54)` has ample margin for the product, error, message-scaling, and rounding terms.
The compiled circuit derives this width from its BIT_E0 type parameter, never from observed witness
magnitudes.

## P3 ct1 and CRP specialization

The direct ct1 relation uses a 14-bit short quotient and keeps e1 and u bounds. The dynamic version
keeps and bounds the pk1 opening. The specialized version uses the fixed threshold CRP as pk1, with
no private pk1 slot. Only the actual C5-produced committee key qualifies for that specialization.

The fixed-CRP specialization is not selected or exposed by this integration. The normal entry point
accepts arbitrary pk1 values, so it always keeps the pk1 bounds. Its transcript keeps the
dynamic-key tag. Public outputs and the u commitment linking ct0 to ct1 are retained. The larger
fixed-CRP reduction in the benchmark table is not a claim about this branch's generic encryption
path.

## Circuit C7: derived reconstruction and rounded decoding

The three secure primes have a 172-bit product Q; `t*Q` has 191 bits, below the native field prime.
Therefore bounded integer reconstruction and decoding can use native field arithmetic.

Sorted party IDs are range-checked in `1..P`. With at most ten parties, the integer numerator and
absolute denominator of each interpolation coefficient are below `19^9<2^39`. A modular inverse hint
computes a candidate; the circuit verifies its canonical range and a divisibility equation with a
40-bit quotient. The denominator is nonzero and below each prime, so the result is unique.

For each limb and coefficient, sum all `d_i*lambda_i` first, then reduce once. The sum is below
`10*q^2<2^119`; its quotient fits 62 bits. This replaces repeated term-by-term reductions without
allowing field overflow.

Garner reconstruction:

```
a = (r1-r0) * inverse(q0 mod q1) mod q1
U01 = r0 + q0*a
b = (r2-(U01 mod q2)) * inverse(q0*q1 mod q2) mod q2
U = U01 + q0*q1*b
```

The code adds positive multiples of q before hint divisions. Each reduction checks a bounded
quotient and canonical remainder. Thus `0<=U<Q` and all three residues match. The existing private
u_global and CRT quotient fields remain in the entry-point layout for caller compatibility, but the
secure path does not use them to determine the decoded output. It derives U from the committed
shares. Changing these auxiliary fields cannot change the verified output.

Let `v=floor((t*U+(Q-1)/2)/Q)`. Check v in 20 bits and the remainder in `[0,Q)`. Since the numerator
is below `t*Q+Q/2`, v is in `0..t`. Output 0 when v=t; otherwise output v. This equals
`-Q^(-1) * center(t*U mod Q) mod t`, the old decoding rule. Every claimed coefficient is checked,
including zero. BigNum division occurs only inside the hint; the constraints proving v are native.

## Integration boundary

No recursive circuit is changed. No recursive proof verification is removed. The existing witness
serializers and artifact selectors remain unchanged. Some auxiliary witnesses are no longer used by
the secure path because their role is replaced by derived, bounded values. They remain necessary for
the original insecure path.

The new leaf bytecode and verification keys must be generated and tested with the recursive
pipeline, SDK artifacts, and on-chain verifiers before release. The older standalone benchmark
measurements do not establish gate counts or full-size proof validity for these compatibility
adapters. Re-run both positive and adversarial full-size tests on the normal entry points.

The public-key serializer from the original research is not installed. Existing key transport
remains unchanged.
