<!--
SPDX-License-Identifier: LGPL-3.0-only

This file is provided WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
-->

# Measurements of the FHE program

All numbers come from the real `fhe_processor` (`program/src/lib.rs`) under a local committee key.
The committee uses the key generation of the production path: public key shares and relinearization
key shares from the common random polynomials of the preset `INSECURE_THRESHOLD_SIMD` (degree 128,
`t = 257`, `log2(q) = 168`). Offers use the layout rules of `program/src/lib.rs` (`layout`), which
the unit tests compare with `sdk/test-vectors/layout.json`.

The commands run in `examples/negotiation`. Add `--release -p e3-user-program --example <name> --`.

## Noise

`cargo run --release -p e3-user-program --example noise -- --negotiations 40 --parties 3`

The budget is `log2(q / t) - 1 - noise`. The limit of the decryption is 159.0 bits of noise.

| Item                                            | Noise (bits) | Budget (bits) |
| ----------------------------------------------- | ------------ | ------------- |
| Fresh ciphertext (max of the 6 inputs, 40 runs) | 19           | 140.0         |
| Output, 3 members (40 runs, min / max)          | 67 / 68      | 92.0 / 91.0   |
| Output, 1 member (20 runs, min / max)           | 66 / 66      | 93.0 / 93.0   |

Every output decrypted to the expected outcome (17 of 40 matched; the sample has the extremes
`(0, 15)` and `(15, 0)`). The output noise does not depend on the match, on the steps or on the
shares.

The real decryption adds a smudging noise for each committee member. The preset sizes the bound for
multiplicative depth 3: 2^151 for each of the 9 members of the preset, at most 2^154.2 summed. The
output noise of the program (2^68) is negligible against it. With the summed smudging, the margin to
the limit of 159.0 bits is 4.8 bits, the same as for any program of depth at most 3.

## Distribution of the agreed level

`cargo run --release -p e3-user-program --example distribution -- --seller-step S --buyer-step B --runs N`

Each run draws fresh uniform shares and masks, encrypts both offers, runs the program, decrypts and
applies the contract rule (the sum of the 8 groups of each level). The exact law is the one of
`sdk/src/uniformity.ts`, in sixteenths. TV is the total variation distance.

| Steps (s, b) | Runs  | Exact law (sixteenths)    | Observed counts by level                                                                              | Chi-square (df), p-value | TV to exact law |
| ------------ | ----- | ------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------ | --------------- |
| (2, 12)      | 300   | 2:2 3:2 4..11:1 each 12:4 | 2:33 3:28 4:20 5:19 6:23 7:14 8:24 9:17 10:19 11:25 12:78                                             | 9.04 (10), 0.528         | 0.068           |
| (2, 12)      | 3000  | same                      | 2:397 3:393 4:198 5:202 6:171 7:188 8:207 9:182 10:185 11:165 12:712                                  | 12.17 (10), 0.274        | 0.028           |
| (2, 12)      | 30000 | same                      | 2:3726 3:3717 4:1871 5:1892 6:1876 7:1828 8:1854 9:1920 10:1903 11:1872 12:7541                       | 3.75 (10), 0.958         | 0.0044          |
| (0, 15)      | 300   | 1 each (uniform)          | 0:13 1:20 2:18 3:16 4:23 5:21 6:22 7:17 8:23 9:21 10:15 11:15 12:19 13:22 14:16 15:19                 | 7.95 (15), 0.926         | 0.071           |
| (0, 15)      | 3000  | same                      | 0:208 1:178 2:211 3:169 4:181 5:182 6:194 7:193 8:169 9:182 10:186 11:207 12:189 13:195 14:169 15:187 | 14.43 (15), 0.493        | 0.028           |
| (9, 4)       | 20    | no match                  | no match in 20 of 20 runs                                                                             | -                        | -               |

No run agreed on a level outside `[s, b]`, and every output had level sums that are the one-hot
vector or the zero vector. For (2, 12), the exact law is 0.227 away (TV) from the uniform law on
`[s, b]`; the observed histogram follows the exact law, not the uniform one.
