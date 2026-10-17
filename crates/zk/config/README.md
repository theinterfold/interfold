# e3-zk-config

This crate owns static BFV circuit configuration and public-input layouts. Each circuit family
derives its bounds and widths from existing BFV parameters. `Configs::for_preset` constructs the
parameters for a supported preset; `Configs::new` uses an existing parameter owner.

`Configs::render` produces the Noir configuration declarations. This path does not need sample data,
secret keys, witness preparation, or a prover. C1, C2, C5, and C7 use the canonical committee enum.

Constructors reject unsupported degrees, plaintext moduli, CRT bases, and sampler variances. They
retain the supplied parameter `Arc`. Both existing insecure DKG builder profiles remain supported.
C3 and user-data encryption derive `k0is` once per configuration and share them with bounds,
rendering, and witness preparation.

C6 and C7 carry `max_msg_non_zero_coeffs`. Its default matches the compiled message width of 50. A
different host width requires matching C6/C7 artifacts and matching public-input consumers. Changing
this field does not change an existing compiled ABI.

`field` owns shared BN254 field literals. Witness JSON encoding belongs to `e3-zk-witness`.
