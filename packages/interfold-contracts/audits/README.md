# Interfold Contract Audits

| Date       | Auditor | Scope                        | Report                                                                                           |
| ---------- | ------- | ---------------------------- | ------------------------------------------------------------------------------------------------ |
| 2026-07-02 | Zenith  | FOLD token                   | [20260702_audit_token_zenith.pdf](./20260702_audit_token_zenith.pdf)                             |
| 2026-08-17 | Zenith  | Protocol contracts (6 files) | [20260714-Interfold - Zenith Audit Report.pdf](<./20260714-Interfold - Zenith Audit Report.pdf>) |
| 2026-09-08 | Zenith  | Protocol update (14 files)   | [20260908_audit_protocol_zenith.pdf](./20260908_audit_protocol_zenith.pdf)                       |

## What the 2026-08-17 protocol audit covered

Scope commit `c2097da61b4d07c4ce83840393ff4e9f171eefb4`; mitigation review at
`c64bcfb890b596e626ea6578c5fbd53f808c3b43`. Both reviews list the same six
files:

```
E3RefundManager.sol
Interfold.sol
lib/ExitQueueLib.sol
lib/InterfoldPricing.sol
registry/BondingRegistry.sol
registry/CiphernodeRegistryOwnable.sol
```

62 issues: 1 Critical, 6 High, 18 Medium, 19 Low, 18 Informational.

**Read the scope before citing this report as assurance for anything else.** It
covers no Rust and no circuits. In particular, these are _not_ in either file
list:

- `crates/compute-provider` and the RISC Zero guest — the Secure Process and its
  input binding
- `crates/zk-helpers` — the SAFE ciphertext commitment
- `contracts/verifiers/bfv/Risc0BfvCiphertextVerifier.sol`
- `contracts/lib/InterfoldLifecycle.sol`, `lib/Risc0ComputeProof.sol`,
  `lib/FailurePayerLib.sol`
- `examples/CRISP/**`

Several `Z-` entries in `agent/flow-trace/00_INDEX.md` were remediated by adding
files that are themselves outside both file lists, so the remediation code did
not go through the mitigation review either.

Zenith's own §2.5 Security Note: "it is statistically likely that there are more
complex bugs still present given the time-boxed nature of this engagement... a
follow-up audit and development of a more complex stateful test suite [should]
be undertaken prior to continuing to deploy significant monetary capital to
production."
