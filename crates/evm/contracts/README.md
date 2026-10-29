# e3-evm-contracts

Shared Rust ABI bindings for Interfold contracts. These are checked minimal interfaces, not another
implementation of Solidity rules. Contract types and enums use their wire representations (`address`
and `uint8`); consumers validate and translate them at their own boundaries.

`CommitteeSize`, `E3Stage` and `FailureReason` are optional typed views, not alternative wire tuple
definitions. Enum members are checked against the Solidity compiler AST; the failure-reason bound is
not a valid outcome. Keep persisted application/domain representations separate.

This package owns signatures, tuple layouts, events and errors. It creates no provider, actor,
transaction policy or recovery state, and normal builds need no Solidity compiler. Node ingestion
belongs in [e3-evm](../README.md); application delivery belongs in
[e3-evm-helpers](../../evm-helpers/README.md).

## Verification

Run `pnpm evm:build`, `pnpm check:bindings`, then `cargo test --locked -p e3-evm-contracts` from the
repository root. ABI consistency checks compare every declared function, event and error with built
Solidity artifacts, including return tuples and indexed fields. Explicitly forwarded errors are
checked against their declaring contract. Artifact freshness alone does not establish binding
consistency, and ABI consistency does not verify transaction or ingestion behavior.
