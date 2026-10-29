# Shared EVM contract bindings

Keep ABI facts here, independent of node configuration, actors, storage and application delivery. Do
not add provider factories, retry classifications, nonce policy, domain decisions or durable
payloads. Consumers may expose typed views, but must preserve unknown-value validation and persisted
representations at their own boundaries.

Change Solidity sources rather than generated artifacts. Run the ABI consistency checks in
[README.md](README.md) after extending an interface; a matching selector does not check outputs or
event indexing. Keep forwarded-error provenance explicit. No Solidity compilation belongs in this
package's normal build.
