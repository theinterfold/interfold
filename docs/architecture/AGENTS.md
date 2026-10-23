# Working with domain documentation

Use the owning domain below when changing cross-component behavior or its documentation. These
documents are human-readable references, not another required reading sequence or an implementation
inventory. Search the affected owner/symbol.

[Design principles](design-principles.md) explain capability ownership and the target separation of
decisions, actors, and effects. [RELEASING.md](../../RELEASING.md) owns publication;
[contract deployment documentation](../../packages/interfold-contracts/README.md) owns addresses and
deployment commands. Local `AGENTS.md` files hold editing hazards; READMEs hold component usage and
public contracts.

| Domain                                                | Reference                                               |
| ----------------------------------------------------- | ------------------------------------------------------- |
| Lifecycle and terminal boundaries                     | [Protocol lifecycle](protocol-lifecycle.md)             |
| Operator identity, assets, activity, exits            | [Registration and bonding](registration-and-bonding.md) |
| Governance attribution and historical-weight gap      | [Voting power](voting-power.md)                         |
| Request snapshots, VRF, owners, deadlines             | [Committee selection](committee-selection.md)           |
| C0–C5, H-roster, key transport                        | [DKG](dkg.md)                                           |
| Arithmetic, packing, recursive trust                  | [Proof statements](proof-statements.md)                 |
| Application input roots, CRISP ballots, OpenVM        | [Encrypted computation](encrypted-computation.md)       |
| C6/C7, T+1, canonical decryption domain               | [Threshold decryption](threshold-decryption.md)         |
| Payers, refunds, rewards, reporting gate              | [Failure settlement](failure-settlement.md)             |
| Accusations, lanes, evidence, collateral routes       | [Slashing](slashing.md)                                 |
| Event durability, replay, buffers, shutdown, schemas  | [Persistence and replay](persistence-and-replay.md)     |
| Peer admission, gossip, DHT, delivery limits          | [Network delivery](network-delivery.md)                 |
| Avail/VectorX, job finality, outage trust             | [Data availability](data-availability.md)               |
| Generated artifacts, tool pins, release provenance    | [Circuit artifacts](circuit-artifacts.md)               |
| Compatible releases, cutovers, reset, rollback        | [Upgrades](upgrades.md)                                 |
| Rust clients, indexer catch-up, transaction helpers   | [Rust client integration](rust-client-integration.md)   |
| Test scaffolding, simulated transport, proof evidence | [Repository testing](repository-testing.md)             |
| Original finding IDs and evidence scope               | [Protocol review history](protocol-history.md)          |

[Project commands](../../README.md) and [package scripts](../../package.json) define executable
checks; Cargo manifests own dependency edges. Domain evidence sections name representative guards,
not complete coverage. For client-facing recovery limits see the
[indexer](../../crates/indexer/README.md) and
[compute service](../../crates/program-server/README.md).

When maintaining a domain, distinguish its required contract, actual implementation, test evidence,
and remaining gaps. A passing focused test is not proof of every security or recovery property. Keep
important untested constraints and open limitations visible; do not weaken them to match code.
Verify claims against current owners/tests and deployed compatibility. Link local usage rather than
copying source-derived inventories. Historical findings and target designs are not current
assurance.
