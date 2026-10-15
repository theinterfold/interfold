# Protocol lifecycle

Interfold coordinates contracts, encrypted computation, and asynchronous nodes. Cross-layer
contracts are owned by the linked domains, not by a second line-by-line implementation trace.

## Happy path

| Boundary                                                                                                            | Domain owner                                                                                 |
| ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Configure encrypted identity; authorize owner; bond, register, fund tickets; acknowledge release                    | [Registration and bonding](registration-and-bonding.md)                                      |
| Pay request, freeze configuration/dependencies, obtain one VRF draw, submit tickets, finalize canonical committee   | [Committee selection](committee-selection.md)                                                |
| C0 key exchange, C1–C3 shares, mutually ready H-roster, C4 anchors, C5 key proof and validated key transport        | [DKG](dkg.md)                                                                                |
| Commit/finalize exact inputs, prove application and protocol computation, publish one verified ciphertext reference | [Encrypted computation](encrypted-computation.md), [data availability](data-availability.md) |
| Admit T+1 signed canonical roster shares, C6/C7/final proof, permissionless plaintext publication                   | [Threshold decryption](threshold-decryption.md)                                              |
| Confirm Complete, credit pull rewards, close request work; release collateral only after reporting obligations      | [Settlement](failure-settlement.md), [registration](registration-and-bonding.md)             |

On-chain stages progress Requested → CommitteeFinalized → KeyPublished → CiphertextReady → Complete,
or Failed from a nonterminal stage. Local aggregation output is an intent, not chain completion.
KeyPublished is proof-backed authority, not a promise that serialized key bytes have arrived.

## Failure and recovery

Missed request-frozen deadlines permit terminal marking subject to caller grace; grace never extends
the deadline. Authenticated invalid proofs can enter [accusation/slashing](slashing.md); local
infrastructure failures cannot. Failed refunds wait for admitted expelling proposals before fixing
the fault-attributed payer. The randomness fee is not refundable service escrow.

Confirmed chain observations decide publication authority and terminal cleanup. Nodes recover
retained inputs and intents with effects fenced until replay finishes, subject to explicit
[persistence gaps](persistence-and-replay.md) and [network loss windows](network-delivery.md). Not
all target outbox, replay-equivalence, and per-E3 isolation properties exist today.

Changing schemas, proof statements, wire meanings, verifier routes, or ordering requires the
[upgrade decision](upgrades.md), including mixed-version compatibility, release counters,
drain/resync or migration, and rollback. [Circuit artifacts](circuit-artifacts.md) defines
source/archive/VK/guest identity; none is interchangeable with another.
