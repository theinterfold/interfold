# Protocol review history

This is provenance for older finding IDs, not an open-issue tracker or current audit certification.
It consolidates the source-cross-reference notes and circuit/CRISP remediation records accumulated
before the October 2026 documentation reorganization. Current contracts, rationale, tests, and
**remaining gaps** live with their domains in the [domain navigation](AGENTS.md). A historical
"Resolved/Fixed" label meant a repository remediation, not independent re-review or crash
completeness.

## External review scope

The 2026-08-17 Zenith protocol audit (`Z-` IDs) reviewed six Solidity files at `c2097da6`, with a
mitigation review at `c64bcfb8`: E3RefundManager, Interfold, ExitQueueLib, InterfoldPricing,
BondingRegistry, CiphernodeRegistryOwnable. No Rust or CRISP was reviewed. Lifecycle/payer
libraries, compute-provider, ZK configuration/witness code, guest, and receipt-verifier remediation
code were outside those lists. Security Note §2.5 recommends follow-up audit before significant
capital deployment.

The 2026-09-08 scoped review (`ZEN2-`) covered 14 Solidity files on
`feat/avail-vectorx-release-candidate` at `723bed2e`; upstream references use
`zenith-security/2026-09-interfold`. Nine of its 26 findings were tagged out of scope in the CRISP
availability service. Neither review covered the OpenVM guest/prover or Rust compute/witness path.
See [audit reports and scope](../../packages/interfold-contracts/audits/README.md). ZEN2-04
repository settlement hardening is patched with re-review pending, not auditor-approved.

## Circuit findings

Current security arguments and regression ownership: [proof statements](proof-statements.md),
[DKG](dkg.md), and [threshold decryption](threshold-decryption.md).

| Original ID                 | Recorded repair and evidence limit                                                                                                                                                                       |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IF-001                      | Modular division verifies quotient relation; noninvertible-divisor regression.                                                                                                                           |
| IF-002                      | C7 compares every decoded coefficient, including zero; negative false-zero test.                                                                                                                         |
| IF-003                      | Ordered one-based decryption coordinates and registry-backed SK/ESM anchors.                                                                                                                             |
| IF-004 / C-04 (`cd7cbceea`) | SAFE ciphertext witness commitment is stored and compared in final proof, separately from Keccak bytes.                                                                                                  |
| IF-005                      | Integer lifted smudging bound plus bounded CRT limbs/quotients; secure residue-only check was vacuous.                                                                                                   |
| IF-006                      | ct0 removed unbounded e0 CRT split; bounded operands/reduction quotient in reduced identity.                                                                                                             |
| IF-007                      | C3 removed redundant e0 split under the asserted small-variance assumption.                                                                                                                              |
| IF-008                      | C1 originating pk0 and C5 aggregate/opened keys need magnitude/injective-opening constraints; carrier collisions permitted adversarial aggregate keys.                                                   |
| IF-009                      | C4 opens C2 shares injectively before sum; C2's constraint alone did not bind a different C4 witness.                                                                                                    |
| IF-011                      | Enumerated seven external-commitment openings: C2a, C2b, C4, C5, C6×3. Checked packing transfers bounds. C2a/C2b/C6 were source-review findings without attack witnesses.                                |
| IF-012                      | C7 now derives bounded interpolation/Garner u rather than accepting free CRT quotients.                                                                                                                  |
| IF-013                      | Broadened review to every witness reaching Fiat-Shamir, including direct flatten and newly created commitments. C6 d, C3 ciphertext, ct0/ct1, and C7 share opening needed injectivity or real bounds.    |
| IF-014                      | NodeFold pins all non-self recipient limbs to exported limb-zero C0 key; source review plus negative test, no demonstrated end-to-end threshold bypass. Found against 119d110f and predates that branch. |

The old record had no IF-010 row; this document invents no finding for that number. `C-01` is client
PK semantic commitment checking, `C-02` production proof-bypass removal, `C-03` decryption-domain
binding, and `C-08` ordered raw-address committee hash binding. Their current rules are in the
domains above, not proof that all related vulnerabilities are exhausted.

### Arithmetic optimization evidence

The port from `feat/secure-circuit-optimizations` retained the statement modulo `X^N+1`, not that
branch's older soundness assumptions. Historical minimum-pair gate measurements were:

| Circuit | Earlier main | Final measured |
| ------- | -----------: | -------------: |
| ct0     |    1,688,639 |      1,399,227 |
| ct1     |    1,398,622 |      1,216,948 |
| C3      |    3,475,203 |      2,125,396 |
| C7      |      108,461 |         26,808 |
| C4      |    1,746,030 |      1,098,865 |
| C1      |    2,223,114 |      1,634,682 |
| C6      |    2,977,228 |      2,186,053 |
| C5      |      754,560 |      1,123,205 |

These are experiment records, not current artifact promises. Negacyclic kernels deleted product/
cyclotomic witnesses (`r2is/e0is`, `p2is`, C7 `u_global/crt_quotients`) with real replacement
bounds. C4's flat centered-division saving (~855k) was retained; replacing checked packing with
native bounds scaled worse with H (branch break-even ~4.4). Measured C4 minimum/micro/small became
1,098,865 / 2,092,666 / 5,074,069. C5 remains above old main because its repaired openings/aggregate
bound cost cannot disappear algebraically. C6 saved another 415,111 by absorbing the checked
ciphertext commitment instead of coefficients. C3's generated scaled quotient saved 619,294 at the
recorded secure pair (derived widths 26/18/14 versus older 27/19/14). The recorded degree-512
insecure preset used the direct path; recheck branch selection for the current degree-128
configuration.

Keep C1's integer smudging lift despite an older branch deleting it; retain C6 native-tail witness
after an unexplained Brillig diagnostic (derivation saved only 1,950 gates). Quotients such as C3 z
are constrained witnesses with negative tests. Secure-only branch execution, all committee sizes,
browser 2^21 ceiling, and post-sweep artifact restoration remain review requirements. Earlier "not
ported" notes about message scaling were intermediate snapshots, not authoritative current status.

## Internal protocol concerns

Numbers below are the original unprefixed concern IDs. Unless marked otherwise they were recorded as
remediated; links name current owner/evidence. Missing original #4 is not renumbered. Broad
historical "crash-safe" names do not override today's explicitly open snapshot/delivery gaps.

| IDs                 | Recorded subject / current owner                                                                                                                                                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| #1, #26             | Both-lane proposal collateral gate, retained manager obligations — [slashing](slashing.md).                                                                                                                |
| #2                  | Permissionless proof-backed key publication — [DKG](dkg.md).                                                                                                                                               |
| #3                  | Failure grace limits caller, not deadline — [settlement](failure-settlement.md).                                                                                                                           |
| #5                  | Provisional active-job reservation before ticket dispatch — [selection](committee-selection.md).                                                                                                           |
| #6                  | Canonical expulsion identity/parsed addresses — [DKG](dkg.md).                                                                                                                                             |
| #7                  | Exact local proof-worker retries, not peer fault — [persistence](persistence-and-replay.md).                                                                                                               |
| #8                  | Global settlement receipts do not reopen contexts — [persistence](persistence-and-replay.md).                                                                                                              |
| #9                  | Replay-gated compute effects and response reuse — [persistence](persistence-and-replay.md).                                                                                                                |
| #10                 | Recovered plaintext dependencies/checker — [decryption](threshold-decryption.md).                                                                                                                          |
| #11                 | Await replay acceptance beyond mailbox capacity — [persistence](persistence-and-replay.md).                                                                                                                |
| #12                 | H NodeFolds versus N committee addresses — [DKG](dkg.md).                                                                                                                                                  |
| #13                 | Unsupported enum skip versus malformed ABI failure — [selection](committee-selection.md).                                                                                                                  |
| #14                 | Continue after live network lag; startup fails closed — [network](network-delivery.md).                                                                                                                    |
| #15                 | Equal-payload local/network event redelivery — [persistence](persistence-and-replay.md).                                                                                                                   |
| #16                 | Unindexed torn-tail recovery only — [persistence](persistence-and-replay.md).                                                                                                                              |
| #17                 | DAppNode v0.2.3 bridge for v0.1.8 state — [upgrades](upgrades.md).                                                                                                                                         |
| #18                 | Live-tranche/scan cap and separate heads — [registration](registration-and-bonding.md).                                                                                                                    |
| #19                 | Independent requester/honest-node ledgers — [settlement](failure-settlement.md).                                                                                                                           |
| #20                 | Sale config consumable only by immutable factory deployment operator, Safe still token owner — [sale tests](../../packages/interfold-contracts/test/Token/InterfoldTokenSaleDeployer.spec.ts).             |
| #21                 | Constructor deployed verifier/nonzero VK trust anchors — [artifacts](circuit-artifacts.md).                                                                                                                |
| #22                 | 128-byte EIP-170 headroom, measured variant limits — [artifacts](circuit-artifacts.md).                                                                                                                    |
| #23                 | Atomic asset configuration, drain and bound policies — [registration](registration-and-bonding.md).                                                                                                        |
| #24                 | Eligibility version invalidates caches, requires refresh — [registration](registration-and-bonding.md).                                                                                                    |
| #25 (Accepted then) | Old quote-only fee-consent description superseded by current expected-token/config/max-fee guards — [selection](committee-selection.md).                                                                   |
| #27                 | Explicit committed upgrade baselines — [artifacts](circuit-artifacts.md).                                                                                                                                  |
| #28                 | Per-E3 immutable settlement policy — [settlement](failure-settlement.md).                                                                                                                                  |
| #29                 | Coherent drained generation replacement — [upgrades](upgrades.md).                                                                                                                                         |
| #30                 | Reserved proposal-scoped retryable slash routing — [slashing](slashing.md).                                                                                                                                |
| #31                 | Exhaustive fault-attributed, token-aware payer — [settlement](failure-settlement.md).                                                                                                                      |
| #32                 | No production proof-disabled publication — [proof contracts](proof-statements.md).                                                                                                                         |
| #33                 | Validate serialized PK against C5 commitment — [DKG](dkg.md).                                                                                                                                              |
| #34                 | C6 domain and on-chain DKG anchors — [decryption](threshold-decryption.md).                                                                                                                                |
| #35                 | Owner transfer preserves old locked-FOLD floor — [registration](registration-and-bonding.md).                                                                                                              |
| #36                 | Terminal timeout redrive; snapshot acknowledgment still open — [DKG](dkg.md).                                                                                                                              |
| #37, #38            | Owner-only admission/retirement, deployed bootstrap at initialization — [selection](committee-selection.md).                                                                                               |
| #39, #40            | Network/deployment isolation and fail-closed staged admission — [network](network-delivery.md).                                                                                                            |
| #41                 | Local result intent versus canonical completion — [decryption](threshold-decryption.md).                                                                                                                   |
| #42                 | Readiness-gated durable aggregator phases — [DKG](dkg.md), [decryption](threshold-decryption.md).                                                                                                          |
| #43                 | Per-aggregate sequence and monotonic router checkpoint — [persistence](persistence-and-replay.md).                                                                                                         |
| #44                 | Fresh boot infrastructure events / early NetReady listener — [persistence](persistence-and-replay.md).                                                                                                     |
| #45                 | Direct snapshot-derived participation, no synthetic log facts — [persistence](persistence-and-replay.md).                                                                                                  |
| #46                 | Durable sortition/finalizer inputs and slash intent — [persistence](persistence-and-replay.md).                                                                                                            |
| #47                 | Recreate slashing recipients and recover pending voted accusations/timeouts; unsaved buffers remain — [slashing](slashing.md).                                                                             |
| #48 (open, Medium)  | Finalized terminal reconciliation; local Failed reason and snapshot-only canonical failure gaps — [persistence](persistence-and-replay.md).                                                                |
| #49, #50            | Non-prefix recipient IDs versus C4 fold-row indexing in circuit/checker — [DKG](dkg.md).                                                                                                                   |
| #51                 | Ordered proof/metadata/output recovery — [DKG](dkg.md).                                                                                                                                                    |
| #52                 | One roster leader/failover path; fixed-roster durability caveat remains — [DKG](dkg.md).                                                                                                                   |
| #53                 | Stale topic subscriptions and reconnect readiness — [network](network-delivery.md).                                                                                                                        |
| #54                 | 75% share checkpoint is soft, canonical deadline remains — [DKG](dkg.md).                                                                                                                                  |
| #55                 | Fresh transport delivery ID, stable protocol fact — [network](network-delivery.md).                                                                                                                        |
| #56                 | HLC floor above post-snapshot suffix — [persistence](persistence-and-replay.md).                                                                                                                           |
| #57                 | Reuse randomized successful TrBFV responses — [DKG](dkg.md).                                                                                                                                               |
| #58                 | Hold early C1 outcome for exact recovered roster — [DKG](dkg.md).                                                                                                                                          |
| #59                 | Repair pre-v0.16 derived sortition projection only — [persistence](persistence-and-replay.md).                                                                                                             |
| #60                 | Mainnet E3-2 document upload storm; notification/refresh split — [network](network-delivery.md).                                                                                                           |
| #61, #62            | Six-hour seen/stored windows, bounded fair eviction and backed-off retransmission — [network](network-delivery.md).                                                                                        |
| #63                 | Backed-off decryption-share retransmission — [decryption](threshold-decryption.md).                                                                                                                        |
| #64                 | Filter self/loopback addresses without quarantining real peers — [network](network-delivery.md).                                                                                                           |
| #65                 | Bounded byte formatting and quiet default logs (E3-2 incident) — [network](network-delivery.md).                                                                                                           |
| #66                 | Reset guards all keyshare prefixes plus unsubmitted slash evidence — [upgrades](upgrades.md).                                                                                                              |
| #67                 | Persistent container state location, refuse dual state — [upgrades](upgrades.md).                                                                                                                          |
| #68                 | Demoted aggregator finishes started work; restart C6-verification limitation — [decryption](threshold-decryption.md).                                                                                      |
| #69                 | Forged notification cannot displace correct metadata/requested key — [network](network-delivery.md).                                                                                                       |
| #70                 | Fetch retries until expiry/closure, not six attempts — [network](network-delivery.md).                                                                                                                     |
| #71                 | Decoded revert data, never error-text selector scans — [settlement](failure-settlement.md).                                                                                                                |
| #72                 | Teardown grace, own C0 ordering, C4 sequence layout, early C2/C3, converged votes, prover cap/fresh finalizer provider — [DKG](dkg.md), [slashing](slashing.md), [persistence](persistence-and-replay.md). |
| #73                 | Early keys/shares, saved expulsions and overdue cutoff recovery — [DKG](dkg.md).                                                                                                                           |
| #74                 | Announce local DHT copy without waiting for upload — [network](network-delivery.md).                                                                                                                       |
| #75 (open, Low)     | SyncEnded publication fence still races live buffered closure; incomplete cancel — [network](network-delivery.md).                                                                                         |
| #76 (open, Low)     | Best-effort received broadcast restoration, no durable targeted/replica shares — [network](network-delivery.md).                                                                                           |
| #77                 | Outage redial concrete trusted identity address / QUIC self-dial rejection — [network](network-delivery.md).                                                                                               |

## Zenith 2026-08 IDs

All listed Z- rows were recorded as repository remediations, with external scope limits above.

| Original IDs                                               | Subject / current owner                                                                                                                                                                                                           |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Z-01, Z-09, Z-10, Z-14                                     | Finalization/failure authority, grace, enum validity, inclusive DKG deadline — [settlement](failure-settlement.md).                                                                                                               |
| Z-02, Z-20, Z-35, Z-47, Z-58                               | Small refunds, proposal-aware rewards, slash rounding, fail-closed recipient lookup, frozen recipients — [settlement](failure-settlement.md).                                                                                     |
| Z-03                                                       | Ban/unban eligibility refresh across retained managers — [registration](registration-and-bonding.md).                                                                                                                             |
| Z-04, Z-36, Z-37, Z-39, Z-40, Z-42, Z-44, Z-60             | Committee/candidate collateral, full pending slash, permissionless ticket exit, rounded-up bond, surplus rotation, local locks and ticket binding — [registration](registration-and-bonding.md).                                  |
| Z-05                                                       | One paid request-bound VRF draw prevents requester seed grinding — [selection](committee-selection.md).                                                                                                                           |
| Z-06, Z-08, Z-11, Z-21, Z-22, Z-24, Z-27, Z-28, Z-38, Z-45 | Schedule, controller identity, reusable tree, frozen verifier/timeouts, no provisional authority, build crypto ID, local active jobs, immutable snapshot, compute clock, in-call fee bound — [selection](committee-selection.md). |
| Z-07, Z-13, Z-16, Z-46, Z-53, Z-55                         | Fixed supplier attribution, objective vote deadline, manager retirement, actual amounts, timelocked reduction, reserved route — [slashing](slashing.md).                                                                          |
| Z-12, Z-49, Z-62                                           | Coherent fully drained replacement, no concurrent membership generations — [upgrades](upgrades.md).                                                                                                                               |
| Z-15, Z-19, Z-59                                           | Separate protocol compute gate, SAFE commitment, atomic publication — [encrypted computation](encrypted-computation.md).                                                                                                          |
| Z-17                                                       | Authorized minting remains available through CCA/Cooldown until TGE — [token tests](../../packages/interfold-contracts/test/Token/InterfoldToken.spec.ts).                                                                        |
| Z-18                                                       | Launcher temporary distribution whitelist is revoked before Safe handover; LBP/position manager keep needed liquidity access — [sale tests](../../packages/interfold-contracts/test/Token/InterfoldTokenSaleDeployer.spec.ts).    |
| Z-25                                                       | Exact non-rebasing custody accounting — [registration](registration-and-bonding.md).                                                                                                                                              |
| Z-29, Z-30, Z-34                                           | Canonical field/u64, ordered raw-address hash, reject false verifier results — [proof contracts](proof-statements.md).                                                                                                            |
| Z-31, Z-33                                                 | Bounded semantic PK transport, frozen registry/fold attestation domains — [DKG](dkg.md).                                                                                                                                          |
| Z-32                                                       | Atomic viability-breaking expulsion and publication viability gates — [settlement](failure-settlement.md).                                                                                                                        |
| Z-43                                                       | Layout checks include dynamic arrays, enums, ERC-7201; fingerprint/archive compiler input and dependency lock — [artifacts](circuit-artifacts.md).                                                                                |
| Z-61                                                       | Original requester cancellation only after unusable randomness expires — [settlement](failure-settlement.md).                                                                                                                     |
| Z-48                                                       | Pricing/committee validation use public Interfold caps, not duplicate library constants — [pricing tests](../../packages/interfold-contracts/test/Pricing/Pricing.spec.ts).                                                       |

## Zenith 2026-09 IDs

| Original ID | Recorded disposition / current owner                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ZEN2-01     | Remediated program interface probe — [selection](committee-selection.md).                                                                                    |
| ZEN2-02     | Timing check remediated; reconciliation/skipping pending ballots **not implemented**, loss policy remains — [DA](data-availability.md).                      |
| ZEN2-03     | Reject key after input-window end — [DKG](dkg.md).                                                                                                           |
| ZEN2-04     | **Patched, re-review pending:** reporting/proposal settlement gate and payer correction — [settlement](failure-settlement.md).                               |
| ZEN2-05     | Zero content hash rejected — [DA](data-availability.md).                                                                                                     |
| ZEN2-07     | Advisory randomness breaker, per-outstanding-draw subscription reserve — [selection](committee-selection.md).                                                |
| ZEN2-08     | **Documented unresolved:** external pointer rotation stalls bound rounds; no unsafe repoint/extension remedy — [DA](data-availability.md).                   |
| ZEN2-09     | Finalized collateral release after accusation deadline — [registration](registration-and-bonding.md).                                                        |
| ZEN2-10     | Removed obsolete generated ImageID copy without rebuilding/hand-editing canonical historical ID — [artifacts](circuit-artifacts.md).                         |
| ZEN2-11     | Retain Avail coordinates for rejected-proof replacement; old missing-coordinate jobs need operator recovery — [DA](data-availability.md).                    |
| ZEN2-12     | CRISP checks assigned program before initialization — [selection](committee-selection.md).                                                                   |
| ZEN2-13     | Reachable IMT cap is 2^depth−1 — [selection](committee-selection.md).                                                                                        |
| ZEN2-14     | Canonical decimal E3 identity prevents duplicate paid jobs — [DA](data-availability.md).                                                                     |
| ZEN2-15     | **Documented unresolved:** stage-derived DA loss allocation, no funded insurance — [settlement](failure-settlement.md).                                      |
| ZEN2-16     | **Documented:** floor/dust policies unchanged, per-request raw-unit bound — [selection](committee-selection.md), [settlement](failure-settlement.md).        |
| ZEN2-17     | **Documented:** dynamic publication payloads/repeated valid key chunks impose observer costs despite retained-assembly caps — [DKG](dkg.md).                 |
| ZEN2-18     | Intake bytes reproduce proof commitment before funded attestation — [DA](data-availability.md).                                                              |
| ZEN2-19     | Frozen divisor/snapshot readback, durable deferred discovery; no live failed-provider listener coverage — [encrypted computation](encrypted-computation.md). |
| ZEN2-20     | Operator-keyed claims recheck later expulsion; per-target held slash buckets; legacy balances remain claimable — [settlement](failure-settlement.md).        |
| ZEN2-21     | Request-owned quota guard, commit with durable job before awaits — [DA](data-availability.md).                                                               |
| ZEN2-22     | Per-job ownership prevents status from overwriting worker progress — [DA](data-availability.md).                                                             |
| ZEN2-23     | Existing-job replay does not charge admission quota — [DA](data-availability.md).                                                                            |
| ZEN2-24     | Finalized observations retire recovery; orphaned publications/relay commitments retry — [DA](data-availability.md).                                          |
| ZEN2-25     | Per-statement, not per-slot admission; retain earlier attested objects — [DA](data-availability.md).                                                         |
| ZEN2-26     | Recheck stage/viability after mutable program verifier — [encrypted computation](encrypted-computation.md).                                                  |

The original record had no ZEN2-06 row; no status is inferred for it.

## Earlier audit aliases

Earlier reports reused short severity IDs, so these aliases are scoped to the cited subject/report,
not globally unique findings. They remain searchable without treating one report's H-04 as
another's.

- Internal concern aliases: #18 = AUD M-01; #19 = AUD M-02; #20 = AUD L-01; #21 = AUD L-02; #22 =
  AUD L-03; #23 = AUD M-08; #24 = AUD M-03; #25 = AUD H-02; #26 = AUD H-03; #27 = AUD H-04; #28 =
  AUD M-07; #29 = AUD M-04; #30 = AUD M-05; #31 = AUD H-01; #32 = AUD C-02; #33 = AUD C-01; #34 =
  AUD C-03; #35 = N-1; #36 = AUD M-42; #37 = AUD M-43; #38 = AUD M-39. The numbered concern rows
  above name current owners.
- Token cluster: H-02 registry initialization; H-16 / H-20 / M-22 locked-registry swap timelock;
  M-11 disabled permit; M-12 underlying-safe rescue; M-25 self-only delegation; M-29 timestamp
  clock. [Registration](registration-and-bonding.md) owns these constraints.
- Committee cluster: H-04 snapshot eligibility; M-28 immutable per-E3 sortition; M-33 caller grace;
  H-26 timestamp `requestBlock`. [Selection](committee-selection.md) owns their current meanings.
- Exit-queue cluster: C-03 separate asset heads, M-08 scan past locked tranches, H-21a bounded live
  tranches. This C-03 is not the later cross-E3 proof replay ID. See
  [registration](registration-and-bonding.md).
- Slashing cluster: C-05 / H-24 role separation; M-17 delayed default-admin handover; H-10 / M-24
  EIP-712 domain; H-06 appealable Lane A; H-05 collateral gate; H-01 / H-07 / H-09 pull slash funds;
  M-14 / M-15 distinct-signer bans; M-36 event lane. See [slashing](slashing.md).
- Reward/verifier labels: H-01 / M-02 pull rewards; M-07 rotating success dust; M-09 frozen
  failed-E3 per-node amount ([settlement](failure-settlement.md)); M-34 immutable recursive VK
  anchors and M-35 rejected false verification results ([proof contracts](proof-statements.md)).
  These record the remediation subjects, not a new assurance claim for subsequently changed
  implementations.

## CRISP-specific review record

[Encrypted computation](encrypted-computation.md) retains full-degree plaintext bounds, one ballot
relation/shape, parent-chain selection, and tally modulus reasoning. Historical fixes covered checks
reading padding instead of message coefficients; unconstrained extra coefficients; mismatched
re-vote bytes/commitment; occupied-slot mask digest; unusable heads freezing masking; second-opening
masks erasing votes; and plaintext total wrap. These are application findings, not claims about
audited protocol coverage.

Accepted limitations remain local: unsigned masks can fill `inputLimit`; relay limits are per server
instance; dropped-input visibility depends on active client/index and is absent in governance apps.
Mid-round relay ledger adoption now takes the wallet path for unaccounted earlier history. Access
logs use route templates, not caller/job identifiers. [DA](data-availability.md) owns those
operating details. Hardhat/EDR's five-minute local subscription expiry is a listener limitation, not
a proof defect.

The original documentation-accuracy corrections (#1/#2 ticket units, #3 grace, #5 event crypto ID,
#6 strict finalization boundary, #7 permissionless key proof, #8 separate key transport, #9
eligibility read owner, #10 attestation lane) are folded into current domain statements. These
doc-table numbers were a different namespace from the internal concerns above; they are not new
protocol findings.
