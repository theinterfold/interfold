# Registration, collateral, and exit

Owners: [BondingRegistry and libraries](../../packages/interfold-contracts/contracts/registry/),
[tokens](../../packages/interfold-contracts/contracts/), and
[ciphernode CLI](../../crates/cli/src/ciphernode/). [Voting power](voting-power.md) owns governance
attribution, not eligibility.

## Operator and bond owner

The hot operator address is the registry leaf, tFOLD holder, ticket submitter, protocol signer, and
ban/slash target. Its bond owner funds collateral and controls withdrawals. A cold wallet/Safe is
recommended, but explicit self-ownership is supported; separating keys is not a slashing escape.

`interfold ciphernode setup` delegates to entrypoint setup. It refuses existing config, unsupported
networks (the setup binary carries Sepolia; `local` names the template), and incomplete nonterminal
automation arguments before reading stdin. Supply secrets through hidden prompts or stdin, never
argv or environment metadata. `password set`, `wallet set`, and setup reject secret-value options.
Cipher uses Argon2-derived keys and AES-256-GCM; wallet keys must not be plaintext at rest.
Configuration is YAML; status derives owner/registration/balances/activity/release/exit state from
the configured contracts, rather than treating registration as readiness.

```text
operator: setBondOwner(nonzero owner)
owner:    bondCiphernodeFor(operator, amount)
owner:    registerOperatorFor(operator)
owner:    addTicketBalanceFor(operator, raw collateral amount)
node:     verify release policy, acknowledge, refresh, then sync and listen
```

The operator can correct its owner while the position is empty. After funding or registration,
rotation requires current-owner `proposeBondOwner` and proposed-owner `acceptBondOwner`. A zero
owner cannot authorize position calls. Acceptance transfers active **and queued** FOLD credit
atomically; the old owner's wallet plus remaining bonds must still cover
`lockedBalanceOf(previousOwner)`. Otherwise ownership transfer would turn locked bonded FOLD into an
unlocked payout. Both ownership write paths checkpoint owner history before assignment for
sortition.

Financial `...For(operator)` calls are owner-authorized. Deregistration additionally permits the
operator kill switch, but that does not redirect payouts. CLI owner-aware commands take
`--operator`; self-owned positions may omit it. Bond must reach the full registration requirement
before register; tickets before registration revert `NotRegistered`. Registration inserts the
operator into the IMT, not the owner. It remains inactive until ticket and release requirements also
pass.

## Assets and activation

tFOLD is a non-transferable 1:1 claim on raw underlying base units. Deposits and burns do **not**
multiply amounts by `ticketPrice`; price serves activation, sortition capacity, and
`availableTickets`. Only mint/burn may pass `_update`; approve, permit, delegateBySig, and
delegation away from self are disabled. This keeps snapshot collateral attributable. Its ERC-6372
clock is timestamp mode, distinct from FOLD's pre-TGE transfer restrictions.

FOLD's immutable CCA start/end, claim source, and lifecycle determine phases. Before TGE only
allowed registry, claim-source, and whitelist transfers pass. Lock policies are write-once; active
including pending locks pool at wallet level. Claim-source transfers auto-lock. `totalBonded(owner)`
sums active and queued bonds over all owned operators; unbonding changes no custody, so it does not
lower that total. Bond, slash, exit claim, and ownership transfer do. Transferability nets wallet
locks against bonded credit; a slash can leave a lock undercovered. Mint/mint-and-lock remain
role-controlled; renouncing token ownership is disabled and ownership transfer is two-step.

The immutable `NO_MORE_LOCKS` sunset bounds every policy's hold/curve. From that timestamp transfer
updates skip lock accounting, including pending locks; it is not just a limit on creating new
policies. Locks may use absolute or TGE anchors; `linkClaim` consumes queued claim locks and
unclassified claims use `PENDING_LOCK_POLICY_ID`. Transfer whitelisting (pre-TGE) and lock
whitelisting (claim-source exemption) are different authorities. Authorized minting remains
available through pre-TGE CCA/Cooldown. Only the registry wraps/burns/pays ticket collateral; burn
leaves underlying as payable balance until exit/slash payout. Planned fee USDS and ticket sUSDS are
separate assets: fixed sUSDS ticket/slash units do not promise fixed USDS redemption value. A
one-time zero bond-token placeholder is only for circular deployment, never an operating asset
configuration.

`_updateOperatorStatus` (permissionlessly rerunnable through `refreshOperatorStatus`) computes
active status; there is no `activate` entry point. All conditions must hold:

- registered and not banned by any retained manager;
- ticket token authorizes this BondingRegistry;
- release registry has code and accepts exact protocol version and at least the minimum generation;
- active bond ≥ `ceil(requiredCiphernodeBond * ciphernodeBondActiveBps / 10000)` (default 8,000
  bps);
- `ticketBalance / ticketPrice >= minTicketBalance`, which must stay nonzero.

Cached status is valid only at the current monotonic `eligibilityConfigurationVersion`. Effective
changes to price, bond requirement/active ratio, minimum tickets, assets, or release policy
invalidate every cached status in O(1) and reset the active count. Every registration captured at
the change must be refreshed, including inactive results; duplicates/new registrations cannot settle
another's check, and deregistration settles its own. Emit `EligibilityConfigurationVersionUpdated`
for every bump. Rust invalidates on it, gets price from `BondingAssetConfigUpdated`, and uses source
block seconds from `...At` events rather than the merged event clock.
[Selection](committee-selection.md) owns the snapshot owner-capacity gate. Admission cooldown/pause
and full registration bond requirements are separate from the lower active-bond threshold; callers
cannot infer one from another.

## Admission is separate from activity

`setAdmissionPolicy(cooldownEnabled,cooldownDuration,admissionsPaused)` defaults to no cooldown/open
admissions and does not alter collateral/release/slash requirements. Registration or an actual owner
change checkpoints `AdmissionStarted`, even when cooldown is off. Proposal/same-owner acceptance and
later ticket funding do not restart it; re-registration does. `isActive` remains the
collateral/release view; `eligibilityAt` also applies the historical admission policy.
Status/dashboard show these separately (unknown eligibility on failed read), so active can still
mean waiting for admission.

Pausing freezes the eligible pool immediately before the pause timestamp. Waiting positions cannot
mature into it; new registrations/owners remain out. Cooldown changes/disabling while paused do not
widen it, even with multiple same-timestamp changes. Existing positions still need other
requirements. Time continues during pause; unpause uses original start plus current duration. Policy
changes reset conservative owner capacity, not activity or old request history. Refresh matured
positions; no expiry timer transaction runs automatically and refresh cannot admit early.

Before pausing after an eligibility-version change, refresh every operator meant to stay eligible,
wait a later timestamp, and verify T−1 owner capacity. Refresh after pause cannot retroactively
create its cutoff checkpoint. To repair that ordering, unpause admissions, refresh, wait, pause
again, then refresh the frozen capacity and wait before requests. Requests at a policy-change
timestamp fail capacity closed. Old E3s keep their own T−1 eligibility despite later owner/policy
changes.

Unchanged legacy positions without admission-start history are explicitly admitted, not proven old.
Later registration/owner change starts cooldown. Upgrade nodes before the contract: startup rebuilds
v2 admission state from typed aggregate-zero events and EVM-sourced raw chain-aggregate
`EvmLogObserved` with validated topics/data; replay decodes the suffix likewise. Leave v1 projection
unchanged. Missing/invalid required history must recover before correct shortlisting. This delay
buys reaction time, not human uniqueness or resistance to preprepared wallets.

Ticket underlying, bond token, expected decimals, ticket price, and required bond form one atomic
asset configuration. Replacements must contain code and the bond token must answer
`lockedBalanceOf`. Drain old balances, E3 assignments, locks, and slash routes before changing asset
identity. Slash policies bind exact registry and asset-configuration version. Every configuration
call first sweeps unsolicited surplus above `totalCiphernodeBondLiability` to treasury before
replacement validation.

Ticket-token `registry()` must match at activation, each request, and rotation; `initialize` alone
does not establish it. A mismatch makes nodes inactive without blocking bond slashes, bans, or exit
bookkeeping. Initial circular deployment permits a placeholder only until wiring completes. After
one-way `lockRegistry`, replacement follows its timelock, requires drained supply/payable balance,
and freezes new liabilities while pending. Rescue cannot withdraw the underlying backing.

All custody assets are exact-transfer, non-rebasing ERC-20s. Check custody increase on deposit and
both custody decrease and recipient increase on payout; mismatch reverts all accounting and
preserves other pooled liabilities. Decimal checks establish scale, not market value.
Fee-token/raw-price configuration is separate and atomic; `setRandomnessFlatFee` changes only its
nonzero raw-unit charge.

## Owner identity

`setIdentityPolicy(registry,required)` (owner only) checkpoints an identity policy in its own
namespace and emits `IdentityPolicyUpdated`; those events are the policy history, and no view
returns it. An unset or disabled policy requires no identity. A required policy needs a deployed
`OwnerIdentityRegistry`: `eligibilityAt(operator,T−1)` then also requires
`isVerifiedAt(bondOwnerAt(operator,T−1),T−1)`, and owner transfers check identity before they move
counted capacity. One verified owner may fund many operators; the selection cap still gives each
owner one seat.

`OwnerIdentityRegistry.register(evidence)` passes the caller as the owner to the governance-set
`IIdentityVerifier`, which must bind the credential to that owner, and checkpoints the result. Each
identifier stays reserved to its first owner through replacement, expiry, and revocation.
Registration cannot shorten an existing expiry, so governance revokes first. Expiry and revocation
keep earlier snapshot answers. `setVerifier` accepts any verifier: a replacement that derives other
identifiers lets every registered credential claim a second owner, so it needs a new registry.

Every policy change resets counted owner capacity. Requests fail capacity closed until
`refreshOperatorStatuses` counts the operators again, so refresh after each change. Under a required
policy, capacity covers fixed 30-day windows: an owner counts only when its credential lasts to the
end of the current window, so a short credential stays eligible but cannot make the count stale
early. Capacity reads zero after the window end or a revocation until refreshes rebuild it; a keeper
refreshes at each window end. During an admission pause, an operator also needs identity at the
pause cutoff, so a later credential or policy change cannot widen the frozen pool. Owners renew
before the window that their credential ends in, or they stop counting toward capacity. Rust does
not apply the identity policy to its owner shortlist yet, so enabling `required` before a node
release that does would make verified nodes misjudge selection. An identifier proves what its
verifier proves (for a document verifier, one document rather than one person); it does not stop
identity rental.

`ZKPassportIdentityVerifier` checks ZKPassport proofs of chip documents (passports, national ID
cards, residence permits) through ZKPassport's root verifier. ZKPassport checks the domain, scope,
proof-age window, and dev mode that its caller passes, so the verifier replaces them with fixed
values. It accepts one ZKPassport version (the public-input layout belongs to the version), one
identifier type, and one OPRF key hash (ZKPassport's key for salted proofs, zero otherwise), because
salted and non-salted identifiers of one document differ and a salted identifier depends on the key.
The proof must be bound to the registering owner and `block.chainid`, show an expiry date at or
after the evidence's `validUntil`, and include strict FaceMatch when configured. The credential ends
at `validUntil`, or `MAX_VALIDITY` after the proof date if that is earlier. The identifier hashes
the scoped nullifier with the domain and scope, so it belongs to one document; a second document or
a renewed one gives a new identifier. ZKPassport's admin keys control its verifier, helper,
certificate registry, and OPRF key without delay. When ZKPassport retires the pinned version,
registration and renewal revert until governance sets a verifier for the new version.

## Deactivation and exit

Removing tickets or unbonding can make an operator inactive without removing its IMT leaf.
Deregistration removes the leaf and queues remaining collateral; freed indices are reused before
tree growth. Pending assets remain keyed by operator and slashable until paid to the bond owner.

Claims must respect three independent holds:

1. The tranche's absolute exit time. `exitDelay` is strictly greater than randomness timeout plus
   sortition window, including equality rejection because ticket submission includes its deadline.
   Pointer and value setters enforce this. Each request raises the frozen-deadline watermark;
   `exitDelayFloor()` also covers its remaining duration and current submission window. Old windows
   must expire before reducing that floor. The registry pointer cannot simply be cleared.
2. Candidate/finalized committee obligations. A top-N candidate is held until displacement or
   terminal release. Finalized members remain held through E3 termination **and** past request-time
   manager's accusation submission deadline, even if they deregister. Anyone can call
   `releaseCommittee` on that registry; a new implementation must backfill live obligations or wait
   for their termination. `unresolvedCommitteesOf(operator)` counts these committees, and
   `committeeObligationAt(operator, index)` lists them from a set that `BondingSlashingLib` changes
   together with `unresolvedCommitteeCount`. The set began at the upgrade that added it, so it can
   miss older committees but never holds extra ones: for an operator in an older committee, the last
   indexes revert `CommitteeObligationNotTracked`, and callers such as `ciphernode status` read the
   `CommitteeObligationUpdated` events instead.
3. Aggregate proposal locks in BondingRegistry from every current or retained manager. Withdraw,
   unbond, deregister, and claim revert `OperatorUnderSlash` until every applicable proposal
   resolves. Exit paths read local counts, never call a potentially broken manager.

Anyone may settle a matured ticket-only exit directly to its owner; a claim including bond
collateral is owner-only. Separate ticket/bond queue heads prevent one claim from stranding the
other leg. Scan past locked tranches (`continue`, not `break`) so a later, earlier-unlocking tranche
remains reachable. There are at most 64 live tranches **and** a scan span of at most 64 from the
earlier head. Head advancement/tail pruning free capacity; drained holes between live entries do
not.

Bans require `proposeBan` then `confirmBan` by a distinct governance signer; cancellation rescinds
an unconfirmed proposal, unban is single-step. Legacy direct setting to true reverts
`BanRequiresConfirmation`. Completed changes update manager-scoped registry bans and refresh
eligibility; existing finalized committees change only by E3-scoped expulsion. Manager authorization
checks deployed code, supported API, ERC-165, and registry binding with bounded governance-time
calls, not exit-time callbacks. A manager stays authorized until assignments, locks, bans, and fund
routes drain. Default-admin handover uses the two-day `AccessControlDefaultAdminRules` flow.

## Evidence and deployment constraints

- [Bonding tests](../../packages/interfold-contracts/test/Registry/BondingRegistry.spec.ts),
  [admission tests](../../packages/interfold-contracts/test/Registry/BondingAdmission.spec.ts),
  [ticket tests](../../packages/interfold-contracts/test/Token/InterfoldTicketToken.spec.ts), and
  [exit queue tests](../../packages/interfold-contracts/test/Registry/ExitQueueLib.spec.ts) own
  financial and authorization behavior.
  [Identity tests](../../packages/interfold-contracts/test/Registry/BondingIdentity.spec.ts) and
  [registry tests](../../packages/interfold-contracts/test/Registry/OwnerIdentityRegistry.spec.ts)
  own the identity gate and credential history;
  [ZKPassport verifier tests](../../packages/interfold-contracts/test/Verifiers/ZKPassportIdentityVerifier.spec.ts)
  own its binding, version, identifier-type, and OPRF-key rules against mocks of ZKPassport's
  contracts, not against real proofs. [CLI secret tests](../../crates/cli/tests/cli_secrets.rs) own
  process argument exposure. Run `pnpm evm:test` and `cargo test -p e3-cli --test cli_secrets` as
  relevant.
- [EVM event decoding](../../crates/evm/src/bonding_registry/events.rs) tests typed owner, policy,
  and activity projection inputs. Those tests do not establish complete restart or migration
  behavior.
- BondingRegistry is close to EIP-170. Keep linked logic in `BondingAssetLib`,
  `BondingEligibilityLib`, `BondingSlashingLib`, `BondingRegistrationLib`, and
  `BondingOwnershipLib`; every deployment/upgrade path must link them and keep deployment record
  types synchronized. Keep `Operator` declared in BondingRegistry: baseline type labels participate
  in storage compatibility. The 128-byte CI headroom gate is not permission to bypass layout or
  protocol review.

[Upgrades](upgrades.md) owns generation replacement and release acknowledgments; self-attestation is
not proof that an operator runs the acknowledged executable.
