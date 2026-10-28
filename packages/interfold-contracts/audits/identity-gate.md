# Identity gate: audit pack

With the identity gate, governance can require that the bond owner of each
selected operator holds a verified identity credential at the request boundary
(T−1). The first verifier accepts ZKPassport proofs of chip documents. One
verified owner can fund many operators, but sortition still gives each snapshot
owner one seat.

Status: a stack of draft PRs, not deployed. Design and rules:
[Owner identity](../../../docs/architecture/registration-and-bonding.md#owner-identity)
and [committee selection](../../../docs/architecture/committee-selection.md).

## Scope

Solidity, in this branch. Base: `main` at `26023af50`. Core: #2371 at
`951f2fba7`. ZKPassport adapter: #2372 at `5d1bf062c`.

| File                                                                                                                           | Change                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| [`registry/OwnerIdentityRegistry.sol`](../contracts/registry/OwnerIdentityRegistry.sol)                                        | New. Identifiers, checkpointed credentials, governance revoke and verifier. |
| [`identity/ZKPassportIdentityVerifier.sol`](../contracts/identity/ZKPassportIdentityVerifier.sol)                              | New. Checks a ZKPassport proof and derives the identifier.                  |
| [`lib/BondingIdentityLib.sol`](../contracts/lib/BondingIdentityLib.sol)                                                        | New. Checkpointed identity policy and the per-operator check.               |
| [`lib/BondOwnerCapacityLib.sol`](../contracts/lib/BondOwnerCapacityLib.sol)                                                    | Changed. Capacity windows, freshness, and reset.                            |
| [`lib/BondingEligibilityLib.sol`](../contracts/lib/BondingEligibilityLib.sol)                                                  | Changed. Identity in eligibility and at the pause cutoff; capacity gates.   |
| [`lib/BondingOwnershipLib.sol`](../contracts/lib/BondingOwnershipLib.sol)                                                      | Changed. Owner transfers move counted capacity.                             |
| [`registry/BondingRegistry.sol`](../contracts/registry/BondingRegistry.sol)                                                    | Changed. `setIdentityPolicy`.                                               |
| [`storage/BondingIdentityStorage.sol`](../contracts/storage/BondingIdentityStorage.sol), `storage/BondOwnerHistoryStorage.sol` | New and changed ERC-7201 storage.                                           |
| `interfaces/IBondingIdentity.sol`, `IIdentityVerifier.sol`, `IOwnerIdentityRegistry.sol`, `IZKPassportVerifier.sol`            | New interfaces.                                                             |

Context, not in the Solidity scope. These carry assumptions that the contracts
rely on:

- Node release (#2377): the sortition identity policy store and shortlist rule
  in `crates/sortition`, the capacity refresher in
  `crates/evm/src/capacity_refresh.rs`, and the finalizer stagger cap.
- Verification page (#2378): `packages/interfold-dashboard/src/lib/identity.ts`
  builds the evidence.
- Rollout (#2379): `scripts/upgrade/identityGate.ts` writes the governance
  batches.

Out of scope: ZKPassport's contracts (root verifier
`0x1D000001000EFD9a6371f4d90bB8920D5431c0D8`, sub-verifiers, helper, certificate
and circuit registries) and circuits. They are a trusted dependency.

## How it works

1. **Registration.** A bond owner calls
   `OwnerIdentityRegistry.register(evidence)`. The registry passes the caller to
   the governance-set verifier. The verifier must bind the credential to that
   owner, and returns `(identityId, expiresAt)`. The registry reserves the
   identifier to its first owner forever and checkpoints the expiry.
2. **ZKPassport adapter.** The evidence is
   `abi.encode(ProofVerificationParams, validUntil)`. The adapter replaces the
   caller's service settings with fixed values (domain, scope, proof validity,
   `devMode = false`), accepts one ZKPassport version, one identifier type, and
   one OPRF key hash, and checks the owner and chain binding, the expiry bound,
   and (when configured) strict FaceMatch.
   `identityId = keccak256(abi.encode(namespace, scopedNullifier))`; it does not
   contain the owner.
3. **Eligibility.** With a required policy, `eligibilityAt(operator, T−1)` also
   requires `isVerifiedAt(bondOwnerAt(operator, T−1), T−1)`. During an admission
   pause, the operator also needs identity under the policy at the pause cutoff.
4. **Owner capacity.** A request needs enough counted distinct owners. Under a
   required policy, capacity covers fixed 30-day windows from Unix time zero; an
   owner counts only when its credential lasts to the window end. Capacity reads
   zero after a window end, a revocation, or a policy change until refreshes
   count the owners again.
5. **Governance.** Sets the policy and the verifier, and revokes identifiers.
   Every policy change resets counted capacity, so the rollout batches refresh
   every registered operator in the same transaction. Nodes refresh their own
   operator once in each window.

## Threat model

| Actor                     | Trust                                                                                                                      |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Governance (DAO and Safe) | Trusted to set the policy and verifier, revoke, and turn the gate off.                                                     |
| ZKPassport                | Trusted. Its admin keys can replace the verifier, helper, and registries without delay; its certificate oracle is one key. |
| Bond owners               | Untrusted. May hold several documents, rent an identity, or fund many operators.                                           |
| Operators and nodes       | Untrusted. May be offline, or run an older release.                                                                        |
| Requesters                | Untrusted.                                                                                                                 |

Attacker goals to rule out:

- One document counted as two owners, or a proof registered for an owner it does
  not bind.
- An operator eligible at T−1 without a valid credential, including after expiry
  or revocation.
- A frozen (paused) pool widened by a later credential or policy change.
- Capacity that reads higher than the true number of counted owners.
- Capacity that reads zero while enough owners hold credentials that cover the
  window, after the refreshes that the rollout and the nodes perform.

## Invariants

1. An identifier belongs to its first owner forever, through replacement,
   expiry, and revocation.
2. A registration cannot shorten the owner's current expiry. A credential that
   the verifier returns already expired is rejected, and a revoked identifier
   cannot register again. The reserved owner can renew an unrevoked identifier,
   also after it expired.
3. `isVerifiedAt(owner, t)` and the policy at `t` never change once `t` is in
   the past.
4. Under a required policy at T−1, every eligible operator's snapshot owner was
   verified at T−1. During an admission pause, it was also verified under the
   policy at the pause cutoff.
5. Owner capacity never overestimates: each owner counts at most once per
   capacity version, and only while its credential lasts to the window end. It
   reads zero after a window end, a new revocation, or a policy change, until
   refreshes rebuild it.
6. A repeated `revoke` reverts, so it cannot make capacity stale with nothing
   new revoked.
7. The adapter accepts only proofs under its fixed domain, scope, proof
   validity, and `devMode = false`, of its pinned version, identifier type, and
   OPRF key, bound to `msg.sender` of the registry and to `block.chainid`.
8. BondingRegistry stays upgrade-compatible (storage layout) and under the
   24,448-byte release budget (24,418 bytes at `951f2fba7`).

## Known limits

These are accepted, and the docs state them:

- An identifier proves one document, not one person. A person with two documents
  can verify two owners. Identity rental is not prevented.
- ZKPassport's admin keys and certificate oracle are trusted without delay.
- A new ZKPassport version needs a new verifier deployment. A change of domain,
  scope, identifier type, or OPRF key changes every identifier and needs a new
  registry.
- `setVerifier` accepts any verifier; one that derives other identifiers lets
  every credential claim a second owner, so it needs a new registry.
- Changing or clearing the verifier affects future registrations only. Issued
  credentials stay valid. After a verifier compromise, governance revokes the
  affected identifiers and refreshes capacity, or moves to a new registry.
- Capacity fails closed for a few minutes after each window starts, until the
  nodes refresh. A governance change or a revocation needs a refresh of every
  operator. A refresh counts only owners whose credential lasts to the window
  end; with too few of them, capacity stays below the committee size until
  owners renew. The self-refresh depends on running, funded nodes.
- During an admission pause, turning the requirement off keeps the identity rule
  at the pause cutoff until the admission policy changes too.
- The node does not know which owners hold a credential, so under a required
  policy it turns the owner shortlist off; every eligible node submits, and the
  contract rejects unverified owners.
- An owner who renews during a window counts after a status refresh or at the
  next window.

## Test evidence

- Specs: [`BondingIdentity.spec.ts`](../test/Registry/BondingIdentity.spec.ts),
  [`OwnerIdentityRegistry.spec.ts`](../test/Registry/OwnerIdentityRegistry.spec.ts),
  [`ZKPassportIdentityVerifier.spec.ts`](../test/Verifiers/ZKPassportIdentityVerifier.spec.ts),
  and the existing capacity and admission specs.
- `pnpm evm:test` at `5d1bf062c`: 886 passing, 0 failing. Each review fix and
  each adapter rule fails at least one spec when removed.
- `size:check`, `validate:upgrade`, solhint, and `check:bindings` pass.
- Reviews: Codex gpt-6.1-sol at maximum effort against the architecture docs,
  for #2371, #2372, and #2377. Findings were fixed or are listed above.
- Not yet: a real ZKPassport proof against the verifier on a mainnet fork. The
  adapter specs use mocks of ZKPassport's root verifier and helper.

Run the identity specs from `packages/interfold-contracts`:

```bash
pnpm install
pnpm compile:ts
pnpm hardhat test test/Registry/BondingIdentity.spec.ts test/Registry/OwnerIdentityRegistry.spec.ts \
  test/Verifiers/ZKPassportIdentityVerifier.spec.ts test/Registry/CommitteeCapacity.spec.ts
```

## Focus areas

1. Capacity bookkeeping: `sync`, `transfer`, and `_move` across capacity
   versions, owner transfers, exits, bans, and several operators with one owner.
2. Checkpoint reads: `upperLookupRecent` at a change timestamp, the
   policy-version checks, and reads of past timepoints after later changes.
3. Admission pause: identity at the pause cutoff, and policy changes during a
   pause.
4. Registry: identifier reservation through revoke, expiry, and replacement; the
   external call to the verifier before the state updates in `register`.
5. Adapter: the public-input indices of the pinned version, the fixed service
   settings, the OPRF key rule, the binding and expiry checks, and FaceMatch.
6. Upgrade: storage layout, linked libraries, and the size budget.
7. Liveness: the refresh lists, revocation growth, and any loop that a user can
   lengthen.
