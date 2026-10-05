# Part 1: Node Setup & Registration

## Overview

A ciphernode operator uses the CLI to configure local state, encrypt credentials, and authorize an
initial bond owner. A separate wallet or Safe is recommended, but the operator may explicitly choose
itself. The configured owner then funds and registers the operator on-chain.

For non-interactive provisioning, `password set`, `wallet set`, and `ciphernode setup` expose
`--password-stdin` / `--private-key-stdin` flags. Without the corresponding flag, each command uses
a hidden prompt. The CLI rejects secret-value options, including short options, before it loads the
configuration. The error names the stdin flag and the interactive prompt. Repository scripts and
container entrypoints pass secrets through stdin.

**Files:** `crates/cli/src/{main,password,wallet}.rs`, `crates/cli/src/ciphernode/{mod,setup}.rs`.

## Identity model: bond owner vs operator key

The on-chain operator remains the address whose key is loaded by the ciphernode. That address is
inserted into the registry, owns the non-transferable tFOLD voting balance, submits sortition
tickets, signs DKG proofs, and is the identity targeted by bans and slashes.

Before creating a position, the operator can run:

```text
interfold ciphernode set-bond-owner --owner 0xCOLD_WALLET
```

This sends `BondingRegistry.setBondOwner(owner)` from the operator key and emits the typed
`BondOwnerSet(operator, bondOwner)` event. The owner must be nonzero and may be the operator itself.
The operator may correct the address while the position is empty. Every collateral or registration
action requires the configured owner; after funding or registration, rotation is two-step:
`proposeBondOwner(operator, newOwner)` from the current owner, followed by
`acceptBondOwner(operator)` from the proposed owner. Acceptance is blocked if moving the operator's
FOLD credit would leave the previous owner's wallet-plus-remaining-bonds below its current locked
FOLD balance.

Only that owner can call the financial/lifecycle `...For(operator)` entry points:
`bondCiphernodeFor`, `addTicketBalanceFor`, `registerOperatorFor`, `removeTicketBalanceFor`,
`unbondCiphernodeFor`, and `claimExitsFor`. `deregisterOperatorFor` is also callable by the operator
as an emergency kill switch, but payouts remain owner-only. The CLI exposes owner-aware bond,
ticket, registration, and exit commands with an explicit `--operator`; self-owned positions may omit
it.

---

## Step 1: `interfold ciphernode setup`

**File:** `crates/cli/src/ciphernode/setup.rs` → delegates to
`crates/entrypoint/src/config/setup.rs`

### What happens call-by-call:

```
User runs: interfold ciphernode setup
│
├─ 1. Checks if config already exists → ABORTS if yes
│
├─ 2. Prompts for PASSWORD (confirmed twice)
│     └─ Stored encrypted via Cipher → written to local keystore
│        File: ~/.config/interfold/<name>/password (encrypted blob)
│
├─ 0. Refuses a network other than sepolia (the binary carries only the Sepolia
│     deployment; `local` names the project template). Without a terminal on stdin, it
│     refuses unless --rpc-url, --config-dir, --password-stdin and --private-key-stdin
│     are all given, before it reads stdin.
│
├─ 3. Prompts for WEBSOCKET RPC URL, unless --rpc-url gives it
│     └─ Default: wss://ethereum-sepolia-rpc.publicnode.com
│     └─ Validates it's a valid URL
│
├─ 4. Prompts for ETHEREUM PRIVATE KEY (hex)
│     └─ Encrypted with Cipher using the password from step 2
│     └─ Stored in local keystore
│     └─ NEVER stored in plaintext
│
├─ 5. Prompts for CONFIG DIRECTORY, unless --config-dir gives it
│     └─ Default: ~/.config/interfold
│
├─ 6. Creates config file (YAML):
│     chains:
│       - name: "sepolia"
│         rpc_url: <user's URL>
│         data_availability: { mode: avail, rpc_url: https://turing-rpc.avail.so/rpc }
│         contracts:
│           interfold: <address>
│           bonding_registry: <address>
│           ciphernode_registry: <address>
│           slashing_manager: <address>
│
├─ 7. Derives and prints:
│     └─ Node ADDRESS (from private key)
│     └─ Peer ID (libp2p identity derived from private key)
│
└─ OUTPUT: "Setup complete. Your address: 0x... Your peer ID: 12D3Koo..."
```

### Key internals:

- **Cipher** (`crates/crypto/src/`): AES-256-GCM encryption. The password is used to derive an
  encryption key via Argon2. All secrets at rest are encrypted.
- **Config** (`crates/config/src/`): YAML-based `AppConfig` struct with chain configurations,
  contract addresses, node role, peers, etc.

---

## Step 2: Authorize the bond owner

**File:** `crates/cli/src/ciphernode/lifecycle.rs` → `set_bond_owner()`

```
Operator runs:
  interfold ciphernode set-bond-owner --owner 0xCOLD_WALLET
│
└─ BondingRegistry.setBondOwner(owner)
   ├─ Rejects the zero address
   ├─ Allows owner == operator (separate owner recommended)
   ├─ Allows operator correction only while the position is empty
   ├─ Requires current-owner proposal + new-owner acceptance after funding
   ├─ Preserves the previous owner's locked-FOLD coverage on acceptance
   ├─ Stores bondOwners[operator] = owner
   └─ Emits BondOwnerSet(operator, owner)
```

Until this transaction is mined, `bondOwnerOf(operator)` returns the zero address and all
owner-authorized position calls fail.

The current owner can later call `proposeBondOwner(operator, newOwner)`. Acceptance by `newOwner`
moves the operator's active plus pending FOLD credit between `_bondedByOwner` accounts atomically
only when the previous owner's wallet balance plus its remaining bonds still covers
`lockedBalanceOf(previousOwner)`. This prevents ownership rotation from converting bonded locked
FOLD into an unlocked exit payout. A position backed entirely by locked FOLD can be rotated after
the old owner exits and reclaims it, or after equivalent FOLD is returned to that owner's wallet.
Successful acceptance emits a new `BondOwnerSet`, so the event projection follows rotations.

---

## Step 3: Owner-funded registration

The bond owner wallet or Safe performs the on-chain position transactions. For an EOA owner, the CLI
uses the signer from the selected owner config and targets the node with `--operator`.

```
Bond owner
│
├─ CLI: ciphernode bond --operator OP bond --amount N
├─ ciphernodeBondToken.approve(BondingRegistry, bondAmount)
├─ BondingRegistry.bondCiphernodeFor(operator, bondAmount)
├─ CLI: ciphernode register --operator OP
├─ BondingRegistry.registerOperatorFor(operator)
│  ├─ Verifies msg.sender == bondOwnerOf(operator)
│  ├─ Verifies the operator is not banned or already registered
│  ├─ Verifies the operator has the required FOLD bond
│  ├─ Sets operators[operator].registered = true
│  ├─ Calls registry.addCiphernode(operator)
│  │  ├─ Inserts uint160(operator) into the Lean IMT
│  │  └─ Emits CiphernodeAdded(operator)
│  └─ Calls _updateOperatorStatus(operator)
│     └─ Registered but inactive: the ticket threshold is not met yet
├─ CLI: ciphernode tickets --operator OP buy --amount N
├─ stablecoin.approve(InterfoldTicketToken, ticketAmount)
└─ BondingRegistry.addTicketBalanceFor(operator, ticketAmount)
   ├─ Reverts with NotRegistered() when registration has not happened
   ├─ Mints tFOLD to the operator from the owner's stablecoin
   └─ Calls _updateOperatorStatus(operator)
      └─ Activates when bond, ticket, ban, and required-release checks pass
```

Registration must precede the ticket purchase. `_addTicketBalance` requires
`operators[operator].registered`, so funding tickets first reverts with `NotRegistered()`. The
ciphernode bond is the reverse: `registerOperatorFor` requires
`ciphernodeBond >= requiredCiphernodeBond`, so the bond must already be in place. The only valid
order is bond, register, tickets.

The node's address—not the bond owner's—is inserted into the IMT, owns the tFOLD balance, and
remains the committee and slashing identity.

The ciphernode checks and acknowledges its compatibility values during startup. Registration and
ticket funding may finish first, but the operator remains inactive until that acknowledgement meets
the required protocol version and node generation. See [07_UPGRADES.md](07_UPGRADES.md).

---

## Step 4: `interfold ciphernode status`

**File:** `crates/cli/src/ciphernode/lifecycle.rs` → `status()`

```
User runs: interfold ciphernode status
│
├─ ChainContext::new()
│
├─ Reads on-chain state (multiple view calls):
│   ├─ operator.registered
│   ├─ operator.active
│   ├─ operator.exitRequested
│   ├─ ticketToken.balanceOf(address) → ticket balance
│   ├─ operator.ciphernodeBond → ciphernode bond amount
│   ├─ bondingRegistry.bondOwnerOf(address) → collateral owner
│   ├─ bondingRegistry.pendingBondOwnerOf(address) → proposed replacement owner
│   ├─ pendingExits.ticketAmount, pendingExits.ciphernodeBondAmount
│   ├─ bondingRegistry.minTicketBalance → required minimum
│   ├─ bondingRegistry.ticketPrice → price per ticket
│   ├─ bondingRegistry.requiredCiphernodeBond → required bond
│   └─ bondingRegistry.eligibilityAt(operator, latest block timestamp) → eligible for new
│       committees (admission cooldown and policy applied; `active` alone does not include them)
│
├─ Lists the committees that hold the collateral:
│   e3_evm::fetch_operator_committees()  (crates/evm/src/operator_status.rs)
│   ├─ eth_getLogs BondingRegistry.CommitteeObligationUpdated with topic3 = operator,
│   │   from bonding_registry.deploy_block (block 0 when unset) to head (adaptive window)
│   ├─ The last update of each E3 in chain order decides whether its obligation is open
│   └─ For each open E3:
│       ├─ registry (from the event).isCommitteeMemberActive / isCommitteeMember
│       │   → member, expelled, or sortition candidate
│       └─ interfold.getE3Stage(e3Id)
│
└─ OUTPUT:
   Operator Key:     0x1234...
   Bond Owner:       0xabcd...
   Registered:       true
   Active:           true
   Eligible for new committees: true
   Exit Pending:     false
   Ticket Balance:   100 (available: 95)
   Ciphernode Bond:     50000 FOLD
   Pending Exits:    tickets=0, ciphernode bond=0
   Requirements:     minTickets=10, ticketPrice=1000000, ciphernodeBond=50000
   Committees:       1
     E3 <e3Id>: member, stage KeyPublished
```

The committee list holds the obligations that make `claimExitsFor` revert with
`OperatorInActiveCommittee`. A committee stays in the list until `releaseCommittee(e3Id)` releases
it, also after its E3 is complete or failed. If the log scan fails, the command prints
`Committees: unavailable (<error>)` and keeps the other lines.

---

## Rust-Side: What Happens When a Running Node Detects Registration

When a ciphernode is running (`interfold start`), its EVM readers are listening for on-chain events:

```
BondingRegistrySolReader detects OperatorActivationChanged event
│
├─ Publishes to EventBus: OperatorActivationChanged { node, active }
│
├─ Sortition actor receives event:
│   ├─ If active=true: adds node to NodeStateStore as eligible
│   └─ If active=false: removes node from eligible set
│
└─ This node is now part of the sortition pool for future E3 committees
```

`BondOwnerSet` is also decoded into a typed Rust event. The dashboard records the owner for the
local operator, while `ciphernode status` reads it directly from `bondOwnerOf`.

```
CiphernodeRegistrySolReader detects CiphernodeAdded event
│
├─ Publishes to EventBus: CiphernodeAdded { node }
│
└─ Sortition actor: updates IMT root tracking
```

---

## Contract Interaction Diagram

```
┌────────────────┐ registerOperatorFor(operator) ┌──────────────────┐
│ Bond owner/Safe│ ─────────────────────────────→ │  BondingRegistry │
└────────────────┘                                └────────┬─────────┘
                                                      │
                                          addCiphernode(node)
                                                      │
                                                      ▼
                                             ┌────────────────────────┐
                                             │ CiphernodeRegistry     │
                                             │ (Lean IMT insert)      │
                                             │                        │
                                             │ Emits:                 │
                                             │  CiphernodeAdded       │
                                             └────────────────────────┘
                                                      │
                                          _updateOperatorStatus()
                                                      │
                                                      ▼
                                             ┌────────────────────────┐
                                             │  If meets thresholds:  │
                                             │  active = true         │
                                             │  numActiveOperators++  │
                                             │                        │
                                             │  Emits:                │
                                             │  OperatorActivation    │
                                             │  Changed(node, true)   │
                                             └────────────────────────┘
```
