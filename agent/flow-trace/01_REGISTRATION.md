# Part 1: Node Setup & Registration

## Overview

A ciphernode operator goes from zero to registered on-chain through a series of CLI commands that
configure local state, encrypt credentials, and submit an on-chain transaction to the
`BondingRegistry`.

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
├─ 3. Prompts for WEBSOCKET RPC URL
│     └─ Default: wss://ethereum-sepolia-rpc.publicnode.com
│     └─ Validates it's a valid URL
│
├─ 4. Prompts for ETHEREUM PRIVATE KEY (hex)
│     └─ Encrypted with Cipher using the password from step 2
│     └─ Stored in local keystore
│     └─ NEVER stored in plaintext
│
├─ 5. Prompts for CONFIG DIRECTORY
│     └─ Default: ~/.config/interfold
│
├─ 6. Creates config file (YAML):
│     chains:
│       - name: "default"
│         rpc_url: <user's URL>
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

## Step 2: `interfold ciphernode register`

**File:** `crates/cli/src/ciphernode/lifecycle.rs` → `register()`

### Prerequisites (must be done FIRST):

- Setup completed (config + password + private key exist)
- License bonded: `interfold ciphernode license bond --amount N` (see Part 2)
- Tickets purchased: `interfold ciphernode tickets buy --amount N` (see Part 2)

### What happens call-by-call:

```
User runs: interfold ciphernode register [--chain default]
│
├─ 1. ChainContext::new()
│     ├─ Loads AppConfig from disk
│     ├─ Selects chain config (by --chain name or first configured)
│     ├─ Reads bonding_registry contract address from config
│     ├─ Decrypts private key from keystore using Cipher
│     ├─ Creates alloy EVM signer (SignerProvider)
│     └─ Connects to BondingRegistryContract instance
│
├─ 2. BondingRegistryContract.registerOperator().send().await
│     │
│     │  ┌─── ON-CHAIN (BondingRegistry.sol) ───────────────────┐
│     │  │                                                       │
│     │  │  registerOperator() {                                 │
│     │  │    1. Clears any previous exit request                │
│     │  │    2. Checks: SlashingManager.isBanned(msg.sender)    │
│     │  │       → REVERTS if banned                             │
│     │  │    3. Checks: !operators[msg.sender].registered       │
│     │  │       → REVERTS if already registered                 │
│     │  │    4. Checks: operators[msg.sender].licenseBond       │
│     │  │              >= licenseRequiredBond                    │
│     │  │       → REVERTS if insufficient bond                  │
│     │  │    5. Sets operators[msg.sender].registered = true    │
│     │  │    6. Calls registry.addCiphernode(msg.sender)        │
│     │  │       │                                               │
│     │  │       │  ┌─ CiphernodeRegistryOwnable ──────────┐    │
│     │  │       │  │  addCiphernode(node):                 │    │
│     │  │       │  │    Inserts uint160(node) into         │    │
│     │  │       │  │    Lean Incremental Merkle Tree (IMT) │    │
│     │  │       │  │    Increments numCiphernodes          │    │
│     │  │       │  │    Emits CiphernodeAdded(node)        │    │
│     │  │       │  └───────────────────────────────────────┘    │
│     │  │    7. Calls _updateOperatorStatus(msg.sender)         │
│     │  │       │                                               │
│     │  │       │  Activation check (ALL must be true):         │
│     │  │       │  ✓ registered == true                         │
│     │  │       │  ✓ licenseBond >= requiredBond * 80%          │
│     │  │       │  ✓ ticketBalance / ticketPrice >= minTickets  │
│     │  │       │                                               │
│     │  │       │  If ALL true AND was not active:              │
│     │  │       │    → active = true                            │
│     │  │       │    → numActiveOperators++                     │
│     │  │       │    → Emit OperatorActivationChanged(node,true)│
│     │  │  }                                                    │
│     │  └───────────────────────────────────────────────────────┘
│     │
├─ 3. Waits for transaction receipt
│
└─ OUTPUT: "Transaction hash: 0x..."
```

### What the on-chain registration achieves:

1. **IMT Insertion**: The node's address is now in the Incremental Merkle Tree. This tree is
   snapshot at each E3 request to determine eligible committee members.
2. **Active Status**: If bond + tickets meet thresholds, the node is immediately active and eligible
   for committee selection.
3. **Event Emission**: `CiphernodeAdded` and `OperatorActivationChanged` events are emitted, which
   running ciphernodes pick up via their EVM readers.

---

## Step 3: `interfold ciphernode activate`

**File:** `crates/cli/src/ciphernode/lifecycle.rs` → `activate()`

```
User runs: interfold ciphernode activate
│
└─ Currently delegates directly to register()
   └─ Calls BondingRegistryContract.registerOperator()
```

> **BUG / LIMITATION:** `activate()` simply calls `register()` which calls `registerOperator()`. The
> contract has `require(!operators[msg.sender].registered, AlreadyRegistered())`, so calling
> `activate` on an already-registered operator will **revert**. This command only works for
> operators who were previously deregistered (and whose exit has unlocked) — it re-registers them.
>
> There is currently **no on-chain function** to force re-evaluation of an operator's active status
> without a state change. If an operator becomes inactive (e.g., ticket balance drops below
> threshold) and later tops up tickets, the `_updateOperatorStatus()` call inside
> `addTicketBalance()` or `bondLicense()` will automatically re-activate them. A standalone
> "activate" trigger doesn't exist on the contract.

---

## Step 4: `interfold ciphernode status`

**File:** `crates/cli/src/ciphernode/lifecycle.rs` → `status()`

```
User runs: interfold ciphernode status
│
├─ ChainContext::new() (same as register)
│
├─ Reads on-chain state (multiple view calls):
│   ├─ operator.registered
│   ├─ operator.active
│   ├─ operator.exitRequested
│   ├─ ticketToken.balanceOf(address) → ticket balance
│   ├─ operator.licenseBond → license bond amount
│   ├─ pendingExits.ticketAmount, pendingExits.licenseAmount
│   ├─ bondingRegistry.minTicketBalance → required minimum
│   ├─ bondingRegistry.ticketPrice → price per ticket
│   └─ bondingRegistry.licenseRequiredBond → required bond
│
└─ OUTPUT:
   Address:          0x1234...
   Registered:       true
   Active:           true
   Exit Pending:     false
   Ticket Balance:   100 (available: 95)
   License Bond:     50000 FOLD
   Pending Exits:    tickets=0, license=0
   Requirements:     minTickets=10, ticketPrice=1000000, licenseBond=50000
```

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
┌──────────────┐     registerOperator()     ┌──────────────────┐
│   CLI/User   │ ──────────────────────────→ │  BondingRegistry │
└──────────────┘                             └────────┬─────────┘
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
