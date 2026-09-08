# Interfold Smart Contracts

## Contract Overview

| Contract                        | Description                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `Interfold.sol`                 | Main protocol coordinator — handles E3 requests, param sets, fee routing, and output publication |
| `CiphernodeRegistryOwnable.sol` | Ciphernode registration and committee selection                                                  |
| `BondingRegistry.sol`           | FOLD token bonding for ciphernodes; tracks bond amounts and manages bond lifecycle               |
| `InterfoldToken.sol`            | FOLD governance/utility token                                                                    |
| `InterfoldTicketToken.sol`      | Collateral-backed tickets used by ciphernodes for sortition entry                                |
| `SlashingManager.sol`           | Fault attribution and slashing for dishonest ciphernodes (accusation → quorum → slash)           |
| `E3RefundManager.sol`           | Issues refunds to requesters when an E3 fails                                                    |
| `test/MockE3Program.sol`        | Stateless BFV program for protocol tests without application-specific rules                      |

## Audits

Contract audit reports are kept in [`audits/`](./audits/).

### Key Interfaces

| Interface          | Description                                                                   |
| ------------------ | ----------------------------------------------------------------------------- |
| `IE3Program`       | Implement this to write a custom E3 program (defines `validate` and `verify`) |
| `IInterfold`       | External interface to the main Interfold contract                             |
| `IBondingRegistry` | Interface for bonding queries and management                                  |
| `ISlashingManager` | Interface for accusation and slashing                                         |
| `IE3RefundManager` | Interface for the refund manager                                              |
| `IComputeProvider` | Interface for compute provider integration                                    |

## Importing the contracts, interfaces or types

To install, run

```sh
pnpm add @interfold/contracts
```

If writing a new E3 program, you can import the necessary interfaces by writing
something similar to:

```solidity
import {
    IE3Program,
} from "@interfold/contracts/contracts/interfaces/IE3Program.sol";

contract MockE3Program is IE3Program {...}
```

[See the stateless mock program](./contracts/test/MockE3Program.sol) or its
[test-only failure harness](./contracts/test/MockE3ProgramHarness.sol) for
examples.

## To deploy

Phase 1 deploys FOLD plus the CCA sale:

```sh
pnpm sale --network sepolia --action prepare --safe 0xSafe
pnpm sale --network sepolia --action plan --config packages/interfold-contracts/deploy/sale/sepolia-sale.config.json
pnpm sale --network sepolia --action deploy --config packages/interfold-contracts/deploy/sale/sepolia-sale.config.json --propose-safe
pnpm sale --network sepolia --action validate --config packages/interfold-contracts/deploy/sale/sepolia-sale.config.json --allow-pending-owner
```

To deploy a Predicate-gated sale, add Predicate at prepare time:

```sh
pnpm sale --network sepolia --action prepare --safe 0xSafe \
  --predicate-registry 0xPredicateRegistry \
  --predicate-policy-id x-your-policy
```

The Safe owners then approve the queued sale activation in the Safe UI. For a
plain sale this is `FOLD.acceptOwnership()`; for a Predicate-gated sale the same
batch also calls `PredicateValidationHook.setAuction(<CCA auction>)`. After
that, rerun sale validation without `--allow-pending-owner`.

`auction.auctionStepsData` is generated from the same packed uint64 schedule
format used by Uniswap's CCA tooling:

```sh
pnpm cca:schedule -- --config deploy/sale/mainnet-sale.config.json --update-config
```

The protocol deploy happens after the sale/TGE prep and upgrades the existing
placeholder bonding registry proxy:

```sh
pnpm protocol --network sepolia --action check-config --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
pnpm protocol --network sepolia --action deploy --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
pnpm protocol --network sepolia --action validate --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
```

Run `check-config` before `deploy`. This action validates the network, required
contract addresses, ProxyAdmin owner, and initial E3 program owner. It does not
send a transaction.

Committee sortition uses a Chainlink VRF v2.5 subscription through
`ChainlinkVrfRandomnessProvider`. Set the coordinator, subscription ID, key
hash, confirmation count, callback gas limit, payment mode, and response timeout
in the `randomness` configuration. Also set `minimumSubscriptionBalance` in wei
for native payment or juels for LINK. The subscription owner must equal
`protocolOwner`. Deployment validation checks this balance, and the provider
checks it again before each request. An underfunded request reverts before the
protocol accepts the E3 payment. Use a dedicated subscription and monitor its
balance because the floor does not reserve funds for concurrent requests or
automatically replenish the subscription. The governance batch accepts provider
ownership, adds the provider as a subscription consumer, and connects it to the
Registry. The mainnet configuration requires a 1 ETH floor and waits 64 blocks
before fulfillment. This confirmation window makes a request-block rewrite more
expensive while remaining within the one-hour response timeout.

This VRF sortition release supports Ethereum mainnet, Sepolia, and local
development chains only. Deployment scripts, the production provider, and the
ciphernode reject other chain IDs. Arbitrum support requires a later contract
and node upgrade.

Ciphernode releases use the on-chain `NodeReleaseRegistry`. A compatible rolling
release keeps both compatibility values and needs no governance transaction. For
a mandatory node-only fix, increase `node_generation`, pause and drain the
protocol, then run `pnpm upgrade:node-release --action prepare --mandatory`.
After enough upgraded nodes acknowledge the release, generate the checked
unpause transaction with `pnpm upgrade:node-release --action resume`.

If a request reaches its randomness deadline without a usable response, the
Registry clears the active provider. This blocks every new E3 request and stops
a withholding provider from creating repeated randomness draws. The Registry
emits `RandomnessCircuitBreakerTripped` for monitoring. Governance must pause
requests, investigate the subscription or provider, and call
`setRandomnessProvider` before requests can resume.

Set `protocolOwner` to the contract that owns and configures the protocol. Set
the optional `safe` field to the same address only when the protocol owner is a
Safe. The deploy action writes a governance transaction file. Use
`--propose-safe` only for a Safe owner. Submit the transaction file through the
native proposal flow for another governance contract.

For an Aragon Admin plugin deployment, set `protocolOwner` to the DAO address
and add the `governance` object:

```json
{
  "protocolOwner": "0xInterfoldDao",
  "governance": {
    "adminPlugin": "0xAdminPlugin",
    "proposerSafe": "0xSafeThatCanExecuteAdminProposals",
    "proposalMetadata": "0x"
  }
}
```

The deploy action writes two files in this mode:

- `<name>.safe-transactions.json`: the raw DAO action list, for review.
- `<name>.governance.safe-builder.json`: one Safe Builder transaction that calls
  `AdminPlugin.executeProposal(...)` with the raw actions.

Import the Safe Builder wrapper into the configured proposer Safe. Do not import
the raw action list into the Safe, because those calls must execute from the
DAO.

Choose one initial E3 program in the protocol configuration. For an existing
program, set `e3Programs` to its deployed address. The deploy action rejects an
address without contract code. Set `bindInitialE3Program` to bind a compatible
program in the governance transaction.

Set `deployMockE3Program` to `true` and set `e3Programs[0]` to the zero address
to deploy `MockE3Program` in the same run. This stateless program applies no
application-specific input or output rules. It has no owner, controller,
setters, or reentrancy hooks. Interfold still verifies each BFV ciphertext proof
and committee decryption proof. Its deterministic receipt is for tests, not
production data availability. Keep requests paused until a production program is
registered and wired. Do not set `bindInitialE3Program` for this option.

`Interfold.initialize` registers the selected program before the governance
transaction executes. Later registrations require an owner transaction.

Set `verifiers.deploy` to `true` to deploy the generated BFV verifier stack. Set
`ciphertextVerifier` to the deployed application ciphertext verifier.

The fee token and the ticket collateral token have separate configuration
fields. For the planned launch, set `feeToken` to USDS and set
`ticketUnderlyingToken` to sUSDS. Set both decimal values to `18`. Set
`ticketPrice` and each ticket slash penalty in sUSDS share units. Do not copy
the six-decimal mock-token values into a release configuration.

The canonical outputs live under `packages/interfold-contracts/deploy/`. The
scripts also mirror addresses into `deployed_contracts.json` for older tasks and
verification.

## E3 pricing and protocol revenue

Protocol revenue comes from successful E3 request fees, not from ticket
purchases. Tickets are collateral-backed sortition capacity deposits for
ciphernodes. The planned launch uses sUSDS shares. Nodes can redeem their shares
after an exit, while the protocol routes slashed shares through the slashed-fund
paths.

The launch pricing model separates node services from the VRF request:

```text
modeled base cost = key generation + coordination + availability
                  + decryption + publication + verification
service fee       = modeled base cost * (1 + marginBps / 10_000)
total quote       = service fee + randomnessFlatFee
treasury revenue  = randomnessFlatFee
                  + service fee * protocolShareBps / 10_000
CN reward pool    = service fee - service protocol share
```

Launch defaults set `marginBps = 1000` and `protocolShareBps = 182`. In plain
English: requests pay a 10% margin over modeled ciphernode cost, and the
protocol treasury receives about 1.82% of the service fee. Because the treasury
share is applied to the service fee in-contract, 1.82% is approximately 20% of
the 10% margin; the remaining fee is distributed to active committee nodes.

The Ethereum launch configuration sets `randomnessFlatFee` to 5 USDS. The fee
reimburses the DAO-funded Chainlink VRF subscription. It does not receive the
service margin, and ciphernodes do not share it. The contract credits this fee
to the request-time treasury when Chainlink accepts the randomness request.

The 5 USDS value is a rounded long-term operating estimate. Actual requests can
cost more or less because Ethereum gas prices and the ETH price change. The DAO
subscription reserve absorbs this variance across requests. This estimate
assumes that 1 USDS is worth 1 USD.

The randomness fee is not part of service escrow. If randomness times out, the
requester receives all service escrow, but the randomness fee stays charged. A
late fulfillment can still charge the subscription after the E3 fails. If the
Chainlink request itself reverts, the complete E3 request reverts and no fee is
collected.

Do not configure `protocolShareBps = 2000` unless the intent is for the treasury
to receive 20% of the service fee. With a 10% margin, that would pay ciphernodes
less than the modeled base cost.

## Localhost deployment

If you are running Interfold locally, you can first start a local hardhat (or
Anvil) node, then deploy the contracts using the following commands:

```sh
pnpm hardhat node
pnpm clean:deployments
pnpm sale --network localhost --action full-test --mock-cca --safe 0xYourLocalSafeOrOperator
pnpm protocol --network localhost --action deploy --config packages/interfold-contracts/deploy/protocol/localhost-protocol.config.json --sync-integration-config
```

This will ensure that you are a local node running, as well as that there are no
conflicting deployments stored in localhost.

## Configuration

### Using Environment Variables (Development)

For development, you can set your private key in a `.env` file:

```sh
# .env
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### Using Hardhat Configuration Variables (Production)

For production, it's recommended to use Hardhat's configuration variables
system:

```sh
# Set your configuration variable (securely stored)
npx hardhat vars set PRIVATE_KEY

```

Then update `hardhat.config.ts` to use configuration variables:

```typescript
import { vars } from "hardhat/config";

const privateKey = vars.get("PRIVATE_KEY", "");
```

## Registering a Ciphernode

The tasks use the first signer configured in your Hardhat network configuration.

To add a ciphernode to the registry:

```sh
pnpm ciphernode:add --network [network]
```

Options:

- `--ciphernode-bond-amount`: Amount of FOLD to bond (default: 1000 FOLD)
- `--ticket-amount`: Amount of the configured ticket collateral token

For testing/development, you can also use the admin task to register any
ciphernode address:

```sh
pnpm ciphernode:admin-add --network localhost --ciphernode-address [address]
```

To request a new committee, run

```sh
pnpm run hardhat committee:new --network [network]
```

To publish the public key of a committee, run

```sh
pnpm run hardhat --network [network] committee:publish --e3-id [e3-id] --nodes [node address],[node address] --public-key [publickey] --proof [hex-encoded pk proof]
```

To activate an E3, run

```sh
pnpm run hardhat --network [network] e3:activate --e3-id [e3-id]
```

To publish an input for an active E3, run

```sh
pnpm run hardhat --network [network] e3:publishInput --e3-id [e3-id] --data [input data]
```
