# Interfold Smart Contracts

## Contract Overview

| Contract                        | Description                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `Interfold.sol`                 | Main protocol coordinator — handles E3 requests, param sets, fee routing, and output publication |
| `CiphernodeRegistryOwnable.sol` | Ciphernode registration and committee selection                                                  |
| `BondingRegistry.sol`           | FOLD token bonding for ciphernodes; tracks bond amounts and manages bond lifecycle               |
| `InterfoldToken.sol`            | FOLD governance/utility token                                                                    |
| `InterfoldTicketToken.sol`      | USDC-backed tickets used by ciphernodes for sortition entry                                      |
| `SlashingManager.sol`           | Fault attribution and slashing for dishonest ciphernodes (accusation → quorum → slash)           |
| `E3RefundManager.sol`           | Issues refunds to requesters when an E3 fails                                                    |

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

[Check out the E3 mock for an example](./contracts/test/MockE3Program.sol)

## To deploy

Phase 1 deploys FOLD plus the CCA sale:

```sh
pnpm sale --network sepolia --action prepare --safe 0xSafe
pnpm sale --network sepolia --action plan --config packages/interfold-contracts/deploy/sale/sepolia-sale.config.json
pnpm sale --network sepolia --action deploy --config packages/interfold-contracts/deploy/sale/sepolia-sale.config.json --propose-safe
pnpm sale --network sepolia --action validate --config packages/interfold-contracts/deploy/sale/sepolia-sale.config.json --allow-pending-owner
```

The Safe owners then approve `FOLD.acceptOwnership()` in the Safe UI. After
that, rerun sale validation without `--allow-pending-owner`.

The protocol deploy happens after the sale/TGE prep and upgrades the existing
placeholder bonding registry proxy:

```sh
pnpm protocol --network sepolia --action deploy --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json --propose-safe
pnpm protocol --network sepolia --action validate --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
```

The canonical outputs live under `packages/interfold-contracts/deploy/`. The
scripts also mirror addresses into `deployed_contracts.json` for older tasks and
verification.

## E3 pricing and protocol revenue

Protocol revenue comes from successful E3 request fees, not from ticket
purchases. Tickets are USDC-backed sortition capacity deposits for ciphernodes;
they are normally redeemable by the node, while slashed ticket funds are routed
through the failure/success slashed-funds paths.

The launch pricing model is cost-plus:

```text
modeled base cost = key generation + coordination + availability
                  + decryption + publication + verification
gross E3 fee      = modeled base cost * (1 + marginBps / 10_000)
treasury revenue  = gross E3 fee * protocolShareBps / 10_000
CN reward pool    = gross E3 fee - treasury revenue
```

Launch defaults set `marginBps = 1000` and `protocolShareBps = 182`. In plain
English: requests pay a 10% margin over modeled ciphernode cost, and the
protocol treasury receives about 1.82% of the gross E3 fee. Because the treasury
share is applied to the gross fee in-contract, 1.82% gross is approximately 20%
of the 10% margin; the remaining fee is distributed to active committee nodes.

Do not configure `protocolShareBps = 2000` unless the intent is for the treasury
to receive 20% of the whole E3 fee. With a 10% margin, that would pay
ciphernodes less than the modeled base cost.

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

- `--license-bond-amount`: Amount of FOLD to bond (default: 1000 FOLD)
- `--ticket-amount`: Amount of USDC for tickets (default: 1000 USDC)

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
