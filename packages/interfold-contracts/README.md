# Interfold Smart Contracts

## Contract Overview

| Contract                        | Description                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `Interfold.sol`                 | Main protocol coordinator — handles E3 requests, param sets, fee routing, and output publication |
| `CiphernodeRegistryOwnable.sol` | Ciphernode registration and committee selection                                                  |
| `BondingRegistry.sol`           | INTF token bonding for ciphernodes; tracks bond amounts and manages bond lifecycle               |
| `InterfoldToken.sol`            | INTF governance/utility token                                                                    |
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

```sh
pnpm deploy --network [network]
```

This will add the deployment information to the `./ignition/deployments`
directory, as well as to the `deployed_contracts.json` file.

Be sure to configure your desired network in `hardhat.config.ts` before
deploying.

For non-local networks, set `INTERFOLD_TGE_TIMESTAMP` to the agreed INTF TGE
Unix timestamp before deploying. The deployment script configures this on
`InterfoldToken` for token-level lock schedules. Local mock deployments default
this timestamp to the latest local block timestamp.

## Localhost deployment

If you are running Interfold locally, you can first start a local hardhat (or
Anvil) node, then deploy the contracts using the following commands:

```sh
pnpm hardhat node
pnpm clean:deployments
pnpm deploy:mocks --network localhost
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

- `--license-bond-amount`: Amount of INTF to bond (default: 1000 INTF)
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
