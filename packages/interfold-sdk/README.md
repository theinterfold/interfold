# Interfold TypeScript SDK

A powerful, type-safe TypeScript SDK for interacting with Interfold smart contracts. This SDK
provides real-time event listening, contract interaction methods, and comprehensive error handling.

## Features

- **Event-driven architecture**: Listen to smart contract events in real-time
- **Type-safe**: Built with TypeScript and uses generated types from contracts
- **Easy contract interactions**: Simple methods for reading from and writing to contracts
- **React integration**: Includes React hooks for easy frontend integration (via `@interfold/react`)
- **Modular architecture**: Tree-shakeable sub-modules for contracts, events, and encryption
- **Encryption helpers**: Standalone FHE encryption functions with optional ZK proof generation
- **Error handling**: Comprehensive error handling with custom error types
- **Gas estimation**: Built-in gas estimation for transactions
- **Event polling**: Support for both WebSocket and polling-based event listening

## Installation

```bash
pnpm add @interfold/sdk
```

## Quick Start

```typescript
import { CommitteeSize, InterfoldSDK, InterfoldEventType, RegistryEventType } from '@interfold/sdk'
import { createPublicClient, createWalletClient, http, custom } from 'viem'
import { sepolia } from 'viem/chains'

// Initialize clients
const publicClient = createPublicClient({
  chain: sepolia,
  transport: http('YOUR_RPC_URL'),
})

const walletClient = createWalletClient({
  chain: sepolia,
  transport: custom(window.ethereum),
})

// Create SDK instance
const sdk = new InterfoldSDK({
  publicClient,
  walletClient,
  contracts: {
    interfold: '0x...', // Your Interfold contract address
    ciphernodeRegistry: '0x...', // Your CiphernodeRegistry contract address
    feeToken: '0x...', // Your ERC-20 fee token address
  },
  chain: sepolia,
  // Match the parameter set selected by the target E3.
  thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
})

// Listen to events with the unified event system
sdk.onInterfoldEvent(InterfoldEventType.E3_REQUESTED, (event) => {
  console.log('E3 Requested:', event.data)
})

sdk.onInterfoldEvent(RegistryEventType.COMMITTEE_RANDOMNESS_REQUESTED, (event) => {
  console.log('Committee randomness requested:', event.data)
})

// Interact with contracts
const now = BigInt(Math.floor(Date.now() / 1000))
const requestParams = {
  committeeSize: CommitteeSize.Minimum,
  inputWindow: [now, now + 300n] as const,
  e3Program: '0x...',
  paramSet: 0, // Insecure512 for development
  computeProviderParams: '0x...',
  customParams: '0x...',
}
const quote = await sdk.getE3Quote(requestParams)
const approvalHash = await sdk.approveFeeToken(quote)
await sdk.waitForTransaction(approvalHash)
const hash = await sdk.requestE3({ ...requestParams, maxFee: quote })
```

### Factory Method

For a simpler setup (especially on the server), use the static `InterfoldSDK.create()` factory:

```typescript
import { InterfoldSDK } from '@interfold/sdk'
import { sepolia } from 'viem/chains'

const sdk = InterfoldSDK.create({
  rpcUrl: 'wss://sepolia.example.com',
  contracts: {
    interfold: '0x...',
    ciphernodeRegistry: '0x...',
    feeToken: '0x...',
  },
  chain: sepolia,
  privateKey: '0x...', // optional — omit for read-only
  // Match the parameter set selected by the target E3.
  thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
})
```

The factory auto-detects HTTP vs WebSocket transports and creates the appropriate viem clients.

## Usage within a browser

Usage within a typescript project should work out of the box, however in order to use wasm related
functionality of the SDK within the browser vite you must do the following:

- Use `vite`
- Use the `vite-plugin-top-level-await` plugin
- Use the `vite-plugin-wasm` plugin
- Exclude the `@interfold/wasm` package from bundling optimization.

This will enable `vite` to correctly bundle and serve the wasm bundle we use effectively.

```
import { defineConfig } from 'vite'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'

export default defineConfig({
  // other config ...
  optimizeDeps: {
    exclude: ['@interfold/wasm'],
  },
  plugins: [wasm(), topLevelAwait()],
})
```

## Event System

The SDK uses a unified event system with TypeScript enums for type safety:

### Interfold Events

```typescript
enum InterfoldEventType {
  // E3 Lifecycle
  E3_REQUESTED = 'E3Requested',
  CIPHERTEXT_OUTPUT_PUBLISHED = 'CiphertextOutputPublished',
  PLAINTEXT_OUTPUT_PUBLISHED = 'PlaintextOutputPublished',

  // E3 Program Management
  E3_PROGRAM_REGISTERED = 'E3ProgramRegistered',

  // Encryption Scheme Management
  ENCRYPTION_SCHEME_ENABLED = 'EncryptionSchemeEnabled',

  // Configuration
  CIPHERNODE_REGISTRY_SET = 'CiphernodeRegistrySet',
  MAX_DURATION_SET = 'MaxDurationSet',
  PARAM_SET_REGISTERED = 'ParamSetRegistered',
  OWNERSHIP_TRANSFERRED = 'OwnershipTransferred',
  INITIALIZED = 'Initialized',
}
```

### Registry Events

```typescript
enum RegistryEventType {
  // On-chain legacy event retained only for pre-VRF registry logs. The
  // ciphernode runtime creates its separate durable CommitteeRequested event
  // after the Registry accepts a VRF response.
  COMMITTEE_REQUESTED = 'CommitteeRequested',
  COMMITTEE_RANDOMNESS_REQUESTED = 'CommitteeRandomnessRequested',
  RANDOMNESS_CIRCUIT_BREAKER_TRIPPED = 'RandomnessCircuitBreakerTripped',
  COMMITTEE_PUBLISHED = 'CommitteePublished',
  COMMITTEE_FINALIZED = 'SortitionCommitteeFinalized',
  INTERFOLD_SET = 'InterfoldSet',
  OWNERSHIP_TRANSFERRED = 'OwnershipTransferred',
  INITIALIZED = 'Initialized',
}
```

### Randomness Provider Events

The provider address is frozen for each E3 and can change after governance rotation, so it is not
part of the static SDK contract addresses. Read `provider`, `requestId`, and `e3Id` from
`CommitteeRandomnessRequested`, then watch that provider through the main SDK:

```typescript
await sdk.onRandomnessProviderEvent(
  provider,
  RandomnessProviderEventType.RANDOMNESS_FULFILLED,
  ({ data }) => {
    console.log(data.requestId, data.e3Id, data.fulfilledAt)
  },
)
```

Use `sdk.getHistoricalRandomnessProviderEvents` with explicit block bounds to recover earlier
fulfillments. Start the live watcher at `historicalToBlock + 1n` so the historical and live ranges
do not overlap. Historical reads are split into bounded RPC queries, and live watchers suppress
duplicate delivery of the same log. `RandomnessFulfilled` proves that the provider stored a
response. The Registry remains authoritative about whether that response was timely and usable. If
the listener config does not define `fromBlock`, the history method requires it as an argument.
Subscribers that share one provider and event watcher must use the same explicit `fromBlock`, or
omit it to join the active watcher.

### Event Data Structure

Each event follows a consistent structure:

```typescript
interface InterfoldEvent<T extends AllEventTypes> {
  type: T
  data: EventData[T] // Typed based on event type
  log: Log // Raw viem log
  timestamp: Date
  blockNumber: bigint
  transactionHash: string
}
```

## React Integration

The SDK includes a React hook via the `@interfold/react` package:

```bash
pnpm add @interfold/react
```

```typescript
import { useInterfoldSDK } from '@interfold/react'

function MyComponent() {
  const {
    sdk,
    isInitialized,
    error,
    requestE3,
    onInterfoldEvent,
    off,
    InterfoldEventType,
    RegistryEventType,
  } = useInterfoldSDK({
    contracts: {
      interfold: '0x...',
      ciphernodeRegistry: '0x...',
      feeToken: '0x...',
    },
    autoConnect: true,
    // 'INSECURE_THRESHOLD_512' for local dev and Sepolia; 'SECURE_THRESHOLD_8192' for production
    thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_512',
  })

  useEffect(() => {
    if (isInitialized) {
      const handler = (event) => {
        console.log('New E3 request:', event)
      }
      onInterfoldEvent(InterfoldEventType.E3_REQUESTED, handler)
      return () => off(InterfoldEventType.E3_REQUESTED, handler)
    }
  }, [isInitialized])

  return (
    <div>
      {error && <p>Error: {error}</p>}
      {!isInitialized && <p>Initializing...</p>}
      {/* Your UI */}
    </div>
  )
}
```

The hook uses wagmi's `usePublicClient` and `useWalletClient` under the hood, so your app must be
wrapped in a wagmi provider.

## Encryption Functions

The SDK provides standalone encryption functions for FHE (Fully Homomorphic Encryption) operations.
These can be used via the SDK instance or imported directly for tree-shaking:

### Via the SDK instance

```typescript
// Generate a public key
const publicKey = await sdk.generatePublicKey()

// Encrypt a single number
const encrypted = await sdk.encryptNumber(42n, publicKey)

// Encrypt a vector
const encryptedVec = await sdk.encryptVector(BigUint64Array.from([1n, 2n, 3n]), publicKey)

// Encrypt with ZK proof generation
const { encryptedData, proof } = await sdk.encryptNumberAndGenProof(42n, publicKey)
```

### Standalone imports

```typescript
import {
  generatePublicKey,
  encryptNumber,
  encryptVector,
  encryptNumberAndGenProof,
  encryptVectorAndGenProof,
  encryptNumberAndGenInputs,
  encryptVectorAndGenInputs,
  computePublicKeyCommitment,
  getThresholdBfvParamsSet,
} from '@interfold/sdk'

// 'INSECURE_THRESHOLD_512' for local dev and Sepolia; 'SECURE_THRESHOLD_8192' for production
const presetName = 'INSECURE_THRESHOLD_512'

const publicKey = await generatePublicKey(presetName)
const encrypted = await encryptNumber(42n, publicKey, presetName)
const { encryptedData, proof } = await encryptNumberAndGenProof(42n, publicKey, presetName)
```

## Modular Imports

The SDK is organized into three sub-modules that can be imported independently for tree-shaking:

```typescript
// Encryption functions and types
import { generatePublicKey, encryptNumber } from '@interfold/sdk/crypto'

// Contract client and types
import { ContractClient } from '@interfold/sdk/contracts'
import type { ContractAddresses, E3 } from '@interfold/sdk/contracts'

// Event listener and types
import { EventListener, InterfoldEventType, RegistryEventType } from '@interfold/sdk/events'
```

All sub-module exports are also re-exported from the main `@interfold/sdk` entry point for
convenience.

## API Reference

### Core Methods

#### Contract Interactions

```typescript
// Approve fee token spending
await sdk.approveFeeToken(amount: bigint);

// Request a new E3 computation
await sdk.requestE3({
  committeeSize: CommitteeSize.Minimum,
  inputWindow: [bigint, bigint],
  e3Program: `0x${string}`,
  paramSet: 0,
  computeProviderParams: `0x${string}`,
  customParams: '0x',
  maxFee: amount,
  gasLimit: 1_500_000n
});

// Publish ciphertext output
await sdk.publishCiphertextOutput(e3Id, {
  contentHash,
  ciphertextCommitment,
  computeProof,
  availabilityProof,
}, gasLimit);

// Read operations
const e3Data = await sdk.getE3(e3Id: bigint);
const publicKey = await sdk.getE3PublicKey(e3Id: bigint);
const quote = await sdk.getE3Quote(params: E3RequestParams);
const stage = await sdk.getE3Stage(e3Id: bigint);
const reason = await sdk.getFailureReason(e3Id: bigint);
```

The original requester can cancel only while the E3 is `Requested`, after the randomness deadline,
and only if no timely VRF result is usable. A valid result disables cancellation. The failure path
returns all service fee escrow and keeps the flat randomness fee charged.

```ts
const hash = await sdk.cancelE3(e3Id)
await sdk.waitForTransaction(hash)
```

#### Event Handling

```typescript
sdk.onInterfoldEvent(eventType: AllEventTypes, callback: EventCallback);

sdk.off(eventType: AllEventTypes, callback: EventCallback);

sdk.once(eventType: AllEventTypes, callback: EventCallback);

const logs = await sdk.getHistoricalEvents(
  eventType: AllEventTypes,
  fromBlock?: bigint,
  toBlock?: bigint
);

// Event polling (if websockets unavailable)
await sdk.startEventPolling();
sdk.stopEventPolling();
```

Committee public keys are emitted as `CommitteePublicKeyChunkPublished` events. Reassemble the
canonical chunk sequence, check its Keccak hash, and validate the decoded key against the event's
proven `pkCommitment` before using it for encryption:

```typescript
import { hexToBytes } from 'viem'
import { CommitteePublicKeyAssembler, RegistryEventType } from '@interfold/sdk'

const assembler = new CommitteePublicKeyAssembler()

await sdk.onInterfoldEvent(
  RegistryEventType.COMMITTEE_PUBLIC_KEY_CHUNK_PUBLISHED,
  async (event) => {
    const assembled = assembler.add(event.data)
    if (!assembled) return

    if (
      !(await sdk.validatePublicKeyCommitment(
        assembled.publicKey,
        hexToBytes(assembled.pkCommitment),
      ))
    ) {
      throw new Error('Committee public-key commitment mismatch')
    }

    assembler.clear(assembled.e3Id)
    // assembled.publicKey is now safe to pass to the encryption methods.
  },
)
```

The assembler tracks at most 128 E3s by default. Pass a positive limit to the constructor if the
application needs a different memory bound. Evicted incomplete keys can be rebuilt by replaying
their chunk events.

#### Encryption

```typescript
// Get BFV parameter set
const params = await sdk.getThresholdBfvParamsSet();

// Key generation
const publicKey = await sdk.generatePublicKey();
const commitment = await sdk.computePublicKeyCommitment(publicKey);
const isValid = await sdk.validatePublicKeyCommitment(publicKey, commitment);

// Encrypt data
const encrypted = await sdk.encryptNumber(data: bigint, publicKey: Uint8Array);
const encryptedVec = await sdk.encryptVector(data: BigUint64Array, publicKey: Uint8Array);

// Encrypt with proof inputs (for ZK verification)
const { encryptedData, circuitInputs } = await sdk.encryptNumberAndGenInputs(data, publicKey);
const { encryptedData, circuitInputs } = await sdk.encryptVectorAndGenInputs(data, publicKey);

// Encrypt with full ZK proof generation
const { encryptedData, proof } = await sdk.encryptNumberAndGenProof(data, publicKey);
const { encryptedData, proof } = await sdk.encryptVectorAndGenProof(data, publicKey);
```

#### Utilities

```typescript
// Gas estimation
const gas = await sdk.estimateGas(functionName, args, contractAddress, abi, value?);

// Transaction waiting
const receipt = await sdk.waitForTransaction(hash);

// Cleanup
sdk.cleanup();
```

## Configuration

```typescript
interface SDKConfig {
  publicClient: PublicClient
  walletClient?: WalletClient
  contracts: {
    interfold: `0x${string}`
    ciphernodeRegistry: `0x${string}`
    feeToken: `0x${string}`
  }
  chain?: Chain
  thresholdBfvParamsPresetName: ThresholdBfvParamsPresetName
}
```

`thresholdBfvParamsPresetName` selects the BFV parameter set used for encryption. It must match the
on-chain `paramSet` index registered in the Interfold contract:

| Preset name                | On-chain `paramSet` index | Use case                                                                 |
| -------------------------- | ------------------------- | ------------------------------------------------------------------------ |
| `'INSECURE_THRESHOLD_512'` | `0`                       | Fast local or testnet work. This preset is not cryptographically secure. |
| `'SECURE_THRESHOLD_8192'`  | `1`                       | Production-equivalent work with degree 8192 and three ciphertext moduli. |

| Network           | Supported presets                                        |
| ----------------- | -------------------------------------------------------- |
| Local development | `'INSECURE_THRESHOLD_512'` and `'SECURE_THRESHOLD_8192'` |
| Sepolia testnet   | `'INSECURE_THRESHOLD_512'` and `'SECURE_THRESHOLD_8192'` |
| Ethereum mainnet  | `'SECURE_THRESHOLD_8192'` only                           |

Use the preset that the target E3 selects. This package includes proof artifacts only for
`'INSECURE_THRESHOLD_512'`. For secure proof generation, use matching application artifacts such as
the `@crisp-e3/sdk/secure-8192` entry point, or compile your own artifacts.

### Proving: embedded circuits or your own

`generateProof()`, `encryptNumberAndGenProof()`, and `encryptVectorAndGenProof()` run the
user-data-encryption (UDE) circuits bundled in this package. Those artifacts are compiled with
`--preset insecure-512 --committee minimum` (`scripts/compile-circuits.sh`), so they only match
`'INSECURE_THRESHOLD_512'` and a minimum-size committee. With `'SECURE_THRESHOLD_8192'`,
`encryptNumberAndGenInputs()` returns N=8192 circuit inputs that the bundled N=512 circuits cannot
execute.

For on-chain Honk verification, compile your own UDE, app, and fold circuits for the preset and
committee your deployment uses, emit the Solidity verifier from them, and feed them the witness from
`encryptNumberAndGenInputs()`. `examples/CRISP` in the monorepo shows the full flow. Secure
artifacts may ship here in a later release.

## Error Handling

The SDK includes comprehensive error handling:

```typescript
import { SDKError } from '@interfold/sdk'

try {
  await sdk.requestE3(params)
} catch (error) {
  if (error instanceof SDKError) {
    console.error(`SDK Error (${error.code}): ${error.message}`)
  } else {
    console.error('Unexpected error:', error)
  }
}
```

## Development

### Building the SDK

```bash
cd packages/interfold-sdk
pnpm build
```

### Running the Demo

```bash
cd examples/basic/client
pnpm install
pnpm dev
```

The demo showcases all SDK features including real-time event listening and contract interactions.

### Testing

```bash
cd packages/interfold-sdk
pnpm test
```

## Architecture

The SDK is organized into a modular architecture with three domain-specific sub-modules:

- **InterfoldSDK** (`interfold-sdk.ts`): Main orchestrator class that delegates to sub-modules
- **Contracts** (`contracts/`): `ContractClient` for contract read/write operations, type
  definitions for contract addresses and E3 data
- **Events** (`events/`): `EventListener` for real-time and historical event subscriptions, typed
  event enums and data interfaces
- **Encryption** (`encryption/`): Standalone FHE encryption functions, BFV parameter management, ZK
  proof generation
- **Utils** (`utils.ts`): Helper functions, error classes, encoding utilities

Each sub-module has its own `index.ts` entry point and can be imported independently.

## License

This project is licensed under the MIT License.
