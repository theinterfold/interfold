# @interfold/react

React hooks and utilities for Interfold SDK.

## Installation

```bash
npm install @interfold/react @interfold/contracts
# or
yarn add @interfold/react @interfold/contracts
# or
pnpm add @interfold/react @interfold/contracts
```

## Usage

### useInterfoldSDK

A React hook for interacting with the Interfold SDK. This hook provides a clean interface for
managing SDK state, handling contract interactions, and listening to events.

```tsx
import { useInterfoldSDK } from '@interfold/react'

function MyComponent() {
  const {
    sdk,
    isInitialized,
    error,
    requestE3,
    activateE3,
    publishInput,
    onInterfoldEvent,
    off,
    InterfoldEventType,
    RegistryEventType,
  } = useInterfoldSDK({
    autoConnect: true,
    contracts: {
      interfold: '0x...',
      ciphernodeRegistry: '0x...',
    },
    chainId: 1,
  })

  // Listen to events
  React.useEffect(() => {
    if (!isInitialized) return

    const handleE3Requested = (event) => {
      console.log('E3 requested:', event.data)
    }

    onInterfoldEvent(InterfoldEventType.E3_REQUESTED, handleE3Requested)

    return () => {
      off(InterfoldEventType.E3_REQUESTED, handleE3Requested)
    }
  }, [isInitialized, onInterfoldEvent, off, InterfoldEventType])

  // Request computation
  const handleRequest = async () => {
    try {
      const hash = await requestE3({
        threshold: [2, 3],
        startWindow: [BigInt(Date.now()), BigInt(Date.now() + 300000)],
        duration: BigInt(1800),
        e3Program: '0x...',
        e3ProgramParams: '0x...',
        computeProviderParams: '0x...',
        customParams: '0x...',
      })
      console.log('E3 requested with hash:', hash)
    } catch (error) {
      console.error('Failed to request E3:', error)
    }
  }

  if (error) {
    return <div>Error: {error}</div>
  }

  if (!isInitialized) {
    return <div>Initializing SDK...</div>
  }

  return (
    <div>
      <button onClick={handleRequest}>Request E3 Computation</button>
    </div>
  )
}
```

## Features

- **Automatic Wallet Integration**: Seamlessly integrates with wagmi for wallet management
- **Event Handling**: Simple event subscription and cleanup
- **Error Handling**: Comprehensive error states and messages
- **TypeScript Support**: Full type safety with TypeScript
- **Optimized**: Automatic cleanup and efficient re-renders

## Requirements

- React 18+
- wagmi 2.0+
- viem 2.0+

## API

### useInterfoldSDK(config)

#### Parameters

- `config.autoConnect` (boolean, optional): Automatically initialize SDK when wallet is connected
- `config.contracts` (object, optional): Contract addresses for Interfold and CiphernodeRegistry
- `config.chainId` (number, optional): Chain ID for the network

#### Returns

- `sdk`: The raw SDK instance
- `isInitialized`: Boolean indicating if SDK is ready
- `error`: Error message if initialization failed
- `requestE3`: Function to request E3 computation
- `publishInput`: Function to publish encrypted inputs
- `onInterfoldEvent`: Function to subscribe to events
- `off`: Function to unsubscribe from events
- `InterfoldEventType`: Event type constants
- `RegistryEventType`: Registry event type constants

## License

MIT
