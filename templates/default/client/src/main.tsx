// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { WagmiProvider, createConfig } from 'wagmi'
import { sepolia, anvil } from 'wagmi/chains'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConnectKitProvider, getDefaultConfig } from 'connectkit'
import App from './App.tsx'

const CHAINS = import.meta.env.DEV ? ([sepolia, anvil] as const) : ([sepolia] as const)

const wagmiConfig = createConfig(
  getDefaultConfig({
    appName: 'Interfold E3',
    enableFamily: false,
    chains: CHAINS,
    walletConnectProjectId: import.meta.env.VITE_WALLETCONNECT_PROJECT_ID!,
  }),
)

// NOTE: ConnectKit doesn’t ship a drop-in chain switcher UI. This just sets the initial chain.
// For a user-facing switcher, implement a small component that calls wagmi’s `useSwitchChain`.
const connectKitOptions = { initialChainId: import.meta.env.DEV ? anvil.id : sepolia.id }

const queryClient = new QueryClient()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <ConnectKitProvider options={connectKitOptions} mode='light'>
          <App />
        </ConnectKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>,
)
