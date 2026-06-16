// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { WagmiProvider, createConfig, http } from 'wagmi'
import { mainnet } from 'wagmi/chains'
import { injected, walletConnect } from 'wagmi/connectors'
import { custom } from 'viem'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConnectKitProvider } from 'connectkit'
import React from 'react'
import { getChain } from '@/utils/methods'

const walletConnectProjectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || ''
if (!walletConnectProjectId)
  console.warn('VITE_WALLETCONNECT_PROJECT_ID is not set in .env file. WalletConnect will not function properly.')

const chain = getChain()
const rpcUrl = import.meta.env.VITE_RPC_URL || 'http://127.0.0.1:8545'

// ConnectKit hard-codes an internal `ensFallbackConfig` that points mainnet at
// viem's default `http()` transport — which resolves to the public, rate-limited,
// CORS-hostile `eth.merkle.io`. It activates that fallback specifically when
// mainnet is NOT in our wagmi config, and there is no option to disable it.
//
// To keep our chain list minimal AND stop the requests, we include mainnet but
// hand it a transport that never makes a network call. ConnectKit then uses
// this no-op transport instead of spinning up its own mainnet client. ENS
// lookups silently fail (we don't display ENS names anywhere) and no public
// RPC is ever contacted.
const ensDisabledMainnet = custom({
  request: async () => {
    throw new Error('mainnet RPC disabled (ENS lookups suppressed)')
  },
})

// We deliberately omit the Coinbase Wallet connector — its SDK also pings
// public mainnet on init for Smart Wallet account discovery and complains
// about COOP headers. Users on the Coinbase browser extension are still
// picked up by `injected()`.
const connectors = [
  injected(),
  ...(walletConnectProjectId ? [walletConnect({ projectId: walletConnectProjectId, showQrModal: false })] : []),
]

const config = createConfig({
  chains: [chain, mainnet],
  transports: {
    [chain.id]: http(rpcUrl),
    [mainnet.id]: ensDisabledMainnet,
  },
  connectors,
})

const queryClient = new QueryClient()

// NOTE: ConnectKit doesn’t ship a drop-in chain switcher UI. This just sets the initial chain.
// For a user-facing switcher, implement a small component that calls wagmi’s `useSwitchChain`.
const options = { initialChainId: getChain().id }

export const Web3Provider = ({ children }: { children: React.ReactNode }) => {
  return (
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <ConnectKitProvider options={options} mode='light'>
          {children}
        </ConnectKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  )
}
