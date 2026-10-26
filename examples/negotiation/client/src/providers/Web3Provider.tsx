// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { WagmiProvider, createConfig, http } from 'wagmi'
import { mainnet } from 'wagmi/chains'
import { injected, walletConnect } from 'wagmi/connectors'
import { custom } from 'viem'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConnectKitProvider } from 'connectkit'
import { WALLETCONNECT_PROJECT_ID } from '@/utils/env-config'
import { HTTP_RPC_URL, chain } from '@/utils/chain'

if (!WALLETCONNECT_PROJECT_ID) {
  console.warn('VITE_WALLETCONNECT_PROJECT_ID is not set: only injected wallets (browser extensions) are available.')
}

// ConnectKit hard-codes an internal ENS fallback that points mainnet at viem's default public
// transport, and it activates that fallback whenever mainnet is not in the wagmi config. Including
// mainnet with a transport that never makes a network call stops those requests; ENS lookups fail
// silently, and this app shows no ENS names.
const ensDisabledMainnet = custom({
  request: async () => {
    throw new Error('mainnet RPC disabled (ENS lookups suppressed)')
  },
})

// The Coinbase Wallet connector is left out on purpose: its SDK pings public mainnet on init and
// complains about the cross-origin isolation headers. The Coinbase extension is still found by `injected()`.
const connectors = [
  injected(),
  ...(WALLETCONNECT_PROJECT_ID ? [walletConnect({ projectId: WALLETCONNECT_PROJECT_ID, showQrModal: false })] : []),
]

const config = createConfig({
  chains: [chain, mainnet],
  transports: {
    [chain.id]: http(HTTP_RPC_URL),
    [mainnet.id]: ensDisabledMainnet,
  },
  connectors,
})

const queryClient = new QueryClient()

export const Web3Provider = ({ children }: { children: React.ReactNode }) => (
  <WagmiProvider config={config}>
    <QueryClientProvider client={queryClient}>
      <ConnectKitProvider options={{ initialChainId: chain.id }} mode='light'>
        {children}
      </ConnectKitProvider>
    </QueryClientProvider>
  </WagmiProvider>
)
