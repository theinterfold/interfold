// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Wallet layer (CRISP `Web3Provider` minus wagmi/connectkit): viem over the injected provider
// (MetaMask) OR one of the anvil dev keys — the submission MUST be signed by the party's
// own key because the contract binds the proven address to `msg.sender`.

import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { createPublicClient, createWalletClient, custom, defineChain, http } from 'viem'
import type { Address, PublicClient, WalletClient } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const RPC_URL = import.meta.env.VITE_RPC_URL ?? 'http://127.0.0.1:8545'
const CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID ?? 31337)

export const chain = defineChain({
  id: CHAIN_ID,
  name: CHAIN_ID === 31337 ? 'Anvil' : `chain-${CHAIN_ID}`,
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
})

/** Anvil `test test ... junk` accounts 6 (party A), 7 (party B), 8, 9 and 0 (1–5 are the ciphernodes). */
export const DEV_KEYS: { label: string; key: `0x${string}` }[] = [
  { label: 'anvil #6 (party A)', key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e' },
  { label: 'anvil #7 (party B)', key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356' },
  { label: 'anvil #8', key: '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97' },
  { label: 'anvil #9', key: '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6' },
  { label: 'anvil #0 (round opener)', key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' },
]

interface WalletState {
  publicClient: PublicClient
  walletClient: WalletClient | null
  address: Address | null
  label: string | null
  connectInjected: () => Promise<void>
  connectDevKey: (index: number) => void
  disconnect: () => void
}

const WalletContext = createContext<WalletState | null>(null)

export const WalletProvider = ({ children }: { children: ReactNode }) => {
  const publicClient = useMemo(() => createPublicClient({ chain, transport: http(RPC_URL) }), [])
  const [walletClient, setWalletClient] = useState<WalletClient | null>(null)
  const [label, setLabel] = useState<string | null>(null)

  const connectInjected = useCallback(async () => {
    const eth = (window as unknown as { ethereum?: { request: (a: { method: string; params?: unknown[] }) => Promise<unknown> } }).ethereum
    if (!eth) throw new Error('No injected wallet found (install MetaMask) — or pick an anvil dev key')
    const [account] = (await eth.request({ method: 'eth_requestAccounts' })) as Address[]
    try {
      await eth.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: `0x${CHAIN_ID.toString(16)}` }] })
    } catch {
      /* user may add the chain manually */
    }
    setWalletClient(createWalletClient({ account, chain, transport: custom(eth) }))
    setLabel('injected')
  }, [])

  const connectDevKey = useCallback((index: number) => {
    const dev = DEV_KEYS[index]
    setWalletClient(createWalletClient({ account: privateKeyToAccount(dev.key), chain, transport: http(RPC_URL) }))
    setLabel(dev.label)
  }, [])

  const disconnect = useCallback(() => {
    setWalletClient(null)
    setLabel(null)
  }, [])

  const value = useMemo<WalletState>(
    () => ({
      publicClient: publicClient as PublicClient,
      walletClient,
      address: walletClient?.account?.address ?? null,
      label,
      connectInjected,
      connectDevKey,
      disconnect,
    }),
    [publicClient, walletClient, label, connectInjected, connectDevKey, disconnect],
  )
  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>
}

export const useWallet = (): WalletState => {
  const ctx = useContext(WalletContext)
  if (!ctx) throw new Error('useWallet outside WalletProvider')
  return ctx
}
