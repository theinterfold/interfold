// SPDX-License-Identifier: LGPL-3.0-only

import { useCallback, useEffect, useState } from 'react'
import { BrowserProvider, getAddress } from 'ethers'
import { defer } from '../lib/storage'
import type { SaleDeployment } from '../types'

export function useWallet(deployment?: SaleDeployment) {
  const [account, setAccount] = useState<string>()
  const [chainId, setChainId] = useState<number>()
  const [provider, setProvider] = useState<BrowserProvider>()
  const [error, setError] = useState<string>()

  const refresh = useCallback(async () => {
    if (!window.ethereum) return
    const browserProvider = new BrowserProvider(window.ethereum)
    const [accounts, network] = await Promise.all([
      window.ethereum.request({ method: 'eth_accounts' }) as Promise<string[]>,
      browserProvider.getNetwork(),
    ])
    setProvider(browserProvider)
    setAccount(accounts[0] ? getAddress(accounts[0]) : undefined)
    setChainId(Number(network.chainId))
  }, [])

  useEffect(() => {
    defer(() => {
      void refresh()
    })
    if (!window.ethereum) return undefined
    const handleChange = () => {
      void refresh()
    }
    window.ethereum.on?.('accountsChanged', handleChange)
    window.ethereum.on?.('chainChanged', handleChange)
    return () => {
      window.ethereum?.removeListener?.('accountsChanged', handleChange)
      window.ethereum?.removeListener?.('chainChanged', handleChange)
    }
  }, [refresh])

  const connect = useCallback(async () => {
    if (!window.ethereum) {
      setError('Wallet not found')
      return
    }
    await window.ethereum.request({ method: 'eth_requestAccounts' })
    await refresh()
  }, [refresh])

  const switchNetwork = useCallback(async () => {
    if (!window.ethereum || !deployment) return
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: `0x${deployment.chainId.toString(16)}` }],
    })
    await refresh()
  }, [deployment, refresh])

  return { account, chainId, provider, walletError: error, connect, switchNetwork }
}
