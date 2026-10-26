// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useState } from 'react'
import { useWalletClient } from 'wagmi'
import type { Address } from 'viem'
import { CAN_MINT_TEST_TOKENS, chain } from '@/utils/chain'
import { formatError } from '@/utils/error-formatting'
import { type TokenInfo, formatAmount, mintTestTokens } from '@/utils/tokens'
import Spinner from './Spinner'

interface MintButtonProps {
  token: TokenInfo
  account: Address | undefined
  /** Base units to mint. */
  amount: bigint
  /** Runs after the mint is mined, so the page can read the new balance. */
  onMinted?: () => void
  label?: string
}

/** Test deployments only: mints mock tokens to the connected account. Renders nothing where the mocks have no public mint. */
const MintButton: React.FC<MintButtonProps> = ({ token, account, amount, onMinted, label }) => {
  const { data: walletClient } = useWalletClient({ chainId: chain.id })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!CAN_MINT_TEST_TOKENS) return null

  const mint = async () => {
    if (!walletClient || !account) return
    setBusy(true)
    setError(null)
    try {
      await mintTestTokens(walletClient, token.address, account, amount)
      onMinted?.()
    } catch (err) {
      setError(formatError(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className='space-y-2'>
      <button type='button' onClick={() => void mint()} disabled={busy || !walletClient || !account} className='btn sm'>
        {busy ? (
          <>
            <Spinner size={12} /> Minting…
          </>
        ) : (
          (label ?? `Mint ${formatAmount(amount, token.decimals)} test ${token.symbol}`)
        )}
      </button>
      {error && <p className='text-xs text-negative'>{error}</p>}
    </div>
  )
}

export default MintButton
