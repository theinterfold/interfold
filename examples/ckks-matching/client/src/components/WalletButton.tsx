// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'
import { WalletPill } from '@interfold/ckks-editorial'

import { DEV_KEYS, useWallet } from '../wallet'

export const WalletButton = () => {
  const { address, label, connectInjected, connectDevKey, disconnect } = useWallet()
  const [error, setError] = useState<string | null>(null)
  if (address) {
    return (
      <span className="row" style={{ gap: 8 }}>
        <WalletPill label={label} address={address} onClick={disconnect} testId="wallet-pill" />
      </span>
    )
  }
  return (
    <span className="row" style={{ gap: 8 }}>
      <select data-testid="dev-key" defaultValue="" onChange={(e) => e.target.value !== '' && connectDevKey(Number(e.target.value))}>
        <option value="" disabled>
          Dev wallet…
        </option>
        {DEV_KEYS.map((k, i) => (
          <option key={k.key} value={i}>
            {k.label}
          </option>
        ))}
      </select>
      <button type="button" className="btn sm" onClick={() => connectInjected().catch((e) => setError(String(e.message ?? e)))}>
        Connect wallet
      </button>
      {error && <span className="error">{error}</span>}
    </span>
  )
}
