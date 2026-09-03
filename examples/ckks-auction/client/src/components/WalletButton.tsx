// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useState } from 'react'

import { DEV_KEYS, useWallet } from '../wallet'

export const WalletButton = () => {
  const { address, label, connectInjected, connectDevKey, disconnect } = useWallet()
  const [error, setError] = useState<string | null>(null)
  if (address) {
    return (
      <span className="row">
        <span className="mono" title={address}>{label} · {address.slice(0, 6)}…{address.slice(-4)}</span>
        <button className="secondary" onClick={disconnect}>Disconnect</button>
      </span>
    )
  }
  return (
    <span className="row">
      <select data-testid="dev-key" defaultValue="" onChange={(e) => e.target.value !== '' && connectDevKey(Number(e.target.value))}>
        <option value="" disabled>Dev wallet…</option>
        {DEV_KEYS.map((k, i) => (
          <option key={k.key} value={i}>{k.label}</option>
        ))}
      </select>
      <button onClick={() => connectInjected().catch((e) => setError(String(e.message ?? e)))}>Connect wallet</button>
      {error && <span className="badge bad">{error}</span>}
    </span>
  )
}
