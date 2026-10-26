// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { ConnectKitButton } from 'connectkit'

/** A note asking for a wallet, with the connect button. */
export const ConnectPrompt: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className='note flex flex-wrap items-center justify-between gap-3'>
    <span>{children}</span>
    <ConnectKitButton.Custom>
      {({ show, isConnecting }) => (
        <button type='button' onClick={show} className='btn sm'>
          {isConnecting ? 'Connecting…' : 'Connect wallet'}
        </button>
      )}
    </ConnectKitButton.Custom>
  </div>
)
