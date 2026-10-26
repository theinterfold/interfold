// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.tsx'
import { Web3Provider } from './providers/Web3Provider'
import { MISSING_ENV_VARS } from './utils/env-config'
import { initPersistence } from './utils/persistence'
import EnvironmentError from './components/EnvironmentError'
import './globals.css'

// The wallet and chain setup reads the contract addresses, so a misconfigured build must stop before it.
const configured = MISSING_ENV_VARS.length === 0
// The stored bids are keyed to the chain's genesis block, so read it before anything loads them.
if (configured) await initPersistence()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {configured ? (
      <Web3Provider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </Web3Provider>
    ) : (
      <EnvironmentError missingVars={MISSING_ENV_VARS} />
    )}
  </StrictMode>,
)
