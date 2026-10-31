// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import { invalidBlockOverrides, parseNetworkHosts, selectNetwork, unscopedOverrideKeys } from './src/lib/networks'

export default defineConfig(({ mode }) => {
  // Fail the build, not the page: the bundle reads these values only in the browser.
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const unscoped = unscopedOverrideKeys(env)
  if (unscoped.length > 0) {
    throw new Error(
      `Unscoped dashboard variables: ${unscoped.join(', ')}. ` +
        'Network overrides use VITE_<NETWORK>_<SETTING>, for example VITE_MAINNET_RPC_URL. See .env.example.',
    )
  }
  const badBlocks = invalidBlockOverrides(env)
  if (badBlocks.length > 0) {
    throw new Error(`${badBlocks.join(', ')} must be a whole block number. See .env.example.`)
  }
  parseNetworkHosts(env.VITE_NETWORK_HOSTS)
  selectNetwork(env, undefined)

  return {
    plugins: [react()],
    server: {
      port: 5173,
    },
  }
})
