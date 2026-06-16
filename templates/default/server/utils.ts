// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export function ensureEnv(key: string): string {
  const value = process.env[key]
  if (!value) {
    throw new Error(`Missing required env var: ${key}`)
  }
  return value
}

export function getCheckedEnvVars() {
  return {
    RPC_URL: ensureEnv('RPC_URL'),
    INTERFOLD_CONTRACT: ensureEnv('INTERFOLD_ADDRESS'),
    CIPHERNODE_REGISTRY_CONTRACT: ensureEnv('REGISTRY_ADDRESS'),
    E3_PROGRAM_ADDRESS: ensureEnv('E3_PROGRAM_ADDRESS'),
    FEE_TOKEN_CONTRACT: ensureEnv('FEE_TOKEN_ADDRESS'),
    PRIVATE_KEY: ensureEnv('PRIVATE_KEY'),
    CHAIN_ID: parseInt(ensureEnv('CHAIN_ID')),
    PROGRAM_RUNNER_URL: process.env.PROGRAM_RUNNER_URL || 'http://127.0.0.1:13151',
    CALLBACK_URL: process.env.CALLBACK_URL || 'http://127.0.0.1:8080',
  }
}
