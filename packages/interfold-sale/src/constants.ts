// SPDX-License-Identifier: LGPL-3.0-only

import { encodeBytes32String } from 'ethers'
import type { Profile, RouteName } from './types'

export const ZERO = '0x0000000000000000000000000000000000000000'
export const PENDING_POLICY = encodeBytes32String('PENDING')

export const DEFAULT_PROFILE: Omit<Profile, 'id'> = {
  name: 'CCA tester',
  account: '',
  amount: '10',
  policyId: 'CCA_TEST',
  label: 'cca-test',
}

export const PUBLIC_RPC: Record<number, string> = {
  1: 'https://ethereum-rpc.publicnode.com',
  11155111: 'https://ethereum-sepolia-rpc.publicnode.com',
}

export const TOKEN_PHASES = ['Virtual', 'CCA', 'Cooldown', 'Live']

export const ROUTES: Array<{ route: RouteName; label: string; path: string }> = [
  { route: 'auction', label: 'Auction', path: '/auction' },
  { route: 'admin', label: 'Admin', path: '/admin' },
]
