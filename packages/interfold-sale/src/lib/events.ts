// SPDX-License-Identifier: LGPL-3.0-only

import type { EventArgs } from '../types'
import { bytes32Label, formatDate, formatTokenAmount, shortAddress } from './format'

function eventValue(args: EventArgs, key: string): unknown {
  return args[key]
}

export function describeEvent(name: string, args?: EventArgs): string {
  if (!args) return ''
  if (name === 'BidSubmitted') {
    return `bid #${String(eventValue(args, 'id') ?? '-')} by ${shortAddress(String(eventValue(args, 'owner') ?? ''))} for ${formatTokenAmount(BigInt(String(eventValue(args, 'amount') ?? '0')))}`
  }
  if (name === 'AllocationMinted') {
    return `${formatTokenAmount(BigInt(String(eventValue(args, 'amount') ?? '0')))} to ${shortAddress(String(eventValue(args, 'recipient') ?? ''))} · ${bytes32Label(String(eventValue(args, 'policyId') ?? ''))}`
  }
  if (name === 'PolicyDefined') return bytes32Label(String(eventValue(args, 'policyId') ?? ''))
  if (name === 'ActiveLockUpdated' || name === 'QueuedLockUpdated') {
    return `${shortAddress(String(eventValue(args, 'account') ?? ''))} · ${bytes32Label(String(eventValue(args, 'policyId') ?? ''))} · ${formatTokenAmount(BigInt(String(eventValue(args, 'amount') ?? '0')))}`
  }
  if (name === 'TransferWhitelistUpdated')
    return `${shortAddress(String(eventValue(args, 'account') ?? ''))} · ${String(eventValue(args, 'whitelisted') ?? '-')}`
  if (name === 'ClaimLockExemptUpdated')
    return `${shortAddress(String(eventValue(args, 'account') ?? ''))} · ${String(eventValue(args, 'exempt') ?? '-')}`
  if (name === 'TgeTriggered') return formatDate(BigInt(String(eventValue(args, 'timestamp') ?? '0')))
  return Object.values(args)
    .filter((value) => typeof value !== 'function')
    .slice(0, 3)
    .map(String)
    .join(' · ')
}
