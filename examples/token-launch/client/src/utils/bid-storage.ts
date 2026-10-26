// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { loadState, saveState } from './persistence'

/**
 * The secret of one bid. The chain holds only ciphertexts and a commitment, so these values are the
 * only way to claim: the claim proof opens the commitment. Whoever holds them can claim the bid.
 */
export interface BidSecret {
  saleId: bigint
  /** The address that sent the bid (or signed it for the relayer). */
  bidder: `0x${string}`
  /** The max price step `b`. */
  step: number
  /** The budget `B` in budget units. */
  budget: number
  /** The escrow `X` in budget units: the tier amount that the bid locked. */
  escrow: number
  /** The index of the escrow tier. */
  tier: number
  /** The index of the bid in the sale: the leaf of the claim tree. */
  index: number
  /** The salt of the bid commitment, as a hex field element. */
  salt: `0x${string}`
  bidCommitment: `0x${string}`
  /** The transaction that carried the bid; `null` until it is sent. */
  txHash: `0x${string}` | null
}

export interface SaleKey {
  chainId: number
  program: `0x${string}`
  saleId: bigint
}

const storageKey = ({ chainId, program, saleId }: SaleKey) => `bids:${chainId}:${program.toLowerCase()}:${saleId}`

/** Every secret that this browser holds for the sale. A failed attempt may leave one that never reached the chain. */
export const loadSecrets = (key: SaleKey): BidSecret[] => loadState<BidSecret[]>(storageKey(key)) ?? []

/** Add a secret, or replace the one with the same commitment. Call it before anything is sent. */
export function saveSecret(key: SaleKey, secret: BidSecret): void {
  const kept = loadSecrets(key).filter(({ bidCommitment }) => bidCommitment !== secret.bidCommitment)
  saveState(storageKey(key), [...kept, secret])
}

/** The backup file: every secret of one deployment, as text. */
interface BackupFile {
  kind: 'token-launch-bid-backup'
  version: 1
  chainId: number
  program: `0x${string}`
  bids: (Omit<BidSecret, 'saleId'> & { saleId: string })[]
}

export function exportBackup(key: SaleKey, secrets: readonly BidSecret[]): string {
  const file: BackupFile = {
    kind: 'token-launch-bid-backup',
    version: 1,
    chainId: key.chainId,
    program: key.program,
    bids: secrets.map((secret) => ({ ...secret, saleId: secret.saleId.toString() })),
  }
  return JSON.stringify(file, null, 2)
}

const isHex = (value: unknown): value is `0x${string}` => typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value)
const isUint = (value: unknown): value is number => typeof value === 'number' && Number.isInteger(value) && value >= 0

/** Read a backup file and store its secrets. It refuses a file of another chain or program. Returns the number of secrets stored. */
export function importBackup(text: string, key: Omit<SaleKey, 'saleId'>): number {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error('The file is not a backup: it is not valid JSON.')
  }
  const file = parsed as Partial<BackupFile> | null
  if (!file || file.kind !== 'token-launch-bid-backup' || file.version !== 1 || !Array.isArray(file.bids)) {
    throw new Error('The file is not a bid backup of this app.')
  }
  if (file.chainId !== key.chainId || file.program?.toLowerCase() !== key.program.toLowerCase()) {
    throw new Error('The backup is from another network or another program.')
  }
  let stored = 0
  for (const entry of file.bids) {
    const valid =
      typeof entry.saleId === 'string' &&
      /^\d+$/.test(entry.saleId) &&
      isHex(entry.bidder) &&
      isHex(entry.salt) &&
      isHex(entry.bidCommitment) &&
      [entry.step, entry.budget, entry.escrow, entry.tier, entry.index].every(isUint)
    if (!valid) throw new Error('The backup holds an entry that is not valid.')
    const secret: BidSecret = {
      saleId: BigInt(entry.saleId),
      bidder: entry.bidder,
      step: entry.step,
      budget: entry.budget,
      escrow: entry.escrow,
      tier: entry.tier,
      index: entry.index,
      salt: entry.salt,
      bidCommitment: entry.bidCommitment,
      txHash: isHex(entry.txHash) ? entry.txHash : null,
    }
    saveSecret({ ...key, saleId: secret.saleId }, secret)
    stored++
  }
  return stored
}

/** Offer `text` as a file download. */
export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
