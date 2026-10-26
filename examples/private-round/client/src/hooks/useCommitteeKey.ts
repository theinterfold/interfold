// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { useEffect, useState } from 'react'
import { hexToBytes } from 'viem'
import { CommitteePublicKeyAssembler } from '@interfold/sdk'
import type { CommitteePublicKeyChunkPublishedData } from '@interfold/sdk'
import { CiphernodeRegistryOwnable__factory } from '@interfold/contracts/types'
import { getContractAddresses } from '@/utils/env-config'
import { scanLogs } from '@/utils/logs'
import { getReadSdk, publicClient } from '@/utils/chain'

/**
 * The committee key of an E3, assembled from the registry's `CommitteePublicKeyChunkPublished` logs.
 *
 * The page may open long after the key was published, so the chunks come from the log history, and
 * a live subscription picks up the chunks of a key that is still being published. Both feed one
 * assembler, which ignores a chunk it already holds.
 *
 * @param enabled Whether the key is still needed; the hook does nothing while it is `false`.
 */
export function useCommitteeKey(e3Id: bigint | null, enabled: boolean): Uint8Array | null {
  const [committeeKey, setCommitteeKey] = useState<Uint8Array | null>(null)

  useEffect(() => {
    setCommitteeKey(null)
    if (e3Id === null || !enabled) return
    const sdk = getReadSdk()
    const { ciphernodeRegistry } = getContractAddresses()
    const assembler = new CommitteePublicKeyAssembler()
    let cancelled = false
    let found = false
    // Chunks are handled one at a time: validating a key is async and a key must be accepted once.
    let queue: Promise<void> = Promise.resolve()

    const handle = (data: CommitteePublicKeyChunkPublishedData) => {
      queue = queue.then(async () => {
        if (cancelled || found) return
        try {
          const assembled = assembler.add(data)
          if (!assembled) return
          // A reassembled key is an untrusted transport value until it matches the on-chain commitment.
          if (!(await sdk.validatePublicKeyCommitment(assembled.publicKey, hexToBytes(assembled.pkCommitment)))) {
            console.warn(`Rejected committee key candidate for E3 ${e3Id}: commitment mismatch`)
            return
          }
          found = true
          assembler.clear(e3Id)
          if (!cancelled) setCommitteeKey(assembled.publicKey)
        } catch (err) {
          console.warn(`Ignored invalid committee key chunk for E3 ${e3Id}:`, err)
        }
      })
    }

    const query = {
      address: ciphernodeRegistry,
      abi: CiphernodeRegistryOwnable__factory.abi,
      eventName: 'CommitteePublicKeyChunkPublished',
      args: { e3Id },
      strict: true,
    } as const
    const toData = (args: {
      e3Id: bigint
      publisher: `0x${string}`
      candidateHash: `0x${string}`
      nodes: readonly `0x${string}`[]
      pkCommitment: `0x${string}`
      chunkIndex: number
      chunkCount: number
      totalLength: number
      chunk: `0x${string}`
    }): CommitteePublicKeyChunkPublishedData => ({ ...args, nodes: [...args.nodes] })

    const unwatch = publicClient.watchContractEvent({
      ...query,
      onLogs: (logs) => logs.forEach((log) => handle(toData(log.args))),
    })
    scanLogs((range) => publicClient.getContractEvents({ ...query, ...range }))
      .then(({ logs }) => logs.forEach((log) => handle(toData(log.args))))
      .catch((err) => console.warn(`Could not read the committee key history of E3 ${e3Id}:`, err))

    return () => {
      cancelled = true
      unwatch()
    }
  }, [e3Id, enabled])

  return committeeKey
}
