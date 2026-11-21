// SPDX-License-Identifier: LGPL-3.0-only
import { writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { renderSolidityVerifier } from './verifiers'

// Qualification only. The package path selects formatting; the key and output stay in the fixture.
export function renderSynchronizedHonk(root: string, key: string, circuit: 'decryption_aggregator' | 'dkg_aggregator', output: string) {
  const contract = circuit === 'dkg_aggregator' ? 'DkgAggregatorVerifier' : 'DecryptionAggregatorVerifier'
  const formattingPath = join(root, `packages/interfold-contracts/contracts/verifiers/bfv/honk/${contract}.sol`)
  const selectedBb = process.env.E3_CUSTOM_BB || 'bb'
  const bb = selectedBb.includes('/') || selectedBb.includes('\\') ? resolve(selectedBb) : selectedBb
  writeFileSync(output, renderSolidityVerifier(root, key, circuit, formattingPath, bb))
}

if (require.main === module) {
  if (process.argv.length !== 3) throw new Error('Expected the exported synchronized decryption fixture directory')
  const fixture = resolve(process.argv[2])
  renderSynchronizedHonk(
    resolve(__dirname, '../..'),
    join(fixture, 'decryption_aggregator.vk'),
    'decryption_aggregator',
    join(fixture, 'SynchronizedHonk.sol'),
  )
}
