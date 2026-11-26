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
  const circuit = process.argv[3] ?? 'decryption_aggregator'
  if (process.argv.length < 3 || process.argv.length > 4 || (circuit !== 'decryption_aggregator' && circuit !== 'dkg_aggregator')) {
    throw new Error('Expected the exported fixture directory and optional synchronized aggregator')
  }
  const fixture = resolve(process.argv[2])
  renderSynchronizedHonk(resolve(__dirname, '../..'), join(fixture, `${circuit}.vk`), circuit, join(fixture, 'SynchronizedHonk.sol'))
}
