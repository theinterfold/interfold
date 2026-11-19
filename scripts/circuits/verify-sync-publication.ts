// SPDX-License-Identifier: LGPL-3.0-only

// Qualification only: render a verifier from an explicit temporary VK, never install/stamp it.
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { renderSynchronizedHonk } from './render-sync-honk'

export function verifySynchronizedPublication(root: string, fixture: string): number {
  const prepared = JSON.parse(readFileSync(fixture, 'utf8'))
  const source = join(dirname(fixture), 'SynchronizedHonk.sol')
  renderSynchronizedHonk(root, prepared.vk, 'dkg_aggregator', source)
  const result = spawnSync('pnpm', ['exec', 'hardhat', 'test', 'mocha', '--no-compile', 'test/SynchronizedDkgPublication.spec.ts'], {
    cwd: join(root, 'packages/interfold-contracts'),
    env: { ...process.env, E3_SYNC_PUBLICATION_FIXTURE: fixture, E3_SYNC_PUBLICATION_VERIFIER_SOURCE: source },
    stdio: 'inherit',
  })
  if (result.error) throw result.error
  return result.status ?? 1
}

if (require.main === module) {
  if (process.argv.length !== 3) throw new Error('Usage: pnpm test:sync-dkg:contract <prepared-publication.json>')
  process.exit(verifySynchronizedPublication(resolve(__dirname, '../..'), resolve(process.argv[2])))
}
