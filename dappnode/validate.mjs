// SPDX-License-Identifier: LGPL-3.0-only

import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { validateComposeSchema, validateDappnodeCompose, validateManifestSchema, validateSetupWizardSchema } from '@dappnode/schemas'
import { readCompose, readManifest, readSetupWizardIfExists } from '@dappnode/dappnodesdk/dist/files/index.js'

const path = (name) => fileURLToPath(new URL(name, import.meta.url))
const root = path('.')
for (const variant of readdirSync(path('package_variants'))) {
  const directories = [{ dir: root }, { dir: path(`package_variants/${variant}`) }]
  const { manifest } = readManifest(directories)
  const compose = readCompose(directories)
  const wizard = readSetupWizardIfExists(directories)
  validateManifestSchema(manifest)
  validateDappnodeCompose(compose, manifest)
  validateSetupWizardSchema(wizard)
  const temporary = mkdtempSync(join(tmpdir(), 'interfold-compose-'))
  try {
    const merged = join(temporary, 'docker-compose.yml')
    writeFileSync(merged, yaml.dump(compose))
    await validateComposeSchema([merged])
  } finally {
    rmSync(temporary, { recursive: true, force: true })
  }
  console.log(`PASS: ${variant} manifest, Compose, and setup wizard validation`)
}
