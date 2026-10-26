// SPDX-License-Identifier: LGPL-3.0-only
//
// Keeps Hardhat deploy scripts scoped to this template directory only.

import path from 'path'
import { fileURLToPath } from 'url'

const scriptsDir = path.dirname(fileURLToPath(import.meta.url))

/** Absolute path to `templates/default`. */
export const TEMPLATE_ROOT = path.resolve(scriptsDir, '..')

export const DEPLOYMENTS_FILE = path.join(TEMPLATE_ROOT, 'deployed_contracts.json')
export const INTERFOLD_CONFIG_FILE = path.join(TEMPLATE_ROOT, 'interfold.config.yaml')

/** Pin cwd so `@interfold/contracts` deployment helpers write only under the template. */
export function ensureTemplateCwd(): void {
  if (process.cwd() !== TEMPLATE_ROOT) {
    process.chdir(TEMPLATE_ROOT)
  }
}
