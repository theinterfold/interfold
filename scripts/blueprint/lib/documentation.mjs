// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execFileSync } from 'node:child_process'

// Facts store repository paths, never arbitrary URLs or Markdown embedded in JSON.
export const documentationPath = (path) => typeof path === 'string' && /^docs\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.mdx?$/.test(path)

export function documentationURL(repository, ref, path) {
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !ref || !documentationPath(path)) return null
  return `${repository}/blob/${encodeURIComponent(ref)}/${path.split('/').map(encodeURIComponent).join('/')}`
}

export function checkoutRef(root) {
  const git = (...args) => {
    try {
      return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
    } catch {
      return ''
    }
  }
  // Branch links can reach unpublished local documentation once the branch is pushed.
  return git('symbolic-ref', '--quiet', '--short', 'HEAD') || git('rev-parse', 'HEAD')
}
