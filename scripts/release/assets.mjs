// SPDX-License-Identifier: LGPL-3.0-only

import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'

import { ROOT_DIR, fail } from './core.mjs'

const REQUIRED_BINARIES = [
  'interfold-linux-x86_64.tar.gz',
  'interfoldup-linux-x86_64.tar.gz',
  'interfold-macos-aarch64.tar.gz',
  'interfoldup-macos-aarch64.tar.gz',
]

function filesBelow(directory) {
  const files = []
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry)
    if (statSync(path).isDirectory()) {
      files.push(...filesBelow(path))
    } else {
      files.push(path)
    }
  }
  return files
}

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function changelogForVersion(changelog, version) {
  const lines = changelog.split('\n')
  const start = new RegExp(`^#+ \\[?v?${escapeRegularExpression(version)}\\]?`)
  const nextVersion = /^#+ \[?v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/
  const startIndex = lines.findIndex((line) => start.test(line))

  if (startIndex < 0) {
    return ''
  }

  const endIndex = lines.findIndex((line, index) => index > startIndex && nextVersion.test(line))
  return lines
    .slice(startIndex + 1, endIndex < 0 ? undefined : endIndex)
    .join('\n')
    .trim()
}

function checksum(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function copyArchives(distDir, assetsDir) {
  const archives = filesBelow(distDir).filter((path) => path.endsWith('.tar.gz'))
  const archiveNames = new Set()

  for (const archive of archives) {
    const name = basename(archive)
    if (archiveNames.has(name)) {
      fail(`release archive name is not unique: ${name}`)
    }
    archiveNames.add(name)
    copyFileSync(archive, join(assetsDir, name))
  }

  return archiveNames
}

function releaseNotes(options, requiredAssets, assetsDir, rootDir) {
  const { candidateSha, circuitSourceHash, isPrerelease, version } = options
  const changelogPath = join(rootDir, 'CHANGELOG.md')
  const changelog = existsSync(changelogPath) ? changelogForVersion(readFileSync(changelogPath, 'utf8'), version) : ''
  const npmTag = isPrerelease ? 'next' : 'latest'
  const warning = isPrerelease
    ? '> **This is a pre-release version.**\n> Pre-release versions can contain bugs and breaking changes.\n\n'
    : ''
  const checksums = requiredAssets
    .map((asset) => `${checksum(join(assetsDir, asset))}  ${asset}`)
    .sort()
    .join('\n')

  return `## Release v${version}

Candidate commit: \`${candidateSha}\`

${warning}### What Changed

${changelog || 'See CHANGELOG.md for details.'}

---

## Installation

### Install with interfoldup

Install the installer:

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/theinterfold/interfold/main/install | bash
\`\`\`

Install Interfold:

\`\`\`bash
interfoldup install
\`\`\`

### npm packages

\`\`\`bash
npm install @interfold/sdk@${npmTag}
npm install @interfold/contracts@${npmTag}
npm install @interfold/config@${npmTag}
npm install @interfold/react@${npmTag}
\`\`\`

## Binary Assets

- \`interfold-*\`: Interfold CLI
- \`interfoldup-*\`: installer and version manager

Supported platforms:

- Linux x86_64
- macOS arm64

## Checksums

\`\`\`
${checksums}
\`\`\`

## Noir Circuits

Source hash: \`${circuitSourceHash}\`
`
}

export function prepareReleaseAssets(options, rootDir = ROOT_DIR) {
  const { candidateSha, circuitSourceHash, tagName, version, workflowRunId } = options
  const assetsDir = join(rootDir, 'release-assets')
  const requiredAssets = [...REQUIRED_BINARIES, `circuits-${version}.tar.gz`]

  rmSync(assetsDir, { force: true, recursive: true })
  mkdirSync(assetsDir, { recursive: true })
  const archiveNames = copyArchives(join(rootDir, 'dist'), assetsDir)

  for (const asset of requiredAssets) {
    if (!existsSync(join(assetsDir, asset))) {
      fail(`required release asset is missing: ${asset}`)
    }
  }
  for (const asset of archiveNames) {
    if (!requiredAssets.includes(asset)) {
      fail(`unexpected release archive: ${asset}`)
    }
  }

  const manifest = join(rootDir, 'deployments/manifest.json')
  if (!existsSync(manifest)) {
    fail('deployments/manifest.json is missing; run pnpm gen:manifest and commit it')
  }
  copyFileSync(manifest, join(assetsDir, 'manifest.json'))

  const provenance = { candidateSha, circuitSourceHash, tag: tagName, workflowRunId }
  writeFileSync(join(assetsDir, 'release-provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`)
  writeFileSync(join(rootDir, 'release_notes.md'), releaseNotes(options, requiredAssets, assetsDir, rootDir))

  console.log(`Prepared ${requiredAssets.length} release archives and release notes.`)
}
