// SPDX-License-Identifier: LGPL-3.0-only

import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'

import { ROOT_DIR, fail } from './core.mjs'
import { releaseChannel } from './version.mjs'

// The test-only archive holds a CLI built with `test-only-skip-proof-aggregation`. The install script
// and `interfold update` select `interfold-<platform>.tar.gz`, so they never install it.
const TEST_ONLY_BINARY = 'interfold-test-only-skip-proof-aggregation-linux-x86_64.tar.gz'
const REQUIRED_BINARIES = ['interfold-linux-x86_64.tar.gz', 'interfold-macos-aarch64.tar.gz', TEST_ONLY_BINARY]

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
  // The lookahead keeps `0.19.0` from matching the heading of `0.19.0-test.2`.
  const start = new RegExp(`^#+ \\[?v?${escapeRegularExpression(version)}(?![0-9A-Za-z.+-])`)
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

/**
 * The changelog of a release. auto-changelog compares each tag with the tag before it, so the
 * section of a stable version lists only the changes since its last pre-release. A stable release
 * also lists the sections of its pre-releases, which its users never installed.
 */
export function changelogForRelease(changelog, version) {
  const versions = [version]
  if (!version.includes('-')) {
    const prerelease = new RegExp(`^#+ \\[?v?(${escapeRegularExpression(version)}-[0-9A-Za-z.-]+)`)
    for (const line of changelog.split('\n')) {
      const match = prerelease.exec(line)
      if (match) versions.push(match[1])
    }
  }
  const sections = versions.map((name) => ({ name, text: changelogForVersion(changelog, name) })).filter((section) => section.text)
  if (sections.length <= 1) {
    return sections[0]?.text ?? ''
  }
  return sections.map((section) => `#### v${section.name}\n\n${section.text}`).join('\n\n')
}

/** The upgrade note of a release, from `scripts/release/notes/<version>.md`, if there is one. */
function upgradeNote(version, rootDir) {
  const path = join(rootDir, 'scripts', 'release', 'notes', `${version}.md`)
  return existsSync(path) ? readFileSync(path, 'utf8').trim() : ''
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
  const changelog = existsSync(changelogPath) ? changelogForRelease(readFileSync(changelogPath, 'utf8'), version) : ''
  const upgrade = upgradeNote(version, rootDir)
  const npmTag = releaseChannel(version)
  const warning = isPrerelease
    ? '> **This is a pre-release version.**\n> Pre-release versions can contain bugs and breaking changes.\n\n'
    : ''
  const checksums = requiredAssets
    .map((asset) => `${checksum(join(assetsDir, asset))}  ${asset}`)
    .sort()
    .join('\n')

  return `## Release v${version}

Candidate commit: \`${candidateSha}\`

${warning}${upgrade ? `### Upgrade\n\n${upgrade}\n\n` : ''}### What Changed

${changelog || 'See CHANGELOG.md for details.'}

---

## Installation

### Install the CLI

Install the CLI with the install script:

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/theinterfold/interfold/main/install | bash${isPrerelease ? ` -s -- --version v${version}` : ''}
\`\`\`

To change an installed CLI to this release, run:

\`\`\`bash
interfold update${isPrerelease ? ` --version v${version}` : ''}
\`\`\`

Release 0.19.0 and earlier do not have \`interfold update\`. On these releases, use the install script.

### npm packages

\`\`\`bash
npm install @interfold/sdk@${npmTag}
npm install @interfold/contracts@${npmTag}
npm install @interfold/config@${npmTag}
npm install @interfold/react@${npmTag}
\`\`\`

## Binary Assets

- \`interfold-<platform>.tar.gz\`: Interfold CLI
- \`${TEST_ONLY_BINARY}\`: Interfold CLI for tests and CI only. It is built with the
  \`test-only-skip-proof-aggregation\` Cargo feature, so its nodes accept \`skip_proof_aggregation: true\`.
  Do not use it in production.

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
