// SPDX-License-Identifier: LGPL-3.0-only

import { spawnSync } from 'node:child_process'
import { existsSync, unlinkSync } from 'node:fs'
import { join, resolve } from 'node:path'

import { ROOT_DIR, fail, readJson } from './core.mjs'
import { releaseChannel } from './version.mjs'

function defaultExecute(command, args, cwd) {
  return spawnSync(command, args, { cwd, encoding: 'utf8', stdio: 'pipe' })
}

function commandError(command, args, result) {
  const detail = (result.stderr || result.stdout || '').trim()
  return new Error(`${command} ${args.join(' ')} failed${detail ? `: ${detail}` : ''}`)
}

function runChecked(execute, command, args, cwd) {
  const result = execute(command, args, cwd)
  if (result.status !== 0) {
    throw commandError(command, args, result)
  }
  return result.stdout.trim()
}

function isMissingNpmPackage(result) {
  return result.status !== 0 && /(?:E404|404 Not Found|is not in this registry)/i.test(`${result.stdout}\n${result.stderr}`)
}

function packedArchive(packed, packageName) {
  if (Array.isArray(packed)) {
    return packed.find((entry) => entry?.name === packageName) ?? packed[0]
  }

  if (packed && typeof packed === 'object') {
    return packed[packageName]
  }

  return undefined
}

export function publishNpmPackage(packageDirectory, distTag, options = {}) {
  const execute = options.execute ?? defaultExecute
  const rootDir = options.rootDir ?? ROOT_DIR
  const packageDir = resolve(rootDir, packageDirectory)
  const packageJson = readJson(packageDir, 'package.json')
  const packageSpec = `${packageJson.name}@${packageJson.version}`
  const channel = releaseChannel(packageJson.version)
  if (distTag !== channel) {
    fail(`refusing npm distribution tag ${distTag} for ${packageSpec}, which belongs to the ${channel} channel`)
  }

  const packed = JSON.parse(runChecked(execute, 'npm', ['pack', '--json'], packageDir))
  const { filename, integrity: localIntegrity } = packedArchive(packed, packageJson.name) ?? {}

  if (!filename || !localIntegrity) {
    fail(`npm pack did not return an archive and integrity for ${packageSpec}`)
  }

  const archive = join(packageDir, filename)

  try {
    const integrityResult = execute('npm', ['view', packageSpec, 'dist.integrity'], packageDir)

    if (integrityResult.status === 0) {
      const remoteIntegrity = integrityResult.stdout.trim()
      if (remoteIntegrity !== localIntegrity) {
        fail(`published ${packageSpec} has integrity ${remoteIntegrity}, expected ${localIntegrity}`)
      }

      const tagResult = execute('npm', ['view', `${packageJson.name}@${distTag}`, 'version'], packageDir)
      if (tagResult.status !== 0) {
        throw commandError('npm', ['view', `${packageJson.name}@${distTag}`, 'version'], tagResult)
      }
      const taggedVersion = tagResult.stdout.trim()
      if (taggedVersion !== packageJson.version) {
        fail(`${packageSpec} exists, but distribution tag ${distTag} selects ${taggedVersion || 'nothing'}`)
      }

      console.log(`${packageSpec} already has the candidate bytes and distribution tag.`)
      return 'skipped'
    }

    if (!isMissingNpmPackage(integrityResult)) {
      throw commandError('npm', ['view', packageSpec, 'dist.integrity'], integrityResult)
    }

    const publishResult = execute('npm', ['publish', `./${filename}`, '--access', 'public', '--tag', distTag, '--provenance'], packageDir)
    if (publishResult.status !== 0) {
      throw commandError('npm', ['publish', `./${filename}`], publishResult)
    }

    process.stdout.write(publishResult.stdout)
    return 'published'
  } finally {
    if (existsSync(archive)) {
      unlinkSync(archive)
    }
  }
}
