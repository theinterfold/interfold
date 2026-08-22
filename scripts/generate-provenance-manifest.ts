#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Build the release provenance manifest for the RISC Zero compute guest.
 *
 * `Risc0BfvCiphertextVerifier.imageId` is immutable and names exactly one guest image. A proof
 * tells a verifier which guest ran; it says nothing about which source produced that guest. This
 * manifest is the record that closes that gap, so a third party can start from a released tag and
 * arrive at the deployed image ID.
 *
 * Local fields come from the working tree and the build output. Chain fields need an RPC endpoint
 * and the deployed verifier address; without them the manifest still emits, with those fields null
 * and `complete` false.
 *
 *   pnpm provenance:manifest
 *   pnpm provenance:manifest --rpc https://... --verifier 0x... --out manifest.json
 *
 * The manifest is a record, not a check: it describes what was built and where it was deployed.
 * Nothing in this repository verifies that the recorded image ID is the one the committed sources
 * produce — that takes a reproducible Docker rebuild of the guest, and the reviewer-facing
 * procedure is documented at docs/pages/verifying-the-compute-provider.mdx.
 */

import { execFileSync } from 'child_process'
import { createHash } from 'crypto'
import fs from 'fs'
import path from 'path'

const REPO_ROOT = path.resolve(__dirname, '..')
const SUPPORT = path.join(REPO_ROOT, 'crates', 'support')
const IMAGE_ID_SOL = path.join(SUPPORT, 'contracts', 'ImageID.sol')
const DOCKERFILE = path.join(SUPPORT, 'Dockerfile')

interface Args {
  rpc?: string
  verifier?: string
  out?: string
}

function parseArgs(argv: string[]): Args {
  const args: Args = {}
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]
    const value = argv[i + 1]
    if (flag === '--rpc' || flag === '--verifier' || flag === '--out') {
      if (!value || value.startsWith('--')) {
        throw new Error(`${flag} needs a value`)
      }
      args[flag.slice(2) as keyof Args] = value
      i += 1
    } else {
      throw new Error(`unknown argument '${flag}'`)
    }
  }
  if (args.rpc && !args.verifier) throw new Error('--rpc also needs --verifier')
  if (args.verifier && !args.rpc) throw new Error('--verifier also needs --rpc')
  return args
}

function sh(command: string, commandArgs: string[]): string | null {
  try {
    return execFileSync(command, commandArgs, {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
  } catch {
    return null
  }
}

function readIfPresent(file: string): string | null {
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null
}

function sha256File(file: string): string | null {
  if (!fs.existsSync(file)) return null
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex')
}

function firstMatch(text: string | null, pattern: RegExp): string | null {
  if (!text) return null
  const match = text.match(pattern)
  return match ? match[1] : null
}

/** Collects every Interfold git pin the guest workspace reads, so a split pin is visible. */
function pinnedRevisions(): Record<string, string[]> {
  const manifests = [path.join(SUPPORT, 'Cargo.toml'), path.join(SUPPORT, 'methods', 'guest', 'Cargo.toml')]
  const pins: Record<string, string[]> = {}
  for (const manifest of manifests) {
    const text = readIfPresent(manifest)
    if (!text) continue
    const found = [...text.matchAll(/rev = "([0-9a-f]{40})"/g)].map((m) => m[1])
    pins[path.relative(REPO_ROOT, manifest)] = [...new Set(found)]
  }
  return pins
}

/**
 * Resolves the RISC Zero guest builder image.
 *
 * `risc0-build` reads a bare tag, not an image reference: `docker_container_tag()` returns
 * `RISC0_DOCKER_CONTAINER_TAG`, else the value the caller set on `DockerOptions`, else its own
 * `DEFAULT_DOCKER_TAG` (`risc0-build-3.0.3/src/config.rs:59-70`), and `docker.rs:145-149` then
 * builds `risczero/risc0-guest-builder:<tag>` from it. Both sources here are therefore suffixes,
 * and the repository prefix belongs on the outside of the choice.
 *
 * `crates/support/methods/build.rs:90-95` always sets the second, from `ARG RISC0_TOOLCHAIN` in
 * `crates/support/Dockerfile`, so `DEFAULT_DOCKER_TAG` is unreachable from this repository.
 * Reading it would record `r0.1.88.0` against a build that pulled `r0.1.91.1` — a builder nobody
 * used, which is the outcome this function exists to avoid.
 *
 * The tag is mutable and does not identify a build on its own, so record the resolved digest
 * whenever Docker can supply it.
 *
 * Without a toolchain there is no builder to name, override or not. `guest_builder_tag` panics on a
 * missing `ARG RISC0_TOOLCHAIN` and asserts on an empty one (`build.rs:67-80`), and it runs only
 * inside `if use_docker()` (`build.rs:90-95`). A tree that cannot supply one therefore either
 * failed the Docker build before `risc0-build` read the variable, or built locally and pulled no
 * image at all. Reporting the override there would name a builder nothing used; leaving the field
 * unresolved says what is true and keeps the manifest incomplete.
 */
function builderImage(guestToolchain: string | null) {
  // Trim before the check, not after, matching the assert at `build.rs:71-77`. A whitespace-only
  // value would otherwise name the image `risczero/risc0-guest-builder:r0.`.
  const toolchain = guestToolchain?.trim() || null
  if (!toolchain) return { tag: null, digest: null }
  const suffix = process.env.RISC0_DOCKER_CONTAINER_TAG?.trim() || `r0.${toolchain}`
  const tag = `risczero/risc0-guest-builder:${suffix}`
  const digest = sh('docker', ['image', 'inspect', '--format', '{{index .RepoDigests 0}}', tag])
  return { tag, digest }
}

/** Reads the guest ELF path out of the generated Elf.sol, which is not committed. */
function guestElf() {
  const elfSol = readIfPresent(path.join(SUPPORT, 'tests', 'Elf.sol'))
  const elfPath = firstMatch(elfSol, /"([^"]+program\.bin)"/)
  if (!elfPath) {
    return { path: null, sha256: null, note: 'Elf.sol absent; build the guest first' }
  }
  const sha256 = sha256File(elfPath)
  return {
    path: elfPath,
    sha256,
    note: sha256 ? null : 'Elf.sol names a path that does not exist on this machine',
  }
}

/**
 * How long a single RPC call may take before it counts as unresolved.
 *
 * `fetch` has no default timeout. An endpoint that accepts the connection and never answers would
 * hang instead of leaving the field unresolved, and a record that never finishes says less than one
 * that names what it could not reach.
 */
const RPC_TIMEOUT_MS = 15_000

async function rpcCall(rpc: string, method: string, params: unknown[]): Promise<string | null> {
  try {
    const response = await fetch(rpc, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    })
    const body = (await response.json()) as { result?: string; error?: unknown }
    if (body.error || typeof body.result !== 'string') return null
    return body.result
  } catch {
    return null
  }
}

/** `keccak256("imageId()")[0..4]` and `keccak256("risc0Verifier()")[0..4]`. */
const SELECTOR_IMAGE_ID = '0xef3f7dd5'
const SELECTOR_RISC0_VERIFIER = '0x5c9770c5'

/**
 * A `0x`-prefixed hex string of exactly `bytes` bytes, or null.
 *
 * An RPC result is only known to be a string. Everything downstream treats non-null as resolved, so
 * a malformed answer that survives this far reads as a verified fact — which is the one thing a
 * fail-closed manifest must not do.
 */
function hexOfLength(value: string | null, bytes: number): string | null {
  if (!value) return null
  // Lowercased, not returned as received. Hex is case-insensitive, but `onchainImageId` is later
  // compared against `ImageID.sol` as a plain string — an uppercase RPC answer would read as a
  // mismatch and make the manifest incomplete for no reason.
  return new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value) ? value.toLowerCase() : null
}

/** Any `0x`-prefixed hex string with a whole number of bytes, lowercased, or null. */
function hexBytes(value: string | null): string | null {
  if (!value) return null
  return /^0x([0-9a-fA-F]{2})*$/.test(value) ? value.toLowerCase() : null
}

async function chainFacts(rpc: string, verifier: string) {
  const code = hexBytes(await rpcCall(rpc, 'eth_getCode', [verifier, 'latest']))
  const codePresent = Boolean(code && code !== '0x')
  // SHA-256, not keccak256: Node's crypto has no keccak256, and any fixed digest serves the
  // purpose here as long as the manifest names which one it is.
  const runtimeCodeSha256 =
    code && codePresent
      ? `0x${createHash('sha256')
          .update(Buffer.from(code.slice(2), 'hex'))
          .digest('hex')}`
      : null

  // Both calls return one ABI word. An image ID is that word; an address is its low 20 bytes.
  const onchainImageId = hexOfLength(await rpcCall(rpc, 'eth_call', [{ to: verifier, data: SELECTOR_IMAGE_ID }, 'latest']), 32)
  const underlyingWord = hexOfLength(await rpcCall(rpc, 'eth_call', [{ to: verifier, data: SELECTOR_RISC0_VERIFIER }, 'latest']), 32)

  const chainIdHex = hexBytes(await rpcCall(rpc, 'eth_chainId', []))
  const chainIdValue = chainIdHex ? Number.parseInt(chainIdHex, 16) : Number.NaN

  return {
    // `Number.isSafeInteger` rather than a null check: `parseInt` yields NaN for a malformed
    // answer, NaN passes `!== null`, and `JSON.stringify` then writes it as null — a manifest that
    // claims to be complete while recording no chain.
    chainId: Number.isSafeInteger(chainIdValue) ? chainIdValue : null,
    ciphertextVerifier: verifier,
    ciphertextVerifierRuntimeCodeSha256: runtimeCodeSha256,
    ciphertextVerifierCodePresent: codePresent,
    underlyingRisc0Verifier: underlyingWord ? `0x${underlyingWord.slice(-40)}` : null,
    onchainImageId,
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))

  const dockerfile = readIfPresent(DOCKERFILE)
  const risc0Version = firstMatch(dockerfile, /^ARG RISC0_VERSION=(.*)$/m)
  const risc0Toolchain = firstMatch(dockerfile, /^ARG RISC0_TOOLCHAIN=(.*)$/m)
  // Lowercased for the same reason the RPC answers are: Solidity accepts either case, and this
  // value is compared against `deployment.onchainImageId` as a plain string.
  const committedImageId = firstMatch(readIfPresent(IMAGE_ID_SOL), /(0x[0-9a-fA-F]{64})/)?.toLowerCase() ?? null

  const elf = guestElf()
  const chain = args.rpc && args.verifier ? await chainFacts(args.rpc, args.verifier) : null

  const manifest = {
    schema: 'interfold.compute-provider-provenance/1',
    generatedFrom: {
      sourceCommit: sh('git', ['rev-parse', 'HEAD']),
      sourceDescribe: sh('git', ['describe', '--tags', '--always', '--dirty']),
      treeClean: sh('git', ['status', '--porcelain']) === '',
    },
    build: {
      risc0Version,
      risc0GuestToolchain: risc0Toolchain,
      hostToolchain: firstMatch(readIfPresent(path.join(REPO_ROOT, 'rust-toolchain.toml')), /channel = "([^"]+)"/),
      builderImage: builderImage(risc0Toolchain),
      pinnedRevisions: pinnedRevisions(),
      // Why the guest is pinned where it is, and what that pin does and does not certify. A
      // consumer reading only a commit hash would reasonably assume the code behind it was
      // audited; for the guest, it was not.
      auditBaseline: {
        commit: 'c2097da61b4d07c4ce83840393ff4e9f171eefb4',
        report: 'packages/interfold-contracts/audits/20260714-Interfold - Zenith Audit Report.pdf',
        mitigationReviewCommit: 'c64bcfb890b596e626ea6578c5fbd53f808c3b43',
        guestInAuditScope: false,
        note: 'The 2026-08-17 Zenith audit covered six Solidity files and no Rust. crates/compute-provider, the RISC Zero guest, crates/zk-helpers, and Risc0BfvCiphertextVerifier.sol were outside both the audit and the mitigation review.',
      },
      lockfiles: {
        'crates/support/Cargo.lock': sha256File(path.join(SUPPORT, 'Cargo.lock')),
        'crates/support/methods/guest/Cargo.lock': sha256File(path.join(SUPPORT, 'methods', 'guest', 'Cargo.lock')),
      },
    },
    guest: {
      elfPath: elf.path,
      elfSha256: elf.sha256,
      elfNote: elf.note,
      // The SHA-256 of the ELF is a binary integrity check. It is NOT the image ID, which is
      // computed from the loaded memory image. Both are recorded; neither substitutes for the other.
      imageId: committedImageId,
    },
    deployment: chain,
  }

  // A deployment object exists even when every RPC call failed, so completeness is decided by the
  // fields themselves. Without this a timed-out RPC would produce a manifest that reads as verified.
  const deploymentResolved =
    chain !== null &&
    chain.chainId !== null &&
    chain.ciphertextVerifierCodePresent &&
    chain.ciphertextVerifierRuntimeCodeSha256 !== null &&
    chain.underlyingRisc0Verifier !== null &&
    chain.onchainImageId !== null

  const unresolved: string[] = []
  if (!manifest.guest.elfSha256) unresolved.push('guest.elfSha256')
  if (!manifest.build.builderImage.digest) unresolved.push('build.builderImage.digest')
  if (!chain) {
    unresolved.push('deployment (pass --rpc and --verifier)')
  } else if (!deploymentResolved) {
    if (chain.chainId === null) unresolved.push('deployment.chainId')
    if (!chain.ciphertextVerifierCodePresent) unresolved.push('deployment.ciphertextVerifier (no code at address)')
    if (chain.ciphertextVerifierRuntimeCodeSha256 === null) unresolved.push('deployment.ciphertextVerifierRuntimeCodeSha256')
    if (chain.underlyingRisc0Verifier === null) unresolved.push('deployment.underlyingRisc0Verifier')
    if (chain.onchainImageId === null) unresolved.push('deployment.onchainImageId')
  }

  // The recorded image ID must also be the one deployed, or the manifest describes a different
  // artefact from the one in use.
  if (chain?.onchainImageId && committedImageId && chain.onchainImageId !== committedImageId) {
    unresolved.push(`deployment.onchainImageId (${chain.onchainImageId}) does not match ImageID.sol (${committedImageId})`)
  }

  const output = { ...manifest, complete: unresolved.length === 0, unresolved }
  const json = `${JSON.stringify(output, null, 2)}\n`

  if (args.out) {
    fs.writeFileSync(path.resolve(REPO_ROOT, args.out), json)
    console.log(`provenance manifest written to ${args.out}`)
  } else {
    process.stdout.write(json)
  }

  if (unresolved.length > 0) {
    console.error(
      `\n⚠️  incomplete manifest. Unresolved: ${unresolved.join(', ')}\n` +
        `   An incomplete manifest records an unfinished verification, not a passing result.\n` +
        `   See docs/pages/verifying-the-compute-provider.mdx.`,
    )
  }
}

main().catch((error: unknown) => {
  console.error(`generate-provenance-manifest: ${(error as Error).message}`)
  process.exit(1)
})
