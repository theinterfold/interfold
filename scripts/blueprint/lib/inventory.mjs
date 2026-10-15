// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Mechanical inventory of the repository: every crate, contract and circuit with its size,
// actors, message handlers and workspace dependencies. Everything here is read from the code by
// pattern, so it needs no checking.
//
//   node scripts/blueprint/lib/inventory.mjs    prints the inventory
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join, relative, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
// The blueprint reads the checked-out repository (scripts/blueprint/lib -> the repository root), or
// the tree in BLUEPRINT_ROOT, which diff.mjs sets to read another version of the code.
export const ROOT = process.env.BLUEPRINT_ROOT ? resolve(process.env.BLUEPRINT_ROOT) : join(HERE, '..', '..', '..')
const git = (...args) => {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return ''
  }
}

function walk(dir, ext, out = []) {
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir)) {
    if (name === 'target' || name === 'node_modules' || name.startsWith('.')) continue
    const p = join(dir, name)
    const s = statSync(p)
    if (s.isDirectory()) walk(p, ext, out)
    else if (ext.some((e) => name.endsWith(e))) out.push(p)
  }
  return out
}

const rel = (p) => relative(ROOT, p)
const lines = (p) => readFileSync(p, 'utf8').split('\n')

// Hand-maintained primary responsibilities for the blueprint, not the full Cargo dependency graph.
export const LAYERS = {
  entry: ['cli', 'entrypoint', 'ciphernode-builder', 'dashboard', 'daemon-server', 'console', 'init', 'fs', 'support-scripts', 'zk/cli'],
  clients: ['program-server', 'compute-provider', 'sdk', 'indexer', 'evm-helpers', 'wasm', 'openvm-host', 'openvm-types', 'openvm-prover'],
  workflows: ['request', 'sortition', 'keyshare', 'aggregator', 'slashing', 'zk-prover', 'fhe', 'multithread', 'trbfv', 'bfv-client'],
  adapters: ['evm', 'net', 'sync', 'event-system', 'data', 'data-availability', 'logger'],
  vocabulary: ['events', 'config', 'fhe-params', 'zk-helpers', 'committee', 'committee-hash'],
  foundations: ['crypto', 'polynomial', 'polynomial/fhe-adapter', 'parity-matrix', 'safe', 'hamt', 'utils', 'utils-derive'],
  validation: ['test-helpers', 'tests', 'layout-lock'],
}

function cargoName(dir) {
  const t = readFileSync(join(dir, 'Cargo.toml'), 'utf8')
  const m = t.match(/^\[package\][\s\S]*?^name\s*=\s*"([^"]+)"/m)
  return m ? m[1] : null
}

function cargoDeps(dir) {
  const t = readFileSync(join(dir, 'Cargo.toml'), 'utf8')
  const sec = t.match(/^\[dependencies\]\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m)
  if (!sec) return []
  const out = []
  for (const line of sec[1].split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9_-]+)\s*(?:\.workspace\s*=|=)/)
    if (!m) continue
    const name = m[1]
    if (name.startsWith('e3-') || name.startsWith('interfold')) out.push(name)
    else {
      const pkg = line.match(/package\s*=\s*"([^"]+)"/)
      if (pkg && (pkg[1].startsWith('e3-') || pkg[1].startsWith('interfold'))) out.push(pkg[1])
    }
  }
  return [...new Set(out)]
}

function rustFacts(dir) {
  const files = walk(join(dir, 'src'), ['.rs'])
  let loc = 0
  let tests = 0
  const actors = []
  const handlers = []
  for (const f of files) {
    const L = lines(f)
    loc += L.length
    // Lines inside an inline `#[cfg(test)] mod name { … }` block, and files whose name says test,
    // are test-only: those actors and handlers are kept but marked. Braces are counted per line,
    // which is enough for this codebase.
    const testFile = /(^|\/)(tests?|test_[^/]*|[^/]*_tests?)(\.rs|\/)/.test(rel(f).replace(/^crates\/[^/]+\/src\//, ''))
    const inTest = new Array(L.length).fill(false)
    for (let i = 0; i < L.length; i++) {
      if (!/^\s*#\[cfg\(test\)\]/.test(L[i])) continue
      const j = [i + 1, i + 2].find((n) => n < L.length && /^\s*(pub(\(crate\))?\s+)?mod\s+\w+\s*\{/.test(L[n]))
      if (j === undefined) continue
      let depth = 0
      for (let n = j; n < L.length; n++) {
        const code = L[n]
          .replace(/\/\/.*$/, '')
          .replace(/"(?:[^"\\]|\\.)*"/g, '""')
          .replace(/'.'/g, "''")
        for (const ch of code) depth += ch === '{' ? 1 : ch === '}' ? -1 : 0
        inTest[n] = true
        if (depth <= 0 && n > j) break
        if (depth <= 0 && /\}/.test(code)) break
      }
    }
    L.forEach((line, i) => {
      if (/#\[(test|tokio::test|actix::test|actix_rt::test)\b/.test(line)) tests++
      const test = testFile || inTest[i]
      const a = line.match(/impl(?:<[^>]*>)?\s+(?:actix::)?Actor\s+for\s+([A-Za-z0-9_]+)/)
      if (a) actors.push({ name: a[1], test, ref: `${rel(f)}@${i + 1}@Actor for ${a[1]}` })
      // A long header puts `for Actor` on the next line: read the two lines together, and cite the
      // first one, where the impl block starts.
      const split = /\bHandler</.test(line) && !/\sfor\s/.test(line)
      const h = (split ? `${line} ${L[i + 1] || ''}` : line).match(/impl(?:<[^>]*>)?\s+(?:actix::)?Handler<(.+?)>\s+for\s+([A-Za-z0-9_]+)/)
      if (h)
        handlers.push({
          actor: h[2],
          msg: h[1].replace(/\s+/g, ''),
          test,
          ref: `${rel(f)}@${i + 1}@${split ? `Handler<${h[1]}>` : `for ${h[2]}`}`,
        })
    })
  }
  // Tests in a crate's tests/ folder count too.
  for (const f of walk(join(dir, 'tests'), ['.rs'])) {
    for (const line of lines(f)) if (/#\[(test|tokio::test|actix::test|actix_rt::test)\b/.test(line)) tests++
  }
  return { loc, tests, files: files.length, actors, handlers }
}

// Paths that the map names (LAYERS, CONTRACTS, CIRCUITS, apps) but the repository no longer has.
// The build skips them, and check.mjs lists them.
export const MISSING = []

// The workspace crates under crates/, as the root Cargo.toml lists them.
export function members() {
  const toml = existsSync(join(ROOT, 'Cargo.toml')) ? readFileSync(join(ROOT, 'Cargo.toml'), 'utf8') : ''
  const list = (toml.match(/members\s*=\s*\[([\s\S]*?)\]/) || ['', ''])[1]
  return [...list.matchAll(/"crates\/([^"]+)"/g)].map((m) => m[1])
}

// With `unmapped`, the workspace crates that LAYERS does not name come too, so diff.mjs sees a crate
// that a pull request adds before LAYERS lists it.
export function crates({ unmapped = false } = {}) {
  const out = []
  const named = Object.values(LAYERS).flat()
  const entries = Object.entries(LAYERS).flatMap(([layer, names]) => names.map((short) => [layer, short]))
  if (unmapped) for (const short of members()) if (!named.includes(short)) entries.push(['unmapped', short])
  for (const [layer, short] of entries) {
    const dir = join(ROOT, 'crates', short)
    if (!existsSync(join(dir, 'Cargo.toml'))) {
      MISSING.push(`crates/${short}`)
      continue
    }
    out.push({ id: cargoName(dir), short, kind: 'crate', layer, path: `crates/${short}`, deps: cargoDeps(dir), ...rustFacts(dir) })
  }
  return out
}

// Contracts shown on the chain plate. Libraries, interfaces and generated verifiers are folded into
// three combined units so the plate reads as the deployed system.
export const CONTRACTS = [
  { id: 'Interfold', file: 'Interfold.sol', role: 'orchestrator' },
  { id: 'CiphernodeRegistryOwnable', file: 'registry/CiphernodeRegistryOwnable.sol', role: 'registry' },
  { id: 'BondingRegistry', file: 'registry/BondingRegistry.sol', role: 'registry' },
  { id: 'BondedVotes', file: 'registry/BondedVotes.sol', role: 'registry' },
  { id: 'NodeReleaseRegistry', file: 'registry/NodeReleaseRegistry.sol', role: 'registry' },
  { id: 'SlashingManager', file: 'slashing/SlashingManager.sol', role: 'slashing' },
  { id: 'E3RefundManager', file: 'E3RefundManager.sol', role: 'money' },
  { id: 'InterfoldToken', file: 'token/InterfoldToken.sol', role: 'token' },
  { id: 'InterfoldTicketToken', file: 'token/InterfoldTicketToken.sol', role: 'token' },
  { id: 'ChainlinkVrfRandomnessProvider', file: 'randomness/ChainlinkVrfRandomnessProvider.sol', role: 'randomness' },
  { id: 'Verifiers', dir: 'verifiers', role: 'verifier' },
  {
    id: 'Interfold libraries',
    glob: [
      'lib/InterfoldLifecycle.sol',
      'lib/InterfoldPricing.sol',
      'lib/RegistrySortitionLib.sol',
      'lib/ExitQueueLib.sol',
      'lib/SlashingEvidenceLib.sol',
    ],
    role: 'library',
  },
  { id: 'Bonding libraries', prefix: 'lib/Bonding', role: 'library' },
]

function solFacts(files) {
  let loc = 0
  const events = []
  const functions = []
  for (const f of files) {
    const L = lines(f)
    loc += L.length
    L.forEach((line, i) => {
      const e = line.match(/^\s*event\s+([A-Za-z0-9_]+)\s*\(/)
      if (e) events.push({ name: e[1], ref: `${rel(f)}@${i + 1}@event ${e[1]}` })
      const fn = line.match(/^\s*function\s+([A-Za-z0-9_]+)\s*\(/)
      if (fn) {
        // Look ahead a few lines for the visibility of a multi-line signature.
        const sig = L.slice(i, i + 12).join(' ')
        const head = sig.split('{')[0]
        if (/\b(external|public)\b/.test(head) && !/\b(view|pure)\b/.test(head)) {
          functions.push({ name: fn[1], ref: `${rel(f)}@${i + 1}@function ${fn[1]}` })
        }
      }
    })
  }
  return { loc, events, functions }
}

export function contracts() {
  const base = join(ROOT, 'packages/interfold-contracts/contracts')
  return CONTRACTS.map((c) => {
    let files
    if (c.file) files = [join(base, c.file)]
    else if (c.dir) files = walk(join(base, c.dir), ['.sol']).filter((f) => !/\/honk\/.+\//.test(rel(f).replace(/^.*verifiers\//, '/')))
    else if (c.glob) files = c.glob.map((g) => join(base, g))
    else
      files = (existsSync(join(base, 'lib')) ? readdirSync(join(base, 'lib')) : [])
        .filter((n) => n.startsWith('Bonding'))
        .map((n) => join(base, 'lib', n))
    const path = c.file ? rel(files[0]) : c.dir ? rel(join(base, c.dir)) : rel(join(base, 'lib'))
    MISSING.push(...files.filter((f) => !existsSync(f)).map(rel))
    files = files.filter((f) => existsSync(f))
    if (!files.length) {
      if (!c.file && !c.glob) MISSING.push(c.dir ? path : `${rel(join(base, c.prefix))}*`)
      return null
    }
    return { id: c.id, kind: 'contract', role: c.role, path, files: files.map(rel), ...solFacts(files) }
  }).filter(Boolean)
}

export const CIRCUITS = [
  { id: 'C0 pk', path: 'circuits/bin/dkg/pk', phase: 'dkg' },
  { id: 'C1 pk_generation', path: 'circuits/bin/threshold/pk_generation', phase: 'dkg' },
  { id: 'C2a sk_share_computation', path: 'circuits/bin/dkg/sk_share_computation', phase: 'dkg' },
  { id: 'C2b e_sm_share_computation', path: 'circuits/bin/dkg/e_sm_share_computation', phase: 'dkg' },
  { id: 'C3 share_encryption', path: 'circuits/bin/dkg/share_encryption', phase: 'dkg' },
  { id: 'C4 share_decryption', path: 'circuits/bin/dkg/share_decryption', phase: 'dkg' },
  { id: 'C5 pk_aggregation', path: 'circuits/bin/threshold/pk_aggregation', phase: 'dkg' },
  {
    id: 'P3 user_data_encryption',
    path: 'circuits/bin/threshold/user_data_encryption',
    phase: 'input',
    extra: ['circuits/bin/threshold/user_data_encryption_ct0', 'circuits/bin/threshold/user_data_encryption_ct1'],
  },
  { id: 'C6 share_decryption', path: 'circuits/bin/threshold/share_decryption', phase: 'decrypt' },
  { id: 'C7 decrypted_shares_aggregation', path: 'circuits/bin/threshold/decrypted_shares_aggregation', phase: 'decrypt' },
  { id: 'Recursive aggregation', path: 'circuits/bin/recursive_aggregation', phase: 'fold' },
  { id: 'config', path: 'circuits/bin/config', phase: 'config' },
  { id: 'Circuit library', path: 'circuits/lib', phase: 'lib' },
]

export function circuits() {
  return CIRCUITS.map((c) => {
    const gone = [c.path, ...(c.extra || [])].filter((p) => !existsSync(join(ROOT, p)))
    MISSING.push(...gone)
    if (gone.includes(c.path)) return null
    const files = [c.path, ...(c.extra || [])].flatMap((p) => walk(join(ROOT, p), ['.nr']))
    let loc = 0
    let main = null
    for (const f of files) {
      const L = lines(f)
      loc += L.length
      if (!main) {
        const i = L.findIndex((l) => /^\s*(pub\s+)?fn\s+main\s*\(/.test(l))
        if (i >= 0) main = `${rel(f)}@${i + 1}@fn main(`
      }
    }
    return { id: c.id, kind: 'circuit', phase: c.phase, path: c.path, loc, files: files.length, main }
  }).filter(Boolean)
}

// Client and app units outside the Rust workspace.
export function apps() {
  const unit = (id, kind, path, exts) => {
    if (!existsSync(join(ROOT, path))) {
      MISSING.push(path)
      return null
    }
    const files = walk(join(ROOT, path), exts)
    const loc = files.reduce((n, f) => n + lines(f).length, 0)
    return { id, kind, path, loc, files: files.length }
  }
  return [
    unit('@interfold/sdk', 'package', 'packages/interfold-sdk/src', ['.ts']),
    unit('CRISP program', 'package', 'examples/CRISP/program', ['.rs']),
    unit('CRISPProgram contract', 'contract', 'examples/CRISP/packages/crisp-contracts/contracts', ['.sol']),
    unit('CRISP circuits', 'circuit', 'examples/CRISP/circuits', ['.nr']),
    unit('CRISP server', 'package', 'examples/CRISP/server', ['.rs']),
    unit('CRISP crates', 'crate', 'examples/CRISP/crates', ['.rs']),
  ].filter(Boolean)
}

export function inventory({ unmapped = false } = {}) {
  MISSING.length = 0
  return {
    sha: git('rev-parse', '--short=9', 'HEAD'),
    tag: git('describe', '--tags', '--always') || 'working tree',
    crates: crates({ unmapped }),
    contracts: contracts(),
    circuits: circuits(),
    apps: apps(),
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const inv = inventory()
  const actors = inv.crates.reduce((n, c) => n + c.actors.length, 0)
  const handlers = inv.crates.reduce((n, c) => n + c.handlers.length, 0)
  console.log(
    `crates ${inv.crates.length} · actors ${actors} · handlers ${handlers} · contracts ${inv.contracts.length} · circuits ${inv.circuits.length} · apps ${inv.apps.length}`,
  )
  for (const c of inv.crates)
    console.log(
      `${c.layer.padEnd(12)} ${c.id.padEnd(24)} loc ${String(c.loc).padStart(6)} tests ${String(c.tests).padStart(4)} actors ${c.actors.filter((a) => !a.test).length}+${c.actors.filter((a) => a.test).length}t handlers ${c.handlers.length} deps ${c.deps.length}`,
    )
  for (const c of inv.crates) for (const a of c.actors.filter((a) => a.test)) console.log(`  test actor ${c.id} ${a.name} ${a.ref}`)
}
