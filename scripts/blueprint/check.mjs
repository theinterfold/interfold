// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Check the blueprint against the checked-out code.
//
//   node scripts/blueprint/check.mjs                 moved and broken references, crates missing or gone
//   node scripts/blueprint/check.mjs --fix           also rewrite the moved line numbers
//   node scripts/blueprint/check.mjs --since <ref>   also list the hand-drawn arrows whose code changed
//
// The generated diagrams follow the code by themselves. The hand-drawn diagrams (curated.mjs, with
// the evidence in refs/) and the facts in facts/ cite code as `path@line@token`. A reference moved
// when its token is now on another line of the same file, and it broke when the token is gone.
// A moved line is found again by its token. When the token has other copies in the file, the
// nearest copy can be the wrong one, so --fix lists those references for a read.
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkRef, fileLines, loadData, ROOT } from './lib/data.mjs'
import { LAYERS, MISSING, members } from './lib/inventory.mjs'
import { CURATED } from './curated.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const fix = args.includes('--fix')
const since = args.includes('--since') ? args[args.indexOf('--since') + 1] : null

// ---- hand-drawn references, with where each one is used ------------------------------------
const { inv, units, report } = loadData()
const refs = []
for (const make of CURATED) {
  const d = make({ units, tag: inv.tag })
  for (const n of d.nodes) if (n.ref) refs.push({ raw: n.ref, where: `${d.id} diagram, box ${n.id}` })
  for (const e of d.edges) for (const r of e.refs || []) refs.push({ raw: r, where: `${d.id} diagram, arrow ${e.from} → ${e.to}` })
}
// Evidence that no diagram shows (a claim the code does not support, a note) is checked the same
// way, so a broken reference there fails the check too.
const shown = new Set(refs.map((r) => r.raw))
for (const f of readdirSync(join(HERE, 'refs')).filter((n) => n.endsWith('.json')))
  for (const claim of JSON.parse(readFileSync(join(HERE, 'refs', f), 'utf8')))
    for (const raw of claim.refs || [])
      if (!shown.has(raw)) {
        shown.add(raw)
        refs.push({ raw, where: `refs/${f}, claim ${claim.id} (on no diagram)` })
      }
for (const r of refs) Object.assign(r, checkRef(r.raw))
// The build accepts a token up to three lines from its cited line. The check wants the exact line.
const cited = (raw) => Number(String(raw).split('@')[1])
for (const r of refs) if (r.status === 'ok' && r.line !== cited(r.raw)) Object.assign(r, { status: 'moved', was: cited(r.raw) })
const moved = refs.filter((r) => r.status === 'moved')
const broken = refs.filter((r) => r.status === 'bad')

// ---- facts references (the build fixes moved ones on the fly and drops broken ones) ----------
const factFiles = readdirSync(join(HERE, 'facts')).filter((f) => f.endsWith('.json'))
const factsMoved = []
for (const f of factFiles)
  for (const u of JSON.parse(readFileSync(join(HERE, 'facts', f), 'utf8')).units || [])
    for (const list of Object.values(u))
      if (Array.isArray(list))
        for (const item of list) {
          if (!item || typeof item.ref !== 'string') continue
          const c = checkRef(item.ref)
          if (c.status === 'moved' || (c.status === 'ok' && c.line !== cited(item.ref))) factsMoved.push({ raw: item.ref, line: c.line })
        }

// ---- workspace crates that the inventory does not list ------------------------------------
const mapped = new Set(Object.values(LAYERS).flat())
const unmapped = members().filter((d) => !mapped.has(d))

// ---- the build, in a temporary folder ------------------------------------------------------
function tryBuild(env = {}) {
  const out = mkdtempSync(join(tmpdir(), 'blueprint-check-'))
  const r = spawnSync(process.execPath, [join(HERE, 'build.mjs')], {
    encoding: 'utf8',
    env: { ...process.env, BLUEPRINT_OUT: out, ...env },
  })
  rmSync(out, { recursive: true, force: true })
  return {
    ok: r.status === 0,
    text: (r.status === 0 ? r.stdout.split('\n')[0] : (r.stderr.match(/^Error: .*$/m) || [r.stderr.trim().split('\n').pop()])[0]).trim(),
  }
}
const build = tryBuild()

// ---- report ---------------------------------------------------------------------------------
const say = (title, items) => {
  console.log(`\n${title}: ${items.length}`)
  for (const x of items.slice(0, 50)) console.log(`  - ${x}`)
  if (items.length > 50) console.log(`  - … and ${items.length - 50} more`)
}
console.log(
  `Blueprint check at ${inv.tag}: ${refs.length} hand-drawn and evidence references, ${report.refs.ok + report.refs.moved + report.refs.bad} facts references.`,
)
say(
  'Broken hand-drawn references (fix by hand)',
  broken.map((r) => `${r.where}: ${r.raw} (${r.why})`),
)
say(
  'Moved hand-drawn references (--fix rewrites the line)',
  moved.map((r) => `${r.where}: ${r.path} line ${r.was} → ${r.line} (${r.token})`),
)
say('Facts references that moved (--fix rewrites them) or broke (the build drops them)', [
  ...factsMoved.map((m) => `moved: ${m.raw} → line ${m.line}`),
  ...report.bad.map((b) => `broken: ${b.unit}: ${b.raw}`),
])
say(
  'Missing or invalid documentation owners (fix by hand)',
  report.documentation.map((d) => `facts/${d.file}, ${d.unit}: ${d.why}`),
)
say('Crates that the blueprint does not show (add them to LAYERS in lib/inventory.mjs)', unmapped)
say('Paths on the map that are gone (remove or rename them in lib/inventory.mjs)', MISSING)
say(
  'Facts for units that the map no longer has (move or remove them in facts/)',
  report.unmatched.map((u) => `facts/${u.file}: ${u.id}`),
)
if (since) {
  const changed = new Set(execFileSync('git', ['diff', '--name-only', since], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean))
  const recheck = [
    ...new Set(refs.filter((r) => changed.has(r.path || r.raw.split('@')[0])).map((r) => `${r.where}: ${r.path || r.raw.split('@')[0]}`)),
  ]
  say(`Hand-drawn arrows whose code changed since ${since} (read them again)`, recheck)
}
console.log(`\nBuild: ${build.ok ? 'passes' : 'FAILS'}. ${build.text}`)

// ---- fix --------------------------------------------------------------------------------------
// A JSON file holds a reference as a plain string. curated.mjs writes one as a string, as a
// template on a path constant (`${SOL}/…`), or as H(path, line, token). rewrite() finds each form
// by its path and token, and changes only the line number.
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const jsEsc = {
  "'": (s) => s.replace(/\\/g, '\\\\').replace(/'/g, "\\'"),
  '"': (s) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"'),
  '`': (s) => s.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${'),
}
const unEsc = (s) => s.replace(/\\(.)/g, '$1')
const parts = (raw) => {
  const at1 = raw.indexOf('@')
  const at2 = raw.indexOf('@', at1 + 1)
  return { path: raw.slice(0, at1), old: raw.slice(at1 + 1, at2), token: raw.slice(at2 + 1) }
}
function rewrite(file, text, raw, line) {
  const { path, old: cited, token } = parts(raw)
  const old = reEsc(cited)
  if (file.endsWith('.json')) {
    const from = JSON.stringify(raw)
    return { text: text.split(from).join(JSON.stringify(`${path}@${line}@${token}`)), n: text.split(from).length - 1 }
  }
  // A constant defined twice with different values stays unresolved, so its references go to "by hand".
  const consts = {}
  for (const [, name, value] of text.matchAll(/const ([A-Z_]+) = '([^']+)'/g))
    consts[name] = name in consts && consts[name] !== value ? null : value
  const resolve = (expr) => expr.replace(/\$\{([A-Z_]+)\}/g, (x, name) => consts[name] ?? x)
  let n = 0
  for (const q of ["'", '"', '`']) {
    const literal = new RegExp(`${reEsc(q)}([^${q}\\n]*?)@${old}@${reEsc(jsEsc[q](token))}${reEsc(q)}`, 'g')
    text = text.replace(literal, (m, prefix) => {
      if (resolve(prefix) !== path) return m
      n++
      return `${q}${prefix}@${line}@${jsEsc[q](token)}${q}`
    })
  }
  // prettier wraps a long H() call over several lines and adds a trailing comma.
  const helper = new RegExp(`H\\(\\s*(['"\`])(.*?)\\1\\s*,\\s*${old}\\s*,\\s*(['"\`])((?:\\\\.|(?!\\3).)*)\\3\\s*,?\\s*\\)`, 'g')
  text = text.replace(helper, (m, q1, p, q2, t) => {
    if (resolve(p) !== path || unEsc(t) !== token) return m
    n++
    return m.replace(new RegExp(`,(\\s*)${old}(\\s*),`), `,$1${line}$2,`)
  })
  return { text, n }
}
if (fix && (moved.length || factsMoved.length)) {
  const files = [
    join(HERE, 'curated.mjs'),
    ...readdirSync(join(HERE, 'refs'))
      .filter((f) => f.endsWith('.json'))
      .map((f) => join(HERE, 'refs', f)),
    ...factFiles.map((f) => join(HERE, 'facts', f)),
  ]
  const text = new Map(files.map((f) => [f, readFileSync(f, 'utf8')]))
  const byHand = []
  const twins = []
  // One rewrite per reference: the same reference can appear more than once.
  const unique = new Map([...moved.map((m) => [m.raw, m.line]), ...factsMoved.map((m) => [m.raw, m.line])])
  for (const [raw, line] of unique) {
    let n = 0
    for (const [f, t] of text) {
      const r = rewrite(f, t, raw, line)
      text.set(f, r.text)
      n += r.n
    }
    if (!n) byHand.push(raw)
    const { path, token } = parts(raw)
    const lines = fileLines(path.replace(/^\.?\//, '')) || []
    if (n && lines.filter((l) => l.includes(token.trim())).length > 1) twins.push(`${path}:${line} (${token})`)
  }
  for (const [f, t] of text) if (t !== readFileSync(f, 'utf8')) writeFileSync(f, t)
  console.log(`\nRewrote ${unique.size - byHand.length} moved reference(s).`)
  if (twins.length)
    console.log(
      `Read these fixed lines. Their token has other copies in the file, so the fix can pick the wrong one:\n  ${twins.join('\n  ')}`,
    )
  if (byHand.length) console.log(`Fix these by hand (their form is not a string, a path template or H()):\n  ${byHand.join('\n  ')}`)
  // A fresh check reads the rewritten files, so it also finds a copy that the fix could not rewrite.
  console.log('\nThe check again, after the fix:')
  const again = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...(since ? ['--since', since] : [])], { stdio: 'inherit' })
  process.exit(again.status ?? 1)
}
const problems = [moved, factsMoved, broken, report.bad, report.documentation, report.unmatched, unmapped, MISSING].reduce(
  (n, list) => n + list.length,
  0,
)
process.exit(problems || !build.ok ? 1 : 0)
