// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The architecture change between two versions of the code, drawn as the blueprint. Experimental:
// README.md in this folder says how to turn it off or remove it.
//
//   node scripts/blueprint/diff/diff.mjs                    this branch against its merge base with main
//   node scripts/blueprint/diff/diff.mjs <base> [<head>]    each one a git ref or a folder; the head is
//                                                           the working tree by default
//
// It writes scripts/blueprint/out/interfold-blueprint-diff.html: the blueprint of the head with what
// changed in colour, a number on each box that has changes inside, a Before and After switch, and
// a list of every change. Options for the pull request comment:
//   --md <file>        also write the comment as markdown
//   --page-url <url>   where the comment links the page (default: the page file)
//
// It compares the crates and their dependencies, the actors, the messages that each actor handles,
// the actor addresses that each actor holds, the contract functions and events, the circuits, and
// every box and arrow of the diagrams. A ref as the base means its merge base with the head, so the
// result shows only the branch's own change. Each version is read by a run of this script with
// BLUEPRINT_ROOT set, because ROOT is fixed when the modules load.
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { OUT } from '../lib/data.mjs'
import { inventory, ROOT } from '../lib/inventory.mjs'
import { buildData, pageHtml } from '../lib/page.mjs'
import { evName } from '../generate.mjs'
import { wiring } from '../lib/wiring.mjs'
import { checkoutRef } from '../lib/documentation.mjs'

const SELF = fileURLToPath(import.meta.url)
const HERE = dirname(SELF)
// The snapshot format. A snapshot in another format is not compared.
const VERSION = 1
const T = '\t'
// At most this many characters in the comment (GitHub takes 65536).
const MAX_CHARS = 60000
const MAX_NAME = 120

// ---- snapshot ---------------------------------------------------------------------------------
// The structure of the tree at ROOT, for the counts and the list. Keys join their parts with a tab,
// which no Rust type or Solidity name contains.
function structure() {
  const inv = inventory({ unmapped: true })
  const s = { crates: {}, actors: [], handlers: [], links: [], contracts: {}, circuits: inv.circuits.map((c) => c.id) }
  for (const c of inv.crates) {
    s.crates[c.id] = c.deps
    for (const a of c.actors) if (!a.test) s.actors.push(`${c.id}${T}${a.name}`)
    for (const h of c.handlers) if (!h.test) s.handlers.push(`${c.id}${T}${h.actor}${T}${h.msg}`)
  }
  for (const [crate, actors] of Object.entries(wiring(inv).actors))
    for (const [name, a] of Object.entries(actors))
      for (const f of a.fields) s.links.push(`${crate}${T}${name}${T}${f.target}${T}${f.kind}`)
  // Overloads share a name: number them, so that a new overload counts as a change.
  const numbered = (names) => {
    const seen = {}
    return names.map((n) => ((seen[n] = (seen[n] || 0) + 1) > 1 ? `${n}#${seen[n]}` : n))
  }
  for (const c of inv.contracts)
    s.contracts[c.id] = { functions: numbered(c.functions.map((f) => f.name)), events: numbered(c.events.map((e) => e.name)) }
  return s
}
// The snapshot goes to a file: a large write to a pipe can be cut short when the process exits.
if (process.argv.includes('--snapshot')) {
  const { data } = buildData()
  writeFileSync(process.argv[process.argv.indexOf('--snapshot') + 1], JSON.stringify({ v: VERSION, structure: structure(), data }))
  process.exit(0)
}

// ---- the two trees ----------------------------------------------------------------------------
// A ref is extracted whole (about 45 MB): the facts and the hand-drawn diagrams cite files all over
// the repository, and a file missing from one side would read as a change.
const argv = process.argv.slice(2)
const OPTIONS = ['--md', '--page-url']
const opt = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null)
const positional = argv.filter((a, i) => !a.startsWith('--') && !OPTIONS.includes(argv[i - 1]))
const [baseArg = 'main', headArg] = positional
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
const isDir = (p) => existsSync(p) && statSync(p).isDirectory()
const temp = []
function extract(sha) {
  const dir = mkdtempSync(join(tmpdir(), 'blueprint-diff-'))
  temp.push(dir)
  const tar = join(dir, 'tree.tar')
  git('archive', '--format=tar', '-o', tar, sha)
  execFileSync('tar', ['-xf', tar, '-C', dir])
  rmSync(tar)
  return dir
}
// A folder is read as it is. A ref is read at its commit, or at its merge base with `other`.
function side(arg, other) {
  if (isDir(arg)) return { dir: resolve(arg), label: arg, ref: checkoutRef(resolve(arg)) }
  const sha = other ? git('merge-base', arg, other) : git('rev-parse', '--verify', `${arg}^{commit}`)
  return { dir: extract(sha), label: sha.slice(0, 9), ref: sha }
}
// A version is read by its own scripts when they write this snapshot format, so that its own lists
// (LAYERS, CONTRACTS, CIRCUITS) and hand-drawn diagrams apply: a contract removed with its entry
// still shows as removed. Otherwise, as for a base from before diff.mjs, this script reads it.
function read(dir, ref) {
  const own = join(dir, 'scripts/blueprint/diff/diff.mjs')
  const scripts = existsSync(own) && resolve(own) !== SELF ? [own, SELF] : [SELF]
  const failed = []
  for (const script of scripts) {
    const out = mkdtempSync(join(tmpdir(), 'blueprint-snapshot-'))
    temp.push(out)
    const file = join(out, 'snapshot.json')
    const r = spawnSync(process.execPath, [script, '--snapshot', file], {
      encoding: 'utf8',
      env: { ...process.env, BLUEPRINT_ROOT: dir, BLUEPRINT_SOURCE_REF: ref },
      timeout: 300000,
    })
    const snap = r.status === 0 && existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null
    if (snap && snap.v === VERSION) return { ...snap, own: script !== SELF || dir === ROOT }
    failed.push(`${script}: ${snap ? `snapshot format ${snap.v}` : r.stderr || r.error}`)
  }
  throw new Error(`could not read ${dir}:\n${failed.join('\n')}`)
}
let base, head, before, after
try {
  const local =
    process.env.BLUEPRINT_HEAD_LABEL ||
    `${git('rev-parse', '--short=9', 'HEAD')}${git('status', '--porcelain') ? ' with local changes' : ''}`
  head = headArg ? side(headArg) : { dir: ROOT, label: local, ref: checkoutRef(ROOT) }
  base = side(baseArg, headArg ? (isDir(headArg) ? null : headArg) : 'HEAD')
  before = read(base.dir, base.ref)
  after = read(head.dir, head.ref)
} finally {
  for (const d of temp) rmSync(d, { recursive: true, force: true })
}

// ---- compare the structure --------------------------------------------------------------------
const delta = (a, b) => {
  const A = new Set(a)
  const B = new Set(b)
  return { added: [...B].filter((x) => !A.has(x)).sort(), removed: [...A].filter((x) => !B.has(x)).sort() }
}
const S0 = before.structure
const S1 = after.structure
const crateIds = new Set([...Object.keys(S0.crates), ...Object.keys(S1.crates)])
const deps = (s) => Object.entries(s.crates).flatMap(([id, ds]) => ds.filter((d) => crateIds.has(d)).map((d) => `${id}${T}${d}`))
const parts = (s, kind) => Object.entries(s.contracts).flatMap(([id, c]) => c[kind].map((x) => `${id}${T}${x}`))
const ROWS = [
  ['crates', 'Crates', (s) => Object.keys(s.crates)],
  ['deps', 'Crate dependencies', deps],
  ['actors', 'Actors', (s) => s.actors],
  ['handlers', 'Message handlers', (s) => s.handlers],
  ['links', 'Actor addresses held', (s) => s.links],
  ['contracts', 'Contracts', (s) => Object.keys(s.contracts)],
  ['functions', 'Contract functions', (s) => parts(s, 'functions')],
  ['events', 'Contract events', (s) => parts(s, 'events')],
  ['circuits', 'Circuits', (s) => s.circuits],
]
const ch = Object.fromEntries(ROWS.map(([key, , get]) => [key, delta(get(S0), get(S1))]))

// Every change as a sentence, with the diagram that shows it. A removed thing shows in Before.
const short = (s) => (s.length > MAX_NAME ? `${s.slice(0, MAX_NAME - 1)}…` : s)
const c = (s) => `\`${short(s).replace(/`/g, "'")}\``
const call = (name) => {
  const [n, k] = name.split('#')
  return `${n}()${k ? ` (overload ${k})` : ''}`
}
const list = []
const each = (d, say, where) => {
  for (const x of d.added) list.push({ text: say(x.split(T), 'added'), diagram: where(x.split(T)), mode: 'after' })
  for (const x of d.removed) list.push({ text: say(x.split(T), 'removed'), diagram: where(x.split(T)), mode: 'before' })
}
const now = (state, yes, no) => (state === 'added' ? yes : no)
each(
  ch.crates,
  ([id], s) => `${now(s, 'New', 'Removed')} crate ${c(id)}`,
  ([id]) => `crate:${id}`,
)
each(
  ch.deps,
  ([from, to], s) => `${c(from)} ${now(s, 'now depends', 'no longer depends')} on ${c(to)}`,
  ([from]) => `crate:${from}`,
)
each(
  ch.actors,
  ([crate, name], s) => `${now(s, 'New', 'Removed')} actor ${c(name)} ${now(s, 'in', 'from')} ${c(crate)}`,
  ([crate, name]) => `actor:${crate}:${name}`,
)
each(
  ch.handlers,
  ([crate, actor, msg], s) => `${c(actor)} in ${c(crate)} ${now(s, 'now handles', 'no longer handles')} ${c(msg)}`,
  ([crate, actor]) => `actor:${crate}:${actor}`,
)
each(
  ch.links,
  ([crate, actor, target, kind], s) =>
    `${c(actor)} in ${c(crate)} ${now(s, 'now holds', 'no longer holds')} ${kind === 'recipient' ? 'a recipient for' : 'the address of'} ${c(target)}`,
  ([crate, actor]) => `actor:${crate}:${actor}`,
)
each(
  ch.contracts,
  ([id], s) => `${now(s, 'New', 'Removed')} contract ${c(id)}`,
  ([id]) => `contract:${id}`,
)
each(
  ch.functions,
  ([id, fn], s) => `${c(id)}: ${now(s, 'new', 'removed')} function ${c(call(fn))}`,
  ([id]) => `contract:${id}`,
)
each(
  ch.events,
  ([id, ev], s) => `${c(id)}: ${now(s, 'new', 'removed')} event ${c(ev)}`,
  ([id]) => `contract:${id}`,
)
each(
  ch.circuits,
  ([id], s) => `${now(s, 'New', 'Removed')} circuit ${c(id)}`,
  ([id]) => `circuit:${id}`,
)

// ---- compare the diagrams ---------------------------------------------------------------------
// A box is the same when its title, lines and tab are; where it sits and the code it opens do not
// count. Most boxes have a name for an id (h:<message>, fn:<name>). A box whose id is a position
// (ev:3, kt:0) is matched by its kind and what it shows instead, so that one new event does not
// mark every event after it. An arrow is matched by its two boxes, its label and its dash. The
// After view marks what is new and what changed, the Before view what is removed and what changed.
const A = before.data.diagrams
const B = after.data.diagrams
// A read-first box has its file and line for a title: the line moves with any edit above it.
const sig = (n) =>
  JSON.stringify([n.id.startsWith('rf:') ? String(n.title ?? '').replace(/:\d+$/, '') : (n.title ?? ''), n.lines ?? [], n.tag ?? ''])
const indexed = (id) => /:\d+$/.test(id)
const match = (n) => (indexed(n.id) ? `${n.id.replace(/\d+$/, '')}${sig(n)}` : n.id)
const tally = (list, key) => list.reduce((t, x) => t.set(key(x), (t.get(key(x)) || 0) + 1), new Map())
// Each item of `list` that `other` has no unused match for. Each side has its own key function.
const unmatched = (list, key, other, otherKey = key) => {
  const left = tally(other, otherKey)
  return list.filter((x) => {
    const n = left.get(key(x)) || 0
    if (n) left.set(key(x), n - 1)
    return !n
  })
}
// `layoutOnly(id, state)` names the boxes that moved only in the layout: they get no mark.
function compare(a, b, layoutOnly = () => false) {
  const m = { after: { nodes: {}, edges: {} }, before: { nodes: {}, edges: {} } }
  if (!a || !b) {
    m.whole = a ? 'removed' : 'added'
    const side = a ? m.before : m.after
    for (const n of (a || b).nodes || []) side.nodes[n.id] = m.whole
    for (const e of (a || b).edges || []) side.edges[e.key] = m.whole
    m.own = Object.keys(side.nodes).length
    return m
  }
  const [an, bn, ae, be] = [a.nodes || [], b.nodes || [], a.edges || [], b.edges || []]
  // Ref-specific URLs differ even for identical docs; only the authored targets count as a change.
  const docs = (d) => JSON.stringify((d.documentation || []).map(({ path, title }) => [path, title]))
  m.documentation = docs(a) !== docs(b)
  for (const n of unmatched(bn, match, an)) if (!layoutOnly(n.id, 'added')) m.after.nodes[n.id] = 'added'
  for (const n of unmatched(an, match, bn)) if (!layoutOnly(n.id, 'removed')) m.before.nodes[n.id] = 'removed'
  const was = Object.fromEntries(an.map((n) => [n.id, n]))
  for (const n of bn) if (!indexed(n.id) && was[n.id] && sig(was[n.id]) !== sig(n)) m.after.nodes[n.id] = m.before.nodes[n.id] = 'changed'
  const arrow = (nodes) => {
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
    const end = (id) => (byId[id] ? match(byId[id]) : id)
    return (e) => [end(e.from), end(e.to), e.label ?? '', !!e.dashed].join(T)
  }
  const quiet = (e, state) => layoutOnly(e.from, state) || layoutOnly(e.to, state)
  for (const e of unmatched(be, arrow(bn), ae, arrow(an))) if (!quiet(e, 'added')) m.after.edges[e.key] = 'added'
  for (const e of unmatched(ae, arrow(an), be, arrow(bn))) if (!quiet(e, 'removed')) m.before.edges[e.key] = 'removed'
  // Changes of its own: marked boxes, and marked arrows between two boxes that stayed.
  const lone = (side, state, edges) =>
    edges.filter((e) => side.edges[e.key] && side.nodes[e.from] !== state && side.nodes[e.to] !== state).length
  m.own =
    Object.keys(m.after.nodes).length +
    Object.values(m.before.nodes).filter((s) => s === 'removed').length +
    lone(m.after, 'added', be) +
    lone(m.before, 'removed', ae)
  return m
}
// A crate diagram shows the first messages of each actor and puts the rest in "+N more", so a new
// message can push another one out of sight. A message box counts only when the crate gained or
// lost that message.
const messages = (S, crate) => new Set(S.handlers.filter((k) => k.split(T)[0] === crate).map((k) => evName(k.split(T)[2])))
const marks = {}
for (const id of new Set([...Object.keys(A), ...Object.keys(B)])) {
  const crate = id.startsWith('crate:') ? id.slice(6) : null
  const [had, has] = crate ? [messages(S0, crate), messages(S1, crate)] : []
  const layoutOnly = (n, state) => !!crate && n.startsWith('in:') && (state === 'added' ? had : has).has(n.slice(3))
  const m = compare(A[id], B[id], layoutOnly)
  if (m.whole || m.own || m.documentation || Object.keys(m.after.edges).length || Object.keys(m.before.edges).length) marks[id] = m
}
// The number on a box: the changes from the list in the diagram that it opens and in every diagram
// below that one, by the parent links of both versions. A change whose diagram does not exist
// counts at the top. A box whose diagrams changed with no change in the list (a fact, a hand-drawn
// arrow) gets a dot. The visited set keeps a cycle from looping.
const kids = {}
for (const d of [...Object.values(A), ...Object.values(B)]) if (d.parent) (kids[d.parent] ||= new Set()).add(d.id)
const listed = {}
for (const item of list) {
  const at = A[item.diagram] || B[item.diagram] ? item.diagram : after.data.root
  listed[at] = (listed[at] || 0) + 1
}
const below = (id, value, seen = new Set()) => {
  if (seen.has(id)) return 0
  seen.add(id)
  let n = value(id)
  for (const k of kids[id] || []) n += below(k, value, seen)
  return n
}
const counts = {}
const touched = {}
for (const id of new Set([...Object.keys(A), ...Object.keys(B)])) {
  const n = below(id, (k) => listed[k] || 0)
  if (n) counts[id] = n
  else if (below(id, (k) => (marks[k] ? 1 : 0))) touched[id] = true
}
const changes = Object.keys(marks).length
if (!list.length && !changes) {
  console.error(`blueprint diff: no architecture change from ${base.label} to ${head.label}`)
  if (opt('--md')) writeFileSync(opt('--md'), '')
  process.exit(0)
}

// ---- the page ---------------------------------------------------------------------------------
// The head's blueprint, with the before version of each diagram that changed, or whose code
// changed, and the code that those open: Before then shows the base's code too. diffview.js draws
// the marks and the switch.
const changedIds = Object.keys(marks)
const keysOf = (d) =>
  [...(d.nodes || []).map((n) => n.code), ...(d.edges || []).flatMap((e) => (e.refs || []).map((r) => r.code))].filter(Boolean)
const codeText = (d, code) => JSON.stringify(keysOf(d).map((k) => (code[k] ? code[k].lines : null)))
const codeChanged = Object.keys(A).filter(
  (id) => B[id] && !marks[id] && codeText(A[id], before.data.code) !== codeText(B[id], after.data.code),
)
const beforeIds = [...changedIds.filter((id) => marks[id].whole !== 'added'), ...codeChanged]
const codeBefore = {}
for (const id of beforeIds) for (const k of keysOf(A[id])) codeBefore[k] = before.data.code[k]
const diff = {
  base: base.label,
  head: head.label,
  before: Object.fromEntries([...changedIds, ...codeChanged].map((id) => [id, A[id] || null])),
  codeBefore,
  documentationBefore: Object.fromEntries(Object.entries(A).map(([id, d]) => [id, d.documentation || []])),
  marks,
  counts,
  touched,
  list: list.length
    ? list
    : changedIds.map((id) => ({
        text: `${(A[id] || B[id]).title}: ${marks[id].documentation && !marks[id].own ? 'documentation' : 'boxes'} changed`,
        diagram: id,
        mode: B[id] ? 'after' : 'before',
      })),
}
const page = { ...after.data, tag: `${base.label} → ${head.label}`, diff }
const extra = {
  css: readFileSync(join(HERE, 'view.css'), 'utf8'),
  js: readFileSync(join(HERE, 'view.js'), 'utf8'),
  nav: `    <span class="dlegend"><i class="a"></i>new <i class="r"></i>removed <i class="c"></i>changed</span>
    <span class="dswitch"><button id="d-before" title="The code before this change (B)">Before</button><button id="d-after" title="The code after this change (B)">After</button></span>
    <button id="d-list" title="Every change (C)">Changes</button>
`,
}
mkdirSync(OUT, { recursive: true })
const pageFile = join(OUT, 'interfold-blueprint-diff.html')
writeFileSync(pageFile, pageHtml(page, extra))

// ---- markdown ---------------------------------------------------------------------------------
if (opt('--md')) {
  const pageUrl = opt('--page-url') || relative(process.cwd(), pageFile)
  const rows = ROWS.map(([key, title, get]) => [title, new Set(get(S0)).size, new Set(get(S1)).size, ch[key]])
    .filter(([, , , d]) => d.added.length || d.removed.length)
    .map(([title, b, a, d]) => `| ${title} | ${b} | ${a} | ${d.added.length || ''} | ${d.removed.length || ''} |`)
  const top = [
    '<!-- blueprint-diff -->',
    '### Architecture change',
    '',
    `From \`${base.label}\` to \`${head.label}\`. [Open this change in the blueprint](${pageUrl}): green is new, red is removed and yellow is changed, and a number on a box counts the changes inside it.`,
    ...(before.own
      ? []
      : ['', 'The base has no `scripts/blueprint/diff/diff.mjs` of this version, so the scripts of this branch read it.']),
    '',
    ...(rows.length ? ['| | Before | After | New | Removed |', '| --- | --: | --: | --: | --: |', ...rows, ''] : []),
  ]
  const foot = [
    '',
    '<sub>Experimental. The page goes away when the pull request closes. `scripts/blueprint/diff/README.md` says how to turn it off or remove it.</sub>',
    '',
  ]
  const tail = ['', '</details>', '']
  const lines = ['<details>', `<summary>Every change (${list.length})</summary>`, '']
  let size = [...top, ...tail, ...foot].join('\n').length + 200
  let shown = 0
  for (const item of list) {
    if (size + item.text.length + 3 > MAX_CHARS) break
    lines.push(`- ${item.text}`)
    size += item.text.length + 3
    shown++
  }
  if (shown < list.length) lines.push(`- … and ${list.length - shown} more. Open the page for all of them.`)
  writeFileSync(opt('--md'), [...top, ...(list.length ? [...lines, ...tail] : []), ...foot].join('\n'))
}
console.error(`blueprint diff: ${list.length} change(s) in ${changes} diagram(s) from ${base.label} to ${head.label}`)
console.log(`Open ${relative(process.cwd(), pageFile) || pageFile} in a browser.`)
