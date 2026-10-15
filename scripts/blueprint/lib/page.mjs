// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The blueprint page: its data (the generated diagrams, the hand-drawn ones from curated.mjs, and
// the code that they open) and its HTML. build.mjs writes the page. diff.mjs reads the data of two
// versions of the code.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { loadData, checkRef, softRef, inTestCode, fileLines, BLUEPRINT, ROOT } from './data.mjs'
import { MISSING } from './inventory.mjs'
import { wiring as readWiring } from './wiring.mjs'
import { generate, actorDiagrams } from '../generate.mjs'
import { CURATED } from '../curated.mjs'
import { checkoutRef, documentationURL } from './documentation.mjs'

// Code drift does not stop the build: it uses the new line of a moved reference, drops a broken
// one, and returns a warning for each. `draft` allows hand-drawn edges without references.
export function buildData({ draft = false, sourceRef = process.env.BLUEPRINT_SOURCE_REF || checkoutRef(ROOT) } = {}) {
  const { inv, units, report } = loadData()
  const raw = readWiring(inv)

  // ---- code store ----------------------------------------------------------------------------
  const code = { ...raw.code }
  const rawKey = (r) => `${r.path}@${r.line}@${r.token}`
  function windowFor(ref, span = 9) {
    if (!ref) return null
    const L = fileLines(ref.path)
    if (!L) return null
    const start = Math.max(1, ref.line - span)
    const end = Math.min(L.length, ref.line + span)
    const key = `${ref.path}:${start}`
    if (!code[key]) code[key] = { path: ref.path, start, lines: L.slice(start - 1, end), more: 0 }
    return key
  }
  const codeFor = {
    handler: (ref) => (ref ? raw.handlerCode[rawKey(ref)] || null : null),
    contract: (ref) => (ref ? raw.contractCode[rawKey(ref)] || null : null),
    circuit: (id) => raw.circuitCode[id] || null,
  }
  // Wiring references are strings; check them like every other reference.
  const asObj = (s) => {
    const c = checkRef(s)
    if (c.status === 'bad') throw new Error(`wiring reference does not check: ${s}`)
    return { path: c.path, line: c.line, token: c.token }
  }
  const wiring = { ...raw, actors: {} }
  for (const [crate, as] of Object.entries(raw.actors)) {
    wiring.actors[crate] = {}
    for (const [name, a] of Object.entries(as)) {
      wiring.actors[crate][name] = {
        ...a,
        fields: a.fields.map((f) => ({ ...f, ref: asObj(f.ref) })),
        sends: a.sends.map((s) => ({ ...s, ref: asObj(s.ref) })),
      }
    }
  }

  // ---- diagrams ------------------------------------------------------------------------------
  const diagrams = { ...generate({ units, wiring, codeFor, windowFor }), ...actorDiagrams({ units, wiring, codeFor, windowFor }) }
  let curatedRefs = 0
  let missing = 0
  const testRefs = []
  // Code drift does not stop the build: each problem becomes a warning, and check.mjs lists them.
  const warnings = [
    ...MISSING.map((p) => `${p} is on the map (lib/inventory.mjs) but no longer exists, so the build skipped it`),
    ...report.bad.map((r) => `facts/${r.file}, ${r.unit}: ${r.raw} is broken (${r.why}), so the build dropped that fact`),
    ...report.moved.map((r) => `facts/${r.file}, ${r.unit}: ${r.path} line ${r.was} moved to ${r.line}`),
    ...report.unmatched.map((u) => `facts/${u.file}: ${u.id} matches no unit on the map, so the build skipped it`),
    ...report.documentation.map((d) => `facts/${d.file}, ${d.unit}: ${d.why}`),
  ]
  for (const make of CURATED) {
    const d = make({ units, tag: inv.tag })
    for (const n of d.nodes) {
      if (n.ref) {
        const r = softRef(n.ref, `${d.id} diagram, box ${n.id}`, warnings)
        if (r) {
          n.code = windowFor(r)
          n.focus = r.line
          curatedRefs++
        }
        delete n.ref
      }
      if (n.drill && !n.drill.includes(':') && !CURATED.some((m) => m.id === n.drill)) {
        if (!draft) throw new Error(`${d.id}: node ${n.id} opens ${n.drill}, which does not exist`)
        delete n.drill
      }
    }
    for (const e of d.edges) {
      if (!e.refs || !e.refs.length) {
        if (e.optional) continue
        missing++
        if (!draft) throw new Error(`${d.id}: edge ${e.from} -> ${e.to} (${e.label || ''}) has no code reference`)
        continue
      }
      e.refs = e.refs
        .map((s) => {
          const r = softRef(s, `${d.id} diagram, arrow ${e.from} -> ${e.to}`, warnings)
          if (!r) return null
          if (inTestCode(r.path, r.line)) testRefs.push(`${d.id} edge ${e.from} -> ${e.to}: ${r.path}:${r.line}`)
          curatedRefs++
          return { code: windowFor(r), focus: r.line }
        })
        .filter(Boolean)
    }
    diagrams[d.id] = d
  }
  // Every edge gets a stable key, `from>to` (with `#2` for a second edge between the same boxes).
  for (const d of Object.values(diagrams)) {
    const seen = {}
    for (const e of d.edges || []) {
      const k = `${e.from}>${e.to}`
      seen[k] = (seen[k] || 0) + 1
      e.key = seen[k] > 1 ? `${k}#${seen[k]}` : k
    }
  }

  // Every drill target must exist.
  for (const d of Object.values(diagrams))
    for (const n of d.nodes || [])
      if (n.drill && !diagrams[n.drill]) {
        warnings.push(`${d.id} diagram, box ${n.id}: opens ${n.drill}, which no longer exists, so the box opens nothing`)
        delete n.drill
      }

  const repository = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).repository?.url
  let unlinkedDocumentation = false
  for (const d of Object.values(diagrams))
    d.documentation = (d.documentation || []).map((doc) => {
      const href = documentationURL(repository, sourceRef, doc.path)
      if (!href) unlinkedDocumentation = true
      return { ...doc, href }
    })
  if (unlinkedDocumentation)
    warnings.push('Documentation links need a GitHub repository URL and source ref; for an exported tree set BLUEPRINT_SOURCE_REF')
  const data = { root: 'system', root_dir: ROOT, tag: inv.tag, diagrams, code }
  return { data, warnings, testRefs, curatedRefs, missing }
}

// The page around the data. `extra` adds styles, header buttons and a script after the renderer.
export function pageHtml(data, extra = {}) {
  const css = readFileSync(join(BLUEPRINT, 'blueprint.css'), 'utf8')
  const js = readFileSync(join(BLUEPRINT, 'renderer.js'), 'utf8')
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Interfold ${data.tag} · blueprint</title>
<style>${css}${extra.css || ''}</style>
</head>
<body data-theme="light">
<header id="bar">
  <div class="brand">Interfold <span>${data.tag} · blueprint</span></div>
  <div id="crumbs"></div>
  <div class="search"><input id="q" type="search" placeholder="Find a box…  ( / )" autocomplete="off" spellcheck="false"><div id="results" hidden></div></div>
  <nav>
${extra.nav || ''}    <button id="up" title="Up one level (Esc)">Up</button>
    <button id="fit" title="Fit (0)">Fit</button>
    <button id="theme" title="Light or dark (T)">Theme</button>
  </nav>
</header>
<main id="stage">
  <div id="head"><div id="dtitle"></div><div id="dsub"></div><div id="documentation"></div></div>
  <svg id="canvas" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Architecture diagram"></svg>
  <div id="tip" hidden></div>
  <aside id="code" hidden></aside>
  <div id="help">Boxes with ⧉ open the diagram inside · boxes with &lt;/&gt; and arrows open the code · Esc goes up · scroll to zoom, drag to pan</div>
</main>
<script>window.BLUEPRINT = ${JSON.stringify(data).replace(/</g, '\\u003c')};</script>
<script>${js}</script>
${extra.js ? `<script>${extra.js}</script>\n` : ''}</body>
</html>
`
}
