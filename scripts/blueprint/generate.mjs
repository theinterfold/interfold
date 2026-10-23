// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Generated levels of the blueprint, built only from exact data: the inventory and wiring read
// from code, and the checked facts. One diagram per crate, contract, circuit and app, and one per
// actor. Layouts are column templates, so every generated diagram reads the same way.
export const evName = (msg) => {
  const m = msg.match(/^TypedEvent<(.+)>$/)
  return m ? m[1] : msg
}
const short = (id) => id.replace(/^e3-/, '')
export function wrap(text, max, lines = 3) {
  const words = String(text || '')
    .split(/\s+/)
    .filter(Boolean)
  const out = []
  let cur = ''
  for (const w of words) {
    if ((cur + ' ' + w).trim().length > max) {
      if (cur) out.push(cur)
      cur = w
    } else cur = (cur + ' ' + w).trim()
    if (out.length === lines) break
  }
  if (cur && out.length < lines) out.push(cur)
  if (out.length === lines && words.join(' ').length > out.join(' ').length) out[lines - 1] = out[lines - 1].replace(/[,.;:]?$/, '') + ' …'
  return out
}
const textW = (s, px) => Math.ceil(String(s).length * px)
const clip = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s))
const chipW = (title, min = 220) => Math.max(min, textW(title, 9.3) + 50)

// Parent diagram of each crate layer.
const crateParent = (u) => (u.layer === 'clients' ? 'apps' : 'ciphernode')

export function generate({ units, wiring, codeFor, windowFor }) {
  const diagrams = {}
  const add = (d) => (diagrams[d.id] = d)
  const refCode = (ref) => (ref ? { code: windowFor(ref), focus: ref.line } : null)

  for (const u of Object.values(units)) {
    let d
    if (u.kind === 'crate' && !u.app) d = crateDiagram(u)
    else if (u.kind === 'contract' && !u.app) d = contractDiagram(u)
    else if (u.kind === 'circuit' && !u.app) d = circuitDiagram(u)
    else d = appDiagram(u)
    add({ ...d, documentation: u.facts?.documentation || [] })
  }
  return diagrams

  // ---------------------------------------------------------------- crate
  function depsRow(u, y) {
    const nodes = []
    const deps = (u.deps || []).filter((d) => units[d])
    if (!deps.length) return { nodes, h: 0 }
    let x = 60
    for (const d of deps) {
      const w = chipW(short(d), 120)
      nodes.push({
        id: 'dep:' + d,
        x,
        y,
        w,
        h: 40,
        title: short(d),
        style: 'chip',
        mono: true,
        drill: `crate:${d}`,
        tip: (units[d].facts && units[d].facts.one_line) || '',
      })
      x += w + 14
    }
    return { nodes, h: 40, w: x }
  }

  function stateCards(u, y, perRow = 4) {
    const f = u.facts || {}
    const nodes = []
    ;(f.state || []).slice(0, 12).forEach((s, i) => {
      const lines = wrap(s.name, 31, 3).map((l) => clip(l, 31))
      nodes.push({
        id: 'state:' + i,
        x: 60 + (i % perRow) * 400,
        y: y + Math.floor(i / perRow) * 140,
        w: 360,
        h: 100,
        tag: (s.where || 'state').split(/[ |/]/)[0].toUpperCase(),
        title: lines[0],
        lines: lines.slice(1),
        style: 'tagged',
        ...(s.ref ? refCode(s.ref) : {}),
        tip: s.name,
      })
    })
    return { nodes, h: nodes.length ? Math.ceil(nodes.length / perRow) * 140 : 0 }
  }

  function crateDiagram(u) {
    const f = u.facts || {}
    const prod = (u.actors || []).filter((a) => !a.test)
    const id = `crate:${u.id}`
    const base = { id, kind: 'diagram', title: u.id, crumb: short(u.id), parent: crateParent(u), sub: f.one_line || '' }
    if (!prod.length) return libraryDiagram(u, base)
    const nodes = []
    const edges = []
    const groups = []
    const deps = depsRow(u, 70)
    if (deps.nodes.length) groups.push({ x: 40, y: 20, w: Math.max(deps.w, 400), h: 108, label: 'Depends on' })
    nodes.push(...deps.nodes)
    let y = deps.nodes.length ? 200 : 60
    const IN_X = 60
    const ACT_X = 640
    const ACT_W = 440
    const OUT_X = 1260
    const actorBox = {}
    const roles = Object.fromEntries((f.actors || []).map((a) => [a.name, a.role]))
    const emitsBy = {}
    for (const e of f.emits || []) {
      const by = String(e.by || '').split(/[ ,]/)[0]
      ;(emitsBy[by] ||= []).push(e)
    }
    const inChips = {}
    for (const a of prod) {
      const hs = (u.handlers || []).filter((h) => h.actor === a.name && !h.test)
      const msgs = []
      for (const h of hs) {
        const name = evName(h.msg)
        if (!msgs.some((m) => m.name === name)) msgs.push({ name, ref: h.ref })
      }
      const shown = msgs.slice(0, msgs.length > 8 ? 7 : 8)
      const outs = (emitsBy[a.name] || []).slice(0, 6)
      const sends = (wiring.actors[u.id] && wiring.actors[u.id][a.name] && wiring.actors[u.id][a.name].sends) || []
      const extTargets = [...new Map(sends.filter((s) => !prod.some((p) => p.name === s.target)).map((s) => [s.target, s])).values()]
      const rows = Math.max(3, shown.length + (msgs.length > shown.length ? 1 : 0), outs.length + extTargets.length)
      const bandH = rows * 52
      const role = wrap(roles[a.name] || '', 46, 2)
      const inCrate = [...new Set(sends.filter((s) => prod.some((p) => p.name === s.target)).map((s) => s.target))]
      const sendLine = inCrate.length ? [clip(`sends to ${inCrate.join(', ')}`, 50)] : []
      const box = {
        id: 'actor:' + a.name,
        x: ACT_X,
        y: y + Math.max(0, bandH / 2 - 76),
        w: ACT_W,
        h: 152,
        title: a.name,
        mono: true,
        lines: [...role, ...sendLine, `${hs.length} handlers · ${sends.length} direct sends`],
        drill: `actor:${u.id}:${a.name}`,
        tip: roles[a.name] || 'Actor',
      }
      actorBox[a.name] = box
      nodes.push(box)
      shown.forEach((m, i) => {
        const cid = 'in:' + m.name
        if (!inChips[cid]) {
          inChips[cid] = {
            id: cid,
            x: IN_X,
            y: y + i * 52,
            w: 420,
            h: 40,
            title: clip(m.name, 38),
            style: 'chip',
            mono: true,
            ...(m.ref ? { code: codeFor.handler(m.ref) || windowFor(m.ref), focus: m.ref.line } : {}),
            tip:
              m.name === 'InterfoldEvent'
                ? 'The envelope of every event: this actor receives events and picks the ones it needs.'
                : `Handled by ${a.name}`,
          }
          nodes.push(inChips[cid])
        }
        edges.push({
          from: cid,
          to: box.id,
          fs: 'r',
          ts: 'l',
          ta: shown.length > 1 ? 0.15 + (0.7 * i) / (shown.length - 1) : 0.5,
          refs: m.ref ? [{ code: codeFor.handler(m.ref) || windowFor(m.ref), focus: m.ref.line }] : [],
        })
      })
      if (msgs.length > shown.length) {
        const more = {
          id: 'more:' + a.name,
          x: IN_X,
          y: y + shown.length * 52,
          w: 420,
          h: 40,
          title: `+${msgs.length - shown.length} more messages`,
          style: 'ghost',
          drill: `actor:${u.id}:${a.name}`,
          tip: 'Open the actor to see every message it handles',
        }
        nodes.push(more)
        edges.push({ from: more.id, to: box.id, fs: 'r', ts: 'l', ta: 0.9, dashed: true })
      }
      outs.forEach((e, i) => {
        const cid = `out:${a.name}:${e.name}`
        const w = chipW(e.name, 300)
        nodes.push({
          id: cid,
          x: OUT_X,
          y: y + i * 52,
          w,
          h: 40,
          title: e.name,
          style: 'chip',
          mono: true,
          ...(e.ref ? refCode(e.ref) : {}),
          tip: `Published by ${a.name} (from the facts; the link shows the line)`,
        })
        edges.push({
          from: box.id,
          to: cid,
          fs: 'r',
          ts: 'l',
          fa: outs.length + extTargets.length > 1 ? 0.15 + (0.7 * i) / Math.max(1, outs.length + extTargets.length - 1) : 0.5,
          refs: e.ref ? [refCode(e.ref)] : [],
        })
      })
      extTargets.forEach((s, i) => {
        const k = outs.length + i
        const cid = `send:${a.name}:${s.target}`
        nodes.push({
          id: cid,
          x: OUT_X,
          y: y + k * 52,
          w: chipW(s.target, 300),
          h: 40,
          title: s.target,
          style: 'chip',
          mono: true,
          tip: `${a.name} sends straight to it (self.${s.field}.${s.method})`,
        })
        edges.push({
          from: box.id,
          to: cid,
          fs: 'r',
          ts: 'l',
          dashed: true,
          label: `${s.field}.${s.method}`,
          fa: 0.15 + (0.7 * k) / Math.max(1, outs.length + extTargets.length - 1),
          refs: [refCode(s.ref)],
        })
      })
      y += bandH + 50
    }
    // Sends between actors of this crate are listed inside each actor box; the actor's own
    // diagram draws them with their code.
    const st = stateCards(u, y + 46)
    nodes.push(...st.nodes)
    if (st.nodes.length) groups.push({ x: 40, y: y - 10, w: 1640, h: st.h + 76, label: 'State it keeps' })
    const h = y + st.h + 80
    // The two column headers are labels only: draw them as notes, not boxes.
    const notes = [
      { x: IN_X, y: (deps.nodes.length ? 200 : 60) - 22, text: 'Messages it handles', cls: 'big' },
      { x: OUT_X, y: (deps.nodes.length ? 200 : 60) - 22, text: 'Publishes, or sends to', cls: 'big' },
    ]
    return { ...base, w: 1700, h, nodes, edges, groups, notes }
  }

  function libraryDiagram(u, base) {
    const f = u.facts || {}
    const nodes = []
    const edges = []
    const groups = []
    const one = wrap(f.one_line || '', 44, 3)
    const center = {
      id: 'self',
      x: 640,
      y: 120,
      w: 440,
      h: 150,
      title: u.id,
      mono: true,
      lines: one,
      tip: f.one_line || '',
      ...(f.read_first && f.read_first[0] && f.read_first[0].ref ? refCode(f.read_first[0].ref) : {}),
    }
    nodes.push(center)
    const users = (u.usedBy || []).filter((d) => units[d]).slice(0, 12)
    users.forEach((d, i) => {
      nodes.push({
        id: 'user:' + d,
        x: 60,
        y: 40 + i * 52,
        w: 300,
        h: 40,
        title: short(d),
        style: 'chip',
        mono: true,
        drill: `crate:${d}`,
        tip: (units[d].facts && units[d].facts.one_line) || '',
      })
      edges.push({ from: 'user:' + d, to: 'self', fs: 'r', ts: 'l', ta: users.length > 1 ? 0.1 + (0.8 * i) / (users.length - 1) : 0.5 })
    })
    const deps = (u.deps || []).filter((d) => units[d])
    deps.forEach((d, i) => {
      nodes.push({
        id: 'dep:' + d,
        x: 1340,
        y: 40 + i * 52,
        w: 300,
        h: 40,
        title: short(d),
        style: 'chip',
        mono: true,
        drill: `crate:${d}`,
        tip: (units[d].facts && units[d].facts.one_line) || '',
      })
      edges.push({ from: 'self', to: 'dep:' + d, fs: 'r', ts: 'l', fa: deps.length > 1 ? 0.1 + (0.8 * i) / (deps.length - 1) : 0.5 })
    })
    const notes = []
    if (users.length) notes.push({ x: 60, y: 24, text: 'Used by', cls: 'big' })
    if (deps.length) notes.push({ x: 1340, y: 24, text: 'Depends on', cls: 'big' })
    let y = Math.max(320, 60 + Math.max(users.length, deps.length) * 52 + 40)
    const kt = (f.key_types || []).slice(0, 12)
    if (kt.length) {
      groups.push({ x: 40, y, w: 1620, h: Math.ceil(kt.length / 3) * 110 + 60, label: 'Key types' })
      kt.forEach((t, i) => {
        const lines = wrap(t.what, 44, 2)
        nodes.push({
          id: 'kt:' + i,
          x: 70 + (i % 3) * 530,
          y: y + 50 + Math.floor(i / 3) * 110,
          w: 500,
          h: 86,
          title: t.name,
          mono: true,
          lines,
          ...(t.ref ? refCode(t.ref) : {}),
          tip: t.what,
        })
      })
      y += Math.ceil(kt.length / 3) * 110 + 100
    }
    const st = stateCards(u, y + 56)
    if (st.nodes.length) {
      groups.push({ x: 40, y, w: 1620, h: st.h + 76, label: 'State it keeps' })
      nodes.push(...st.nodes)
      y += st.h + 100
    }
    return { ...base, w: 1700, h: y + 20, nodes, edges, groups, notes }
  }

  // ---------------------------------------------------------------- contract
  function contractDiagram(u) {
    const f = u.facts || {}
    const nodes = []
    const groups = []
    const id = `contract:${u.id}`
    const fnName = (s) =>
      String(s || '')
        .split('(')[0]
        .trim()
    // Group the state-changing functions by who calls them (from the facts); the rest are listed
    // under "Other functions". Groups fill three columns, shortest column first.
    const byCaller = new Map()
    const placed = new Set()
    for (const c of f.consumes || []) {
      const by =
        String(c.by || 'anyone')
          .split(/[,(]/)[0]
          .trim() || 'anyone'
      const name = fnName(c.name)
      const fi = (u.functions || []).findIndex((fn, i) => fn.name === name && !placed.has(i))
      if (fi < 0) continue
      placed.add(fi)
      if (!byCaller.has(by)) byCaller.set(by, [])
      byCaller.get(by).push(fi)
    }
    const rest = (u.functions || []).map((_, i) => i).filter((i) => !placed.has(i))
    const sections = [...byCaller.entries()].map(([by, list]) => ({ label: `Called by ${by}`, list }))
    const restLabel = byCaller.size ? 'Other functions' : 'Functions that change state'
    for (let i = 0; i < rest.length; i += 10)
      sections.push({
        label: rest.length > 10 ? `${restLabel} (${i / 10 + 1}/${Math.ceil(rest.length / 10)})` : restLabel,
        list: rest.slice(i, i + 10),
      })
    const COLS = 3
    const COLW = 520
    const colY = Array(COLS).fill(30)
    for (const sec of sections) {
      const c = colY.indexOf(Math.min(...colY))
      const x = 40 + c * (COLW + 30)
      const y = colY[c]
      groups.push({ x, y, w: COLW, h: sec.list.length * 50 + 66, label: `${sec.label} · ${sec.list.length}` })
      sec.list.forEach((fi, k) => {
        const fn = u.functions[fi]
        const dup = u.functions.slice(0, fi).filter((x) => x.name === fn.name).length
        nodes.push({
          id: dup ? `fn:${fn.name}#${dup + 1}` : `fn:${fn.name}`,
          x: x + 24,
          y: y + 48 + k * 50,
          w: COLW - 48,
          h: 38,
          title: clip(fn.name + '()', 44),
          style: 'chip',
          mono: true,
          code: codeFor.contract(fn.ref),
          focus: fn.ref ? fn.ref.line : null,
          tip: `${fn.name}(): click to read it`,
        })
      })
      colY[c] += sec.list.length * 50 + 96
    }
    let y = Math.max(...colY) + 10
    const evs = [...(u.events || [])]
    for (const e of f.emits || [])
      if (!evs.some((x) => x.name === fnName(e.name))) evs.push({ name: fnName(e.name), ref: e.ref, iface: true })
    if (evs.length) {
      const rows = Math.ceil(Math.min(evs.length, 24) / 3)
      groups.push({ x: 40, y, w: 1620, h: rows * 50 + 70, label: `Events · ${evs.length}` })
      evs.slice(0, 24).forEach((e, i) =>
        nodes.push({
          id: 'ev:' + i,
          x: 64 + (i % 3) * 530,
          y: y + 50 + Math.floor(i / 3) * 50,
          w: 500,
          h: 38,
          title: clip(e.name, 44),
          style: 'chip',
          mono: true,
          ...(e.ref ? refCode(e.ref) : {}),
          tip: e.iface ? 'Event this contract emits (declared in its interface)' : 'Event declared in this contract',
        }),
      )
      y += rows * 50 + 100
    }
    const calls = (f.depends_on || []).filter((d) => units[d] && units[d].kind === 'contract')
    if (calls.length) {
      groups.push({ x: 40, y, w: 1620, h: 110, label: 'Calls or reads' })
      let x = 70
      for (const d of calls) {
        const w = chipW(d, 200)
        nodes.push({
          id: 'calls:' + d,
          x,
          y: y + 50,
          w,
          h: 40,
          title: d,
          style: 'chip',
          mono: true,
          drill: `contract:${d}`,
          tip: (units[d].facts && units[d].facts.one_line) || '',
        })
        x += w + 16
      }
      y += 140
    }
    const st = stateCards(u, y + 56)
    if (st.nodes.length) {
      groups.push({ x: 40, y, w: 1620, h: st.h + 76, label: 'Storage' })
      nodes.push(...st.nodes)
      y += st.h + 100
    }
    const notes = byCaller.size
      ? [{ x: 40, y: y + 16, text: 'Who calls each function comes from the extraction facts. Open a function to read its own checks.' }]
      : []
    return {
      id,
      kind: 'diagram',
      title: u.id,
      crumb: u.id,
      parent: 'contracts',
      sub: f.one_line || '',
      w: 1700,
      h: y + 40,
      nodes,
      edges: [],
      groups,
      notes,
    }
  }

  // ---------------------------------------------------------------- circuit
  function circuitDiagram(u) {
    const f = u.facts || {}
    const nodes = []
    const edges = []
    const groups = []
    const pub = (f.consumes || []).filter((c) => /^public/i.test(c.name))
    const priv = (f.consumes || []).filter((c) => /^private/i.test(c.name))
    const strip = (s) => s.replace(/^(public|private)\s*:\s*/i, '')
    let y = 70
    const col = (list, label) => {
      if (!list.length) return
      groups.push({ x: 40, y: y - 50, w: 460, h: list.length * 50 + 70, label })
      list.forEach((c, i) => {
        nodes.push({
          id: `${label}:${i}`,
          x: 70,
          y: y + i * 50,
          w: 400,
          h: 38,
          title: strip(c.name),
          style: 'chip',
          mono: true,
          ...(c.ref ? refCode(c.ref) : {}),
          tip: c.by ? `Used in ${c.by}` : label,
        })
        edges.push({ from: `${label}:${i}`, to: 'self', fs: 'r', ts: 'l' })
      })
      y += list.length * 50 + 90
    }
    col(pub, 'Public inputs')
    col(priv, 'Private inputs')
    const one = wrap(f.one_line || '', 42, 4)
    const self = {
      id: 'self',
      x: 640,
      y: 120,
      w: 440,
      h: 170,
      title: u.id,
      mono: true,
      lines: one,
      ...(codeFor.circuit(u.id) ? { code: codeFor.circuit(u.id), focus: u.main ? u.main.line : null } : {}),
      tip: 'Click to read the circuit',
    }
    nodes.push(self)
    const h = Math.max(y, 340)
    return {
      id: `circuit:${u.id}`,
      kind: 'diagram',
      title: u.id,
      crumb: u.id,
      parent: 'circuits',
      sub: f.one_line || '',
      w: 1180,
      h,
      nodes,
      edges,
      groups,
    }
  }

  // ---------------------------------------------------------------- app
  function appDiagram(u) {
    const f = u.facts || {}
    const nodes = []
    const edges = []
    const groups = []
    const self = {
      id: 'self',
      x: 60,
      y: 120,
      w: 460,
      h: 190,
      title: u.id,
      mono: true,
      lines: wrap(f.one_line || '', 46, 5),
      tip: f.one_line || '',
    }
    nodes.push(self)
    const rf = f.read_first || []
    rf.forEach((r, i) => {
      const t = r.ref ? `${r.ref.path.split('/').slice(-2).join('/')}:${r.ref.line}` : 'code'
      nodes.push({
        id: 'rf:' + i,
        x: 640,
        y: 70 + i * 96,
        w: 600,
        h: 80,
        title: t,
        mono: true,
        lines: wrap(r.why, 62, 2),
        ...(r.ref ? refCode(r.ref) : {}),
        tip: r.why,
      })
      edges.push({ from: 'self', to: 'rf:' + i, fs: 'r', ts: 'l', fa: rf.length > 1 ? 0.15 + (0.7 * i) / (rf.length - 1) : 0.5 })
    })
    if (rf.length) groups.push({ x: 610, y: 20, w: 660, h: rf.length * 96 + 70, label: 'Read this first' })
    let y = Math.max(340, rf.length * 96 + 120)
    const kt = (f.key_types || []).slice(0, 9)
    if (kt.length) {
      groups.push({ x: 40, y, w: 1620, h: Math.ceil(kt.length / 3) * 110 + 60, label: 'Key types' })
      kt.forEach((t, i) =>
        nodes.push({
          id: 'kt:' + i,
          x: 70 + (i % 3) * 530,
          y: y + 50 + Math.floor(i / 3) * 110,
          w: 500,
          h: 86,
          title: t.name,
          mono: true,
          lines: wrap(t.what, 44, 2),
          ...(t.ref ? refCode(t.ref) : {}),
          tip: t.what,
        }),
      )
      y += Math.ceil(kt.length / 3) * 110 + 100
    }
    const st = stateCards(u, y + 56)
    if (st.nodes.length) {
      groups.push({ x: 40, y, w: 1620, h: st.h + 76, label: 'State it keeps' })
      nodes.push(...st.nodes)
      y += st.h + 100
    }
    const id = u.kind === 'crate' ? `crate:${u.id}` : `app:${u.id}`
    return {
      id,
      kind: 'diagram',
      title: u.id,
      crumb: short(u.id),
      parent: 'apps',
      sub: f.one_line || '',
      w: 1700,
      h: y + 20,
      nodes,
      edges,
      groups,
    }
  }
}

// One diagram per production actor: every message it handles, what it publishes or sends, and
// the fields that hold other actors.
export function actorDiagrams({ units, wiring, codeFor, windowFor }) {
  const out = {}
  for (const u of Object.values(units)) {
    if (u.kind !== 'crate') continue
    const f = u.facts || {}
    const roles = Object.fromEntries((f.actors || []).map((a) => [a.name, a.role]))
    for (const a of (u.actors || []).filter((a) => !a.test)) {
      const w = (wiring.actors[u.id] || {})[a.name] || { fields: [], sends: [], code: null }
      const nodes = []
      const edges = []
      const groups = []
      const hs = (u.handlers || []).filter((h) => h.actor === a.name && !h.test)
      hs.forEach((h, i) => {
        const nm = evName(h.msg)
        nodes.push({
          id: 'h:' + h.msg,
          x: 60,
          y: 70 + i * 50,
          w: 420,
          h: 38,
          title: clip(nm, 38),
          style: 'chip',
          mono: true,
          code: codeFor.handler(h.ref) || windowFor(h.ref),
          focus: h.ref ? h.ref.line : null,
          tip: `impl Handler<${h.msg}> for ${a.name}`,
        })
        edges.push({ from: 'h:' + h.msg, to: 'self', fs: 'r', ts: 'l', ta: hs.length > 1 ? 0.08 + (0.84 * i) / (hs.length - 1) : 0.5 })
      })
      if (hs.length) groups.push({ x: 30, y: 20, w: 480, h: hs.length * 50 + 70, label: `Handlers (${hs.length})` })
      const role = wrap(roles[a.name] || '', 44, 3)
      const selfH = Math.max(160, Math.min(hs.length * 50, 600))
      const selfY = 70 + Math.max(0, (hs.length * 50 - selfH) / 2)
      nodes.push({
        id: 'self',
        x: 640,
        y: selfY,
        w: 420,
        h: selfH,
        title: a.name,
        mono: true,
        lines: [u.id, ...role],
        ...(w.code ? { code: w.code } : a.ref ? { code: windowFor(a.ref), focus: a.ref.line } : {}),
        tip: 'Click to read the actor struct',
      })
      const outs = (f.emits || []).filter((e) => String(e.by || '').split(/[ ,]/)[0] === a.name)
      const sends = [...new Map(w.sends.map((s) => [s.target + s.field, s])).values()]
      let k = 0
      outs.forEach((e) => {
        nodes.push({
          id: 'o:' + e.name,
          x: 1200,
          y: 70 + k * 50,
          w: 440,
          h: 38,
          title: clip(e.name, 40),
          style: 'chip',
          mono: true,
          ...(e.ref ? { code: windowFor(e.ref), focus: e.ref.line } : {}),
          tip: `${e.name}: published (from the facts; the link shows the line)`,
        })
        edges.push({
          from: 'self',
          to: 'o:' + e.name,
          fs: 'r',
          ts: 'l',
          fa: 0.5,
          refs: e.ref ? [{ code: windowFor(e.ref), focus: e.ref.line }] : [],
        })
        k++
      })
      sends.forEach((s) => {
        const ref = s.ref
        nodes.push({
          id: `s:${s.target}:${s.field}`,
          x: 1200,
          y: 70 + k * 50,
          w: 440,
          h: 38,
          title: clip(s.target, 40),
          style: 'chip',
          mono: true,
          tip: `Direct message to ${s.target}: self.${s.field}.${s.method}(…)`,
        })
        edges.push({
          from: 'self',
          to: `s:${s.target}:${s.field}`,
          fs: 'r',
          ts: 'l',
          dashed: true,
          label: `${s.field}.${s.method}`,
          refs: [{ code: windowFor(ref), focus: ref.line }],
        })
        k++
      })
      if (k) groups.push({ x: 1170, y: 20, w: 500, h: k * 50 + 70, label: 'Publishes, or sends to' })
      let y = Math.max(hs.length * 50 + 120, selfY + selfH + 60, k * 50 + 120)
      if (w.fields.length) {
        groups.push({ x: 30, y, w: 1640, h: Math.ceil(w.fields.length / 2) * 70 + 70, label: 'Fields that hold other actors' })
        w.fields.forEach((fl, i) => {
          const t = `${fl.name}: ${fl.kind === 'addr' ? `Addr<${fl.target}>` : `Recipient<${fl.target}>`}`
          nodes.push({
            id: 'f:' + i,
            x: 60 + (i % 2) * 810,
            y: y + 50 + Math.floor(i / 2) * 70,
            w: 780,
            h: 46,
            title: clip(t, 76),
            style: 'chip',
            mono: true,
            code: windowFor(fl.ref),
            focus: fl.ref.line,
            tip: t,
          })
        })
        y += Math.ceil(w.fields.length / 2) * 70 + 90
      }
      out[`actor:${u.id}:${a.name}`] = {
        id: `actor:${u.id}:${a.name}`,
        kind: 'diagram',
        title: a.name,
        crumb: a.name,
        parent: `crate:${u.id}`,
        sub: roles[a.name] || `An actor in ${u.id}`,
        documentation: f.documentation || [],
        w: 1700,
        h: y + 10,
        nodes,
        edges,
        groups,
      }
    }
  }
  return out
}
