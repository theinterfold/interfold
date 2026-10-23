// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// The change view of the blueprint, on the page that diff.mjs builds. It colours the boxes and
// arrows that changed, puts the number of changes inside on each box that opens a diagram, switches
// between the code before and after the change (B), and lists every change (C). It works through
// the renderer's API, window.blueprint, so it loads after renderer.js.
;(() => {
  const B = window.BLUEPRINT
  const X = B.diff
  const bp = window.blueprint
  const D = B.diagrams
  const NS = 'http://www.w3.org/2000/svg'
  const esc = (s) =>
    String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  const code = (s) => esc(s).replace(/`([^`]*)`/g, '<code>$1</code>')
  const afterCode = B.code
  const afterDocumentation = Object.fromEntries(Object.entries(D).map(([id, d]) => [id, d.documentation || []]))
  // The after version of each diagram that changed, or null when the change removed it.
  const afterOf = Object.fromEntries(Object.keys(X.before).map((id) => [id, D[id] || null]))
  let mode = 'after'

  function setMode(m) {
    mode = m
    for (const id of Object.keys(X.before)) {
      const d = m === 'before' ? X.before[id] : afterOf[id]
      if (d) D[id] = d
      else delete D[id]
    }
    B.code = m === 'before' ? { ...afterCode, ...X.codeBefore } : afterCode
    // Even an unchanged diagram must link to the source version selected by Before/After.
    for (const [id, d] of Object.entries(D)) d.documentation = (m === 'before' ? X.documentationBefore : afterDocumentation)?.[id] || []
    document.body.dataset.diff = m
    for (const b of document.querySelectorAll('.dswitch button')) b.setAttribute('aria-pressed', String(b.id === `d-${m}`))
  }
  // Show diagram `id` in mode `m`. A diagram that does not exist in that mode falls back to its
  // nearest parent that does.
  function show(id, m = mode) {
    setMode(m)
    let target = id
    while (target && !D[target]) target = (X.before[target] || afterOf[target] || {}).parent
    bp.go(target && D[target] ? target : B.root, { push: false })
  }

  // ---- marks ---------------------------------------------------------------------------------
  // Each diagram has marks for each view: After has what is new and what changed, Before what is
  // removed and what changed.
  function arrows(svg) {
    const defs = svg.querySelector('defs')
    const base = defs && defs.querySelector('#arrow')
    if (!base) return
    for (const s of ['added', 'removed', 'changed']) {
      if (defs.querySelector(`#arrow-d-${s}`)) continue
      const m = base.cloneNode(true)
      m.id = `arrow-d-${s}`
      m.querySelector('path').setAttribute('class', `arrowhead d-${s}`)
      defs.appendChild(m)
    }
  }
  // A number, or a dot when the diagrams inside changed with no change in the list.
  function badge(g, n, count) {
    const label = count ? String(count) : ''
    const w = count ? 16 + label.length * 9 : 14
    const x = n.x + n.w - w - 30
    const y = n.y - 12
    const b = document.createElementNS(NS, 'g')
    b.setAttribute('class', 'dbadge')
    const tip = count ? `${count} change${count > 1 ? 's' : ''} inside` : 'Changed inside'
    const h = count ? 24 : 14
    b.innerHTML = `<title>${tip}</title><rect x="${x}" y="${y + (24 - h) / 2}" width="${w}" height="${h}" rx="${h / 2}"></rect><text x="${x + w / 2}" y="${y + 17}" text-anchor="middle">${label}</text>`
    g.appendChild(b)
  }
  function decorate(d) {
    const svg = bp.svg
    const m = X.marks[d.id]
    const side = m ? m[mode] : { nodes: {}, edges: {} }
    arrows(svg)
    for (const g of svg.querySelectorAll('.node[data-id]')) {
      const s = side.nodes[g.dataset.id]
      if (s) g.classList.add(`d-${s}`)
    }
    for (const g of svg.querySelectorAll('.edge[data-key], .elabel[data-key]')) {
      const s = side.edges[g.dataset.key]
      if (!s) continue
      g.classList.add(`d-${s}`)
      const line = g.querySelector('.line')
      if (line && line.getAttribute('marker-end')) line.setAttribute('marker-end', `url(#arrow-d-${s})`)
    }
    for (const n of d.nodes || []) {
      const count = n.drill ? X.counts[n.drill] || 0 : 0
      if (!count && !(n.drill && X.touched[n.drill])) continue
      const g = svg.querySelector(`.node[data-id="${CSS.escape(n.id)}"]`)
      if (g && !g.querySelector('.dbadge')) badge(g, n, count)
    }
    if (m && m.whole)
      document.getElementById('dsub').textContent =
        `${m.whole === 'added' ? 'New in this change' : 'Removed by this change'}. ${d.sub || ''}`
  }

  // ---- the list of changes -------------------------------------------------------------------
  const stage = document.getElementById('stage')
  const panel = document.createElement('div')
  panel.id = 'dchanges'
  panel.hidden = true
  panel.innerHTML =
    `<header><b>${X.list.length} change${X.list.length === 1 ? '' : 's'}</b><span>${esc(X.base)} → ${esc(X.head)}</span></header>` +
    X.list
      .map((c, i) => `<div class="dc" data-i="${i}"><i class="${c.mode === 'before' ? 'r' : 'a'}"></i><span>${code(c.text)}</span></div>`)
      .join('')
  stage.appendChild(panel)
  panel.addEventListener('click', (e) => {
    const row = e.target.closest('.dc')
    if (!row) return
    const c = X.list[Number(row.dataset.i)]
    panel.hidden = true
    show(c.diagram, c.mode)
  })
  const list = document.getElementById('d-list')
  if (list) {
    list.textContent = `Changes (${X.list.length})`
    list.onclick = () => (panel.hidden = !panel.hidden)
  }
  for (const m of ['before', 'after']) {
    const b = document.getElementById(`d-${m}`)
    if (b) b.onclick = () => show(bp.current.id, m)
  }
  bp.onKey = (e) => {
    if (e.key === 'b' || e.key === 'B') show(bp.current.id, mode === 'after' ? 'before' : 'after')
    else if (e.key === 'c' || e.key === 'C') panel.hidden = !panel.hidden
    else if (e.key === 'Escape' && !panel.hidden) panel.hidden = true
    else return false
    return true
  }

  // ---- start ---------------------------------------------------------------------------------
  bp.hooks.push(decorate)
  setMode('after')
  decorate(bp.current)
})()
