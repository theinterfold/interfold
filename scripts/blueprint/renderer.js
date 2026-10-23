// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Blueprint renderer: flat architecture diagrams that open into each other.
// Each diagram is data (boxes, groups, boundaries, edges); this file draws it as SVG, routes the
// edges at right angles, and handles drill-in, breadcrumbs, pan and zoom, and the code panel.
;(() => {
  const B = window.BLUEPRINT
  const D = B.diagrams
  const svg = document.getElementById('canvas')
  const crumbs = document.getElementById('crumbs')
  const titleEl = document.getElementById('dtitle')
  const subEl = document.getElementById('dsub')
  const documentationEl = document.getElementById('documentation')
  const panel = document.getElementById('code')
  const tip = document.getElementById('tip')
  const q = document.getElementById('q')
  const results = document.getElementById('results')
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches
  const NS = 'http://www.w3.org/2000/svg'
  const esc = (s) =>
    String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')

  // ------------------------------------------------------------------ geometry
  const anchor = (n, side, f = 0.5) => {
    if (side === 'l') return [n.x, n.y + n.h * f]
    if (side === 'r') return [n.x + n.w, n.y + n.h * f]
    if (side === 't') return [n.x + n.w * f, n.y]
    return [n.x + n.w * f, n.y + n.h]
  }
  const horiz = (s) => s === 'l' || s === 'r'
  function route(e, nodes) {
    const a = nodes[e.from]
    const b = nodes[e.to]
    if (!a || !b) return null
    const p0 = anchor(a, e.fs || 'r', e.fa ?? 0.5)
    const p1 = anchor(b, e.ts || 'l', e.ta ?? 0.5)
    if (e.via) return [p0, ...e.via, p1]
    const fsH = horiz(e.fs || 'r')
    const tsH = horiz(e.ts || 'l')
    if (fsH && tsH) {
      // Nearly level: draw straight, landing on the target side at the source height.
      if (Math.abs(p0[1] - p1[1]) < 10 && p0[1] > b.y + 4 && p0[1] < b.y + b.h - 4) return [p0, [p1[0], p0[1]]]
      const mx = e.mx ?? (p0[0] + p1[0]) / 2
      return [p0, [mx, p0[1]], [mx, p1[1]], p1]
    }
    if (!fsH && !tsH) {
      if (Math.abs(p0[0] - p1[0]) < 10 && p0[0] > b.x + 4 && p0[0] < b.x + b.w - 4) return [p0, [p0[0], p1[1]]]
      const my = e.my ?? (p0[1] + p1[1]) / 2
      return [p0, [p0[0], my], [p1[0], my], p1]
    }
    return fsH ? [p0, [p1[0], p0[1]], p1] : [p0, [p0[0], p1[1]], p1]
  }
  const pathD = (pts) => 'M' + pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' L')
  function labelSpot(pts, e) {
    if (e.lx != null) return { x: e.lx, y: e.ly, anchor: e.lanchor || 'middle' }
    let best = 0
    let bi = 0
    for (let i = 0; i < pts.length - 1; i++) {
      const len = Math.abs(pts[i + 1][0] - pts[i][0]) + Math.abs(pts[i + 1][1] - pts[i][1])
      if (len > best) {
        best = len
        bi = i
      }
    }
    const [a, b] = [pts[bi], pts[bi + 1]]
    const mx = (a[0] + b[0]) / 2
    const t = e.lt ?? 0.5
    const x = a[0] + (b[0] - a[0]) * t
    const y = a[1] + (b[1] - a[1]) * t
    if (Math.abs(a[1] - b[1]) < 1) return e.lp === 'below' ? { x, y: y + 21, anchor: 'middle' } : { x, y: y - 9, anchor: 'middle' }
    return e.lp === 'left' ? { x: mx - 11, y: y + 5, anchor: 'end' } : { x: mx + 11, y: y + 5, anchor: 'start' }
  }

  // ------------------------------------------------------------------ drawing
  function el(tag, attrs = {}, parent) {
    const n = document.createElementNS(NS, tag)
    for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v)
    if (parent) parent.appendChild(n)
    return n
  }
  function text(parent, x, y, str, cls, anchorSide = 'middle') {
    const t = el('text', { x, y, class: cls, 'text-anchor': anchorSide }, parent)
    t.textContent = str
    return t
  }
  function drawNode(g, n) {
    const grp = el(
      'g',
      { class: `node s-${n.style || 'box'}${n.drill ? ' drill' : ''}${n.ref || n.code ? ' has-code' : ''}`, 'data-id': n.id },
      g,
    )
    el('rect', { x: n.x, y: n.y, width: n.w, height: n.h, rx: n.style === 'chip' ? 6 : 8, class: 'box' }, grp)
    const lines = n.lines || []
    const titleH = n.title ? (n.style === 'chip' ? 19 : 24) : 0
    const lineH = n.style === 'chip' ? 18 : 21
    const total = titleH + lines.length * lineH
    let y = n.y + n.h / 2 - total / 2 + (n.style === 'chip' ? 14 : 17)
    const cx = n.x + n.w / 2
    if (n.title) {
      text(grp, cx, y, n.title, n.mono ? 'title mono' : 'title')
      y += titleH + (lines.length ? 1 : 0)
    }
    for (const l of lines) {
      text(grp, cx, y, l, n.monoLines ? 'line mono' : 'line')
      y += lineH
    }
    if (n.tag) {
      const w = n.tag.length * 9.6 + 22
      el('rect', { x: n.x + 14, y: n.y - 13, width: w, height: 25, rx: 3, class: 'tab' }, grp)
      text(grp, n.x + 14 + w / 2, n.y + 4.5, n.tag.toUpperCase(), 'tabtext')
    }
    if (n.drill) {
      // Two stacked squares: this box has a diagram inside.
      const x = n.x + n.w - 24
      const y0 = n.y + 10
      el('rect', { x: x + 4, y: y0, width: 11, height: 11, rx: 2, class: 'glyph' }, grp)
      el('rect', { x, y: y0 + 4, width: 11, height: 11, rx: 2, class: 'glyph front' }, grp)
    } else if (n.ref || n.code) {
      text(grp, n.x + n.w - 10, n.y + 18, '</>', 'codeglyph', 'end')
    }
    return grp
  }

  let current = null
  let vb = null
  let fit = null
  let navDepth = 0
  function render(d) {
    current = d
    svg.textContent = ''
    const defs = el('defs', {}, svg)
    const m = el(
      'marker',
      {
        id: 'arrow',
        viewBox: '0 0 10 10',
        refX: 9.2,
        refY: 5,
        markerWidth: 8.5,
        markerHeight: 8.5,
        orient: 'auto-start-reverse',
        markerUnits: 'userSpaceOnUse',
      },
      defs,
    )
    el('path', { d: 'M0,0 L10,5 L0,10 z', class: 'arrowhead' }, m)
    const ml = el(
      'marker',
      {
        id: 'arrow-lit',
        viewBox: '0 0 10 10',
        refX: 9.2,
        refY: 5,
        markerWidth: 10,
        markerHeight: 10,
        orient: 'auto-start-reverse',
        markerUnits: 'userSpaceOnUse',
      },
      defs,
    )
    el('path', { d: 'M0,0 L10,5 L0,10 z', class: 'arrowhead lit' }, ml)
    const root = el('g', { id: 'root' }, svg)
    for (const b of d.bounds || []) {
      el('rect', { x: b.x, y: b.y, width: b.w, height: b.h, rx: 18, class: 'bound' }, root)
      text(root, b.x + 22, b.y + 30, b.label, 'glabel', 'start')
    }
    for (const gr of d.groups || []) {
      el('rect', { x: gr.x, y: gr.y, width: gr.w, height: gr.h, rx: 13, class: 'group' }, root)
      if (gr.label) text(root, gr.x + 18, gr.y + 27, gr.label, 'glabel', 'start')
    }
    const nodes = Object.fromEntries((d.nodes || []).map((n) => [n.id, n]))
    const edgeLayer = el('g', { class: 'edges' }, root)
    const nodeLayer = el('g', { class: 'nodes' }, root)
    const labelLayer = el('g', { class: 'elabels' }, root)
    ;(d.edges || []).forEach((e, i) => {
      const pts = route(e, nodes)
      if (!pts) return
      const grp = el(
        'g',
        { class: `edge${e.dashed ? ' dashed' : ''}${e.refs && e.refs.length ? ' has-code' : ''}`, 'data-edge': i, 'data-key': e.key },
        edgeLayer,
      )
      el('path', { d: pathD(pts), class: 'hit' }, grp)
      el(
        'path',
        {
          d: pathD(pts),
          class: 'line',
          id: `ep-${i}`,
          'marker-end': e.none ? null : 'url(#arrow)',
          'marker-start': e.both ? 'url(#arrow)' : null,
        },
        grp,
      )
      if (e.label) {
        const s = labelSpot(pts, e)
        const parts = String(e.label).split('\n')
        const t = el(
          'text',
          { x: s.x, y: s.y - (parts.length - 1) * 19, class: 'elabel', 'text-anchor': s.anchor, 'data-edge': i, 'data-key': e.key },
          labelLayer,
        )
        parts.forEach((p, k) => {
          const ts = el('tspan', { x: s.x, dy: k ? 19 : 0 }, t)
          ts.textContent = p
        })
      }
    })
    for (const n of d.nodes || []) drawNode(nodeLayer, n)
    for (const nt of d.notes || []) {
      const t = el('text', { x: nt.x, y: nt.y, class: `note${nt.cls ? ' ' + nt.cls : ''}`, 'text-anchor': nt.anchor || 'start' }, root)
      String(nt.text)
        .split('\n')
        .forEach((p, k) => {
          const ts = el('tspan', { x: nt.x, dy: k ? 16 : 0 }, t)
          ts.textContent = p
        })
    }
    fit = { x: -40, y: -40, w: d.w + 80, h: d.h + 80 }
    titleEl.textContent = d.title
    subEl.textContent = d.sub || ''
    documentationEl.replaceChildren()
    for (const doc of d.documentation || []) {
      if (!/^https:\/\/github\.com\//.test(doc.href)) continue
      const a = document.createElement('a')
      a.href = doc.href
      a.textContent = doc.title
      a.target = '_blank'
      a.rel = 'noopener noreferrer'
      documentationEl.appendChild(a)
    }
    document.title = `${d.title} · Interfold blueprint`
    drawCrumbs(d)
  }

  // ------------------------------------------------------------------ view
  function setVB(v) {
    vb = v
    svg.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`)
  }
  const lerp = (a, b, t) => a + (b - a) * t
  let anim = null
  function animate(from, to, ms, done) {
    cancelAnimationFrame(anim)
    if (reduced || ms <= 0) {
      setVB(to)
      return done && done()
    }
    const t0 = performance.now()
    const step = (t) => {
      const p = Math.min(1, (t - t0) / ms)
      const e = p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2
      const lw = Math.exp(lerp(Math.log(from.w), Math.log(to.w), e))
      const lh = Math.exp(lerp(Math.log(from.h), Math.log(to.h), e))
      const cx = lerp(from.x + from.w / 2, to.x + to.w / 2, e)
      const cy = lerp(from.y + from.h / 2, to.y + to.h / 2, e)
      setVB({ x: cx - lw / 2, y: cy - lh / 2, w: lw, h: lh })
      if (p < 1) anim = requestAnimationFrame(step)
      else if (done) done()
    }
    anim = requestAnimationFrame(step)
  }
  const pad = (r, k) => ({ x: r.x - r.w * k, y: r.y - r.h * k, w: r.w * (1 + 2 * k), h: r.h * (1 + 2 * k) })

  // Go to diagram `id`. `from` is the rect of the clicked box (zoom in); `back` zooms out.
  // `shown(d)` runs after the new diagram is drawn; it may return the rect to settle on.
  // Each navigation gets a number. The diagram swap runs on its own timer, so a stopped camera
  // animation (a wheel tick, another animation) cannot drop it, and a newer navigation cancels an
  // older swap.
  let navSeq = 0
  function go(id, { from = null, push = true, shown = null, hash = null } = {}) {
    const d = D[id]
    if (!d) return
    const seq = ++navSeq
    closeCode()
    hideTip()
    const prev = current
    const goingUp = prev && isAncestor(id, prev.id)
    const settle = () => {
      const target = (shown && shown(d)) || fit
      for (const fn of api.hooks) fn(d)
      return target
    }
    const swap = () => {
      if (seq !== navSeq) return
      svg.classList.add('fading')
      render(d)
      const target = settle()
      if (goingUp && prev && target === fit) {
        const child = (d.nodes || []).find((n) => n.drill === chainChildOf(id, prev.id))
        setVB(child ? pad(child, 0.15) : fit)
        requestAnimationFrame(() => {
          svg.classList.remove('fading')
          animate(vb, target, 420)
        })
      } else {
        setVB(pad(target, -0.06))
        requestAnimationFrame(() => {
          svg.classList.remove('fading')
          animate(vb, target, 380)
        })
      }
    }
    if (prev && prev.id === id && shown) {
      // Same diagram: keep it, move the camera only.
      const target = settle()
      animate(vb, target, 480)
    } else if (prev && from && !reduced) {
      animate(vb, pad(from, 0.08), 360)
      setTimeout(swap, 360)
    } else if (prev && goingUp && !reduced) {
      animate(vb, pad(vb, 0.25), 220)
      setTimeout(swap, 220)
    } else swap()
    const h = hash || '#d=' + encodeURIComponent(id)
    if (push && location.hash !== h) {
      history.pushState({ id, depth: navDepth + 1 }, '', h)
      navDepth++
    }
  }
  const chain = (id) => {
    const out = []
    let c = D[id]
    while (c) {
      out.unshift(c)
      c = c.parent ? D[c.parent] : null
    }
    return out
  }
  const isAncestor = (a, b) => chain(b).some((d) => d.id === a) && a !== b
  const chainChildOf = (ancestor, id) => {
    const c = chain(id)
    const i = c.findIndex((d) => d.id === ancestor)
    return c[i + 1] ? c[i + 1].id : null
  }
  function drawCrumbs(d) {
    crumbs.innerHTML = chain(d.id)
      .map((c, i, all) =>
        i < all.length - 1
          ? `<a href="#d=${encodeURIComponent(c.id)}" data-id="${esc(c.id)}">${esc(c.crumb || c.title)}</a><span>›</span>`
          : `<b>${esc(c.crumb || c.title)}</b>`,
      )
      .join('')
  }
  crumbs.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-id]')
    if (!a) return
    e.preventDefault()
    go(a.dataset.id)
  })
  addEventListener('popstate', (e) => {
    navDepth = (e.state && e.state.depth) || 0
    const w = location.hash.match(/#w=(\d+)$/)
    if (w && api.onWalkHash) return api.onWalkHash(Number(w[1]))
    const id = decodeURIComponent((location.hash.match(/#d=(.+)$/) || [])[1] || B.root)
    go(D[id] ? id : B.root, { push: false })
  })
  // Up and Esc: back to the diagram you came from; on a page opened at a deep link, to the parent.
  function up() {
    if (navDepth > 0) history.back()
    else if (current && current.parent) go(current.parent)
  }

  // ------------------------------------------------------------------ input
  const geom = () => {
    const r = svg.getBoundingClientRect()
    const s = Math.min(r.width / vb.w, r.height / vb.h)
    return { r, s, ox: (r.width - vb.w * s) / 2, oy: (r.height - vb.h * s) / 2 }
  }
  const toWorld = (cx, cy) => {
    const g = geom()
    return [(cx - g.r.left - g.ox) / g.s + vb.x, (cy - g.r.top - g.oy) / g.s + vb.y]
  }
  let drag = null
  svg.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return
    // Record what is under the pointer now: pointer capture sends the pointerup to the <svg>.
    const nodeEl = e.target.closest && e.target.closest('.node')
    const edgeEl = e.target.closest && (e.target.closest('.edge') || e.target.closest('.elabel'))
    drag = {
      x: e.clientX,
      y: e.clientY,
      vb: { ...vb },
      moved: false,
      node: nodeEl && nodeEl.dataset.id,
      edge: edgeEl && edgeEl.dataset.edge,
    }
    svg.setPointerCapture(e.pointerId)
  })
  svg.addEventListener('pointermove', (e) => {
    if (!drag) return hover(e)
    const dx = e.clientX - drag.x
    const dy = e.clientY - drag.y
    if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true
    if (drag.moved) {
      const g = geom()
      setVB({ ...drag.vb, x: drag.vb.x - dx / g.s, y: drag.vb.y - dy / g.s })
    }
  })
  svg.addEventListener('pointerup', (e) => {
    if (!drag) return
    const { moved, node, edge } = drag
    drag = null
    svg.releasePointerCapture(e.pointerId)
    if (moved) return
    if (node) return clickNode(node)
    if (edge != null) return clickEdge(Number(edge))
    closeCode()
  })
  svg.addEventListener(
    'wheel',
    (e) => {
      e.preventDefault()
      cancelAnimationFrame(anim)
      if (e.ctrlKey || e.metaKey || Math.abs(e.deltaY) > Math.abs(e.deltaX) * 0.6) {
        const f = Math.exp(e.deltaY * (e.ctrlKey ? 0.012 : 0.0022))
        const [wx, wy] = toWorld(e.clientX, e.clientY)
        const w = Math.min(fit.w * 1.6, Math.max(fit.w / 12, vb.w * f))
        const h = (w * vb.h) / vb.w
        setVB({ x: wx - ((wx - vb.x) / vb.w) * w, y: wy - ((wy - vb.y) / vb.h) * h, w, h })
      } else {
        const g = geom()
        setVB({ ...vb, x: vb.x + e.deltaX / g.s, y: vb.y + e.deltaY / g.s })
      }
    },
    { passive: false },
  )
  addEventListener('keydown', (e) => {
    if (e.target === q) {
      if (e.key === 'Escape') {
        q.value = ''
        results.hidden = true
        q.blur()
      }
      return
    }
    if (api.onKey && api.onKey(e)) return
    if (e.key === 'Escape' || e.key === 'Backspace') {
      if (!panel.hidden) return closeCode()
      up()
    } else if (e.key === '0') animate(vb, fit, 300)
    else if (e.key === '/') {
      e.preventDefault()
      q.focus()
    } else if (e.key === 't' || e.key === 'T') toggleTheme()
  })
  document.getElementById('fit').onclick = () => animate(vb, fit, 300)
  document.getElementById('up').onclick = up
  document.getElementById('theme').onclick = toggleTheme
  function toggleTheme() {
    document.body.dataset.theme = document.body.dataset.theme === 'dark' ? 'light' : 'dark'
    try {
      localStorage.setItem('blueprint-theme', document.body.dataset.theme)
    } catch {
      // Storage can be off (a private window): the theme then lasts for this page only.
    }
  }
  try {
    const t = localStorage.getItem('blueprint-theme')
    if (t) document.body.dataset.theme = t
  } catch {
    // Storage can be off (a private window): keep the light theme.
  }

  function nodeById(id) {
    return (current.nodes || []).find((n) => n.id === id)
  }
  function clickNode(id) {
    const n = nodeById(id)
    if (!n) return
    if (n.drill && D[n.drill]) return go(n.drill, { from: n })
    if (n.code || n.ref) return openCode({ title: n.title, refs: n.code ? [{ code: n.code, focus: n.focus }] : [n.ref], tip: n.tip })
  }
  function clickEdge(i) {
    const e = current.edges[i]
    if (e && e.refs && e.refs.length) openCode({ title: e.label ? String(e.label).replace(/\n/g, ' ') : 'edge', refs: e.refs, tip: e.tip })
  }

  // ------------------------------------------------------------------ hover tips
  function hover(e) {
    const n = e.target.closest && e.target.closest('.node')
    const ed = e.target.closest && (e.target.closest('.edge') || e.target.closest('.elabel'))
    let html = ''
    if (n) {
      const d = nodeById(n.dataset.id)
      if (d) {
        html = `<b>${esc(d.title)}</b>${d.tip ? `<span>${esc(d.tip)}</span>` : ''}${d.drill && D[d.drill] ? '<em>Click to open the diagram inside</em>' : d.code || d.ref ? '<em>Click to read the code</em>' : ''}`
      }
    } else if (ed) {
      const d = current.edges[Number(ed.dataset.edge)]
      if (d && (d.tip || (d.refs && d.refs.length)))
        html = `${d.label ? `<b>${esc(String(d.label).replace(/\n/g, ' '))}</b>` : ''}${d.tip ? `<span>${esc(d.tip)}</span>` : ''}${d.refs && d.refs.length ? `<em>Click to read the code (${d.refs.length} ${d.refs.length > 1 ? 'places' : 'place'})</em>` : ''}`
    }
    if (!html) return hideTip()
    tip.innerHTML = html
    tip.hidden = false
    const r = document.getElementById('stage').getBoundingClientRect()
    const x = Math.min(e.clientX - r.left + 16, r.width - 340)
    tip.style.transform = `translate(${x}px, ${e.clientY - r.top + 18}px)`
  }
  function hideTip() {
    tip.hidden = true
  }
  svg.addEventListener('pointerleave', hideTip)

  // ------------------------------------------------------------------ code panel
  const vscode = (path, line) => `vscode://file/${B.root_dir}/${path}:${line}`
  function codeBlock(r) {
    const ex = B.code[r.code]
    if (!ex) return ''
    const focus = r.focus || r.line
    const rows = ex.lines
      .map((l, i) => {
        const n = ex.start + i
        return `<div class="cl${n === focus ? ' focus' : ''}"><i>${n}</i><code>${esc(l) || ' '}</code></div>`
      })
      .join('')
    const more = ex.more > 0 ? `<div class="more">… ${ex.more} more lines in the file</div>` : ''
    return `<div class="file"><a href="${esc(vscode(ex.path, focus || ex.start))}">${esc(ex.path)}:${focus || ex.start}</a><span>open in VS Code</span></div><div class="src">${rows}${more}</div>`
  }
  function openCode({ title, refs, tip: note }) {
    panel.innerHTML = `<header><button class="x" title="Close (Esc)">×</button><div class="k">code</div><h3>${esc(title)}</h3>${note ? `<p>${esc(note)}</p>` : ''}</header>${refs.map(codeBlock).join('')}`
    panel.hidden = false
    panel.scrollTop = 0
    const f = panel.querySelector('.cl.focus')
    if (f) f.scrollIntoView({ block: 'center' })
  }
  function closeCode() {
    panel.hidden = true
  }
  panel.addEventListener('click', (e) => {
    if (e.target.closest('.x')) closeCode()
  })

  // ------------------------------------------------------------------ search
  const index = []
  for (const d of Object.values(D)) {
    index.push({ text: d.title, kind: 'diagram', id: d.id })
    for (const n of d.nodes || []) if (n.title) index.push({ text: n.title, kind: 'in ' + (d.crumb || d.title), id: d.id, node: n.id })
  }
  let hits = []
  let cursor = 0
  q.addEventListener('input', () => {
    const s = q.value.trim().toLowerCase()
    if (!s) return (results.hidden = true)
    const seen = new Set()
    hits = index
      .map((x) => ({ x, i: x.text.toLowerCase().indexOf(s) }))
      .filter((h) => h.i >= 0)
      .sort(
        (a, b) => (a.x.kind === 'diagram' ? -1 : 0) - (b.x.kind === 'diagram' ? -1 : 0) || a.i - b.i || a.x.text.length - b.x.text.length,
      )
      .map((h) => h.x)
      .filter((x) => {
        const k = x.text + '|' + x.id
        if (seen.has(k)) return false
        seen.add(k)
        return true
      })
      .slice(0, 14)
    cursor = 0
    drawHits()
  })
  function drawHits() {
    results.innerHTML = hits.length
      ? hits
          .map(
            (h, i) => `<div class="hit${i === cursor ? ' on' : ''}" data-i="${i}"><b>${esc(h.text)}</b><span>${esc(h.kind)}</span></div>`,
          )
          .join('')
      : '<div class="hit none">No match</div>'
    results.hidden = false
  }
  q.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') {
      cursor = Math.min(hits.length - 1, cursor + 1)
      drawHits()
      e.preventDefault()
    } else if (e.key === 'ArrowUp') {
      cursor = Math.max(0, cursor - 1)
      drawHits()
      e.preventDefault()
    } else if (e.key === 'Enter' && hits[cursor]) choose(hits[cursor])
  })
  results.addEventListener('mousedown', (e) => {
    const h = e.target.closest('.hit')
    if (h && h.dataset.i) choose(hits[Number(h.dataset.i)])
  })
  q.addEventListener('blur', () => setTimeout(() => (results.hidden = true), 150))
  function choose(h) {
    results.hidden = true
    q.blur()
    go(h.id)
    if (h.node)
      setTimeout(() => {
        const g = svg.querySelector(`.node[data-id="${CSS.escape(h.node)}"]`)
        if (g) {
          g.classList.add('flash')
          setTimeout(() => g.classList.remove('flash'), 1600)
        }
      }, 450)
  }

  // ------------------------------------------------------------------ start
  // The walkthrough (walk.js) uses this API; it loads after this file.
  const api = {
    go,
    up,
    openCode,
    closeCode,
    animate: (to, ms = 450) => animate(vb, to, ms),
    pad,
    hooks: [],
    onKey: null,
    onWalkHash: null,
    svg,
    get current() {
      return current
    },
    get vb() {
      return vb
    },
    get fit() {
      return fit
    },
  }
  window.blueprint = api
  const startWalk = location.hash.match(/#w=(\d+)$/)
  const start = decodeURIComponent((location.hash.match(/#d=(.+)$/) || [])[1] || B.root)
  render(D[start] ? D[start] : D[B.root])
  setVB(fit)
  if (!startWalk) history.replaceState({ id: current.id, depth: 0 }, '', '#d=' + encodeURIComponent(current.id))
})()
