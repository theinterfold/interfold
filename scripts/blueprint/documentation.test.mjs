// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runInNewContext } from 'node:vm'
import test from 'node:test'
import { checkDocumentation, checkRef, BLUEPRINT, loadData } from './lib/data.mjs'
import { documentationURL } from './lib/documentation.mjs'
import { buildData, pageHtml } from './lib/page.mjs'

test('documentation accepts existing docs without treating them as code evidence', () => {
  for (const path of ['docs/architecture/dkg.md', 'docs/pages/build/sdk.mdx']) {
    assert.deepEqual(checkDocumentation({ path, title: 'Owner' }), { status: 'ok', path, title: 'Owner' })
    assert.equal(checkRef(`${path}@1@title`).status, 'bad')
  }
})

test('documentation rejects missing targets, non-docs paths and noncanonical paths', () => {
  for (const path of [
    'docs/missing-owner.md',
    'crates/indexer/README.md',
    'AGENTS.md',
    '/docs/architecture/dkg.md',
    'docs/../AGENTS.md',
    'docs//architecture/dkg.md',
    'docs/./architecture/dkg.md',
    'docs\\architecture\\dkg.md',
    'https://example.com/owner.md',
    'javascript:alert(1)',
    'docs/%2e%2e/AGENTS.md',
  ])
    assert.equal(checkDocumentation({ path, title: 'Owner' }).status, 'bad', path)
  for (const value of [null, 'docs/architecture/dkg.md', {}, { path: 'docs/architecture/dkg.md', title: '' }])
    assert.equal(checkDocumentation(value).status, 'bad')
})

test('source URLs work independently of local files and Pages preview routes', () => {
  assert.equal(
    documentationURL('https://github.com/theinterfold/interfold', 'refactor/docs', 'docs/architecture/dkg.md'),
    'https://github.com/theinterfold/interfold/blob/refactor%2Fdocs/docs/architecture/dkg.md',
  )
  assert.equal(documentationURL('javascript:alert(1)', 'main', 'docs/architecture/dkg.md'), null)
  assert.equal(documentationURL('https://github.com/theinterfold/interfold', 'main', '../AGENTS.md'), null)
  assert.equal(documentationURL('https://github.com/theinterfold/interfold', '', 'docs/architecture/dkg.md'), null)
})

test('every authored unit has checked documentation, with existing source references retained', () => {
  for (const file of readdirSync(join(BLUEPRINT, 'facts')).filter((f) => f.endsWith('.json'))) {
    for (const unit of JSON.parse(readFileSync(join(BLUEPRINT, 'facts', file), 'utf8')).units) {
      assert.ok(unit.documentation?.length, `${file}: ${unit.id}`)
      for (const doc of unit.documentation) assert.equal(checkDocumentation(doc).status, 'ok', `${unit.id}: ${doc.path}`)
    }
  }
  const { units, report } = loadData()
  assert.deepEqual(report.documentation, [])
  const circuit = units['C1 pk_generation']
  assert.ok(circuit.facts.documentation.length)
  assert.ok(circuit.facts.read_first.some((r) => r.ref?.path.endsWith('.nr')))
})

test('generated unit and actor diagrams expose documentation without losing code navigation', () => {
  const { data } = buildData({ sourceRef: 'test-ref' })
  const circuit = data.diagrams['circuit:C1 pk_generation']
  assert.ok(circuit.documentation.every((d) => d.href.includes('/blob/test-ref/docs/')))
  assert.ok(circuit.nodes.find((n) => n.id === 'self').code)
  const actor = Object.values(data.diagrams).find((d) => d.id.startsWith('actor:e3-keyshare:'))
  assert.ok(actor.documentation.length)
  assert.ok(actor.nodes.some((n) => n.code))
  assert.match(pageHtml(data), /id="documentation"/)
})

test('an unknown source ref retains documentation targets and warns instead of inventing links', () => {
  const { data, warnings } = buildData({ sourceRef: '' })
  const docs = data.diagrams['circuit:C1 pk_generation'].documentation
  assert.ok(docs.length)
  assert.ok(docs.every((d) => d.path.startsWith('docs/') && d.href === null))
  assert.ok(warnings.some((w) => w.includes('BLUEPRINT_SOURCE_REF')))
})

function renderer(data, diff = false) {
  const element = () => ({
    children: [],
    dataset: {},
    style: {},
    hidden: true,
    innerHTML: '',
    textContent: '',
    classList: { add() {}, remove() {} },
    setAttribute() {},
    addEventListener() {},
    querySelector() {
      return null
    },
    querySelectorAll() {
      return []
    },
    appendChild(child) {
      this.children.push(child)
      return child
    },
    replaceChildren() {
      this.children = []
    },
  })
  const elements = new Map()
  const document = {
    body: element(),
    createElement: element,
    createElementNS: element,
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element())
      return elements.get(id)
    },
    querySelectorAll() {
      return []
    },
  }
  const window = { BLUEPRINT: data }
  const context = {
    window,
    document,
    matchMedia: () => ({ matches: true }),
    addEventListener() {},
    location: { hash: '#d=system' },
    history: { replaceState() {}, pushState() {} },
    localStorage: {
      getItem() {
        return null
      },
    },
    requestAnimationFrame: (fn) => fn(),
    cancelAnimationFrame() {},
  }
  runInNewContext(readFileSync(join(BLUEPRINT, 'renderer.js'), 'utf8'), context)
  if (diff) runInNewContext(readFileSync(join(BLUEPRINT, 'diff/view.js'), 'utf8'), context)
  return { elements, window }
}

const diagram = (documentation) => ({ id: 'system', title: 'Fixture', w: 400, h: 300, nodes: [], edges: [], documentation })

test('renderer uses literal link titles, ignores unsafe schemes and clears links on navigation', () => {
  const title = '<img src=x onerror=alert(1)>'
  const good = { title, href: 'https://github.com/theinterfold/interfold/blob/main/docs/architecture/dkg.md' }
  const { elements, window } = renderer({
    root: 'system',
    code: {},
    diagrams: {
      system: diagram([good, { title: 'bad', href: 'javascript:alert(1)' }]),
      other: { ...diagram([]), id: 'other' },
    },
  })
  const links = elements.get('documentation')
  assert.equal(links.children.length, 1)
  assert.equal(links.children[0].textContent, title)
  assert.equal(links.children[0].innerHTML, '')
  assert.equal(links.children[0].rel, 'noopener noreferrer')
  window.blueprint.go('other')
  assert.equal(links.children.length, 0)
})

test('diff renders documentation-only changes and switches source links even on unchanged diagrams', () => {
  const dir = mkdtempSync(join(tmpdir(), 'blueprint-doc-test-'))
  try {
    const doc = (ref, path = 'docs/architecture/dkg.md') => ({
      title: 'Owner',
      path,
      href: documentationURL('https://github.com/theinterfold/interfold', ref, path),
    })
    const snap = (docs) => ({
      v: 1,
      structure: {
        crates: {},
        actors: [],
        handlers: [],
        links: [],
        contracts: {},
        circuits: [],
      },
      data: { root: 'system', tag: 'fixture', code: {}, diagrams: { system: diagram(docs) } },
    })
    const side = (name, docs) => {
      const path = join(dir, name)
      const script = join(path, 'scripts/blueprint/diff/diff.mjs')
      mkdirSync(join(path, 'scripts/blueprint/diff'), { recursive: true })
      writeFileSync(
        script,
        `import { writeFileSync } from 'node:fs'; writeFileSync(process.argv[process.argv.indexOf('--snapshot') + 1], JSON.stringify(${JSON.stringify(snap(docs))}));`,
      )
      return path
    }
    const base = side('base', [doc('before-ref')])
    const head = side('head', [doc('after-ref', 'docs/architecture/threshold-decryption.md')])
    const out = join(dir, 'out')
    const run = () =>
      execFileSync(process.execPath, [join(BLUEPRINT, 'diff/diff.mjs'), base, head], {
        env: { ...process.env, BLUEPRINT_OUT: out },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    run()
    const file = join(out, 'interfold-blueprint-diff.html')
    const html = readFileSync(file, 'utf8')
    const data = JSON.parse(html.match(/window\.BLUEPRINT = ([\s\S]*?);<\/script>/)[1])
    assert.match(data.diff.list[0].text, /documentation changed/)
    const { elements } = renderer(data, true)
    const links = elements.get('documentation')
    assert.match(links.children[0].href, /\/after-ref\//)
    elements.get('d-before').onclick()
    assert.match(links.children[0].href, /\/before-ref\//)
    elements.get('d-after').onclick()
    assert.match(links.children[0].href, /\/after-ref\//)

    // A ref alone must not create an architecture change or page.
    side('head', [doc('after-ref')])
    rmSync(file)
    run()
    assert.equal(existsSync(file), false)

    // Before still selects the old ref when no boxes or documentation targets changed.
    const unchanged = {
      ...snap([doc('after-ref')]).data,
      diff: {
        before: {},
        codeBefore: {},
        marks: {},
        counts: {},
        touched: {},
        list: [],
        base: 'before',
        head: 'after',
        documentationBefore: { system: [doc('before-ref')] },
      },
    }
    const ui = renderer(unchanged, true)
    ui.elements.get('d-before').onclick()
    assert.match(ui.elements.get('documentation').children[0].href, /\/before-ref\//)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
