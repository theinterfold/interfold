// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'interfold-doc-links-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const write = (path, text) => {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), text)
  }
  execFileSync('git', ['init', '--quiet'], { cwd: root })
  write('docs/guide.md', '# First heading\n\n## Déjà vu &amp; API\n')
  write('docs/with spaces.mdx', '# Repeat\n\n# Repeat\n\n<a id="custom-id"></a>\n')
  write('assets/diagram.svg', '<svg/>')
  const run = (...files) =>
    spawnSync(process.execPath, [new URL('doc-links.mjs', import.meta.url).pathname, ...files], {
      cwd: root,
      encoding: 'utf8',
    })
  return { root, write, run }
}

test('documentation links check relative targets, references, images, and heading/explicit anchors without writing', (t) => {
  const { root, write, run } = fixture(t)
  write(
    'README.md',
    `# Home
[Guide](docs/guide.md#first-heading)
[Unicode](docs/guide.md#déjà-vu--api)
[Spaces](<docs/with spaces.mdx#custom-id>)
[Encoded](docs/with%20spaces.mdx#repeat-1)
[Reference][guide]
[guide]: docs/guide.md#first-heading
![Diagram](assets/diagram.svg)
![](assets/diagram.svg)
[Local](#home)
[Site route](/build/sdk)
[External](https://example.invalid/no-network-request)
Footnote prose[^source].
[^source]: A citation, not a file destination. [Guide](docs/guide.md#first-heading)

\`[Code](not-a-link.md)\`
\`\`\`md
[Example](also-not-a-link.md)
\`\`\`
`,
  )
  execFileSync('git', ['add', '.'], { cwd: root })
  const status = () => execFileSync('git', ['status', '--porcelain=v1'], { cwd: root, encoding: 'utf8' })
  const before = status()
  const result = run()
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /relative documentation links/)
  assert.equal(status(), before)
})

test('documentation links reject missing files, anchors, wrong case, malformed escapes, and repository escapes', (t) => {
  const { write, run } = fixture(t)
  for (const [target, error] of [
    ['docs/missing.md', /missing target/],
    ['docs/guide.md#absent', /missing anchor/],
    ['docs/Guide.md', /missing target|case/],
    ['docs/%ZZ.md', /invalid URL escape/],
    ['../outside.md', /outside the repository/],
  ]) {
    write('README.md', `[Bad](${target})\n`)
    const result = run('README.md')
    assert.equal(result.status, 1, target)
    assert.match(result.stdout + result.stderr, error)
    assert.match(result.stdout + result.stderr, /README\.md:1:/)
  }
  write('README.md', '![](missing.svg)\n')
  const image = run('README.md')
  assert.equal(image.status, 1)
  assert.match(image.stdout + image.stderr, /missing target/)
})

test('documentation discovery includes pending Markdown and excludes Git-ignored output', (t) => {
  const { root, write, run } = fixture(t)
  write('README.md', '[Guide](docs/guide.md#first-heading)\n')
  write('.gitignore', 'ignored.md\n')
  execFileSync('git', ['add', '.'], { cwd: root })
  write('ignored.md', '[Ignored](absent.md)\n')
  write('docs/pending.md', '[Broken](missing.md)\n')
  const failed = run()
  assert.equal(failed.status, 1)
  assert.match(failed.stdout + failed.stderr, /docs\/pending\.md/)
  write('docs/pending.md', '[Good](guide.md#first-heading)\n')
  const passed = run()
  assert.equal(passed.status, 0, passed.stdout + passed.stderr)
})

test('documentation anchor checks do not accept IDs from prose or inline code examples', (t) => {
  const { write, run } = fixture(t)
  write('docs/guide.md', '# Guide\n\nText id="prose-only".\n\n`<a id="example-only"></a>`\n\n<a id="real-anchor"></a>\n')
  for (const anchor of ['prose-only', 'example-only']) {
    write('README.md', `[Not an anchor](docs/guide.md#${anchor})\n`)
    const result = run('README.md')
    assert.equal(result.status, 1, anchor)
    assert.match(result.stdout + result.stderr, /missing anchor/)
  }
  write('README.md', '[Real](docs/guide.md#real-anchor)\n')
  const result = run('README.md')
  assert.equal(result.status, 0, result.stdout + result.stderr)
})

test('documentation links never read a symlink target outside the repository', (t) => {
  const { root, write, run } = fixture(t)
  const outside = mkdtempSync(join(tmpdir(), 'interfold-doc-links-outside-'))
  t.after(() => rmSync(outside, { recursive: true, force: true }))
  writeFileSync(join(outside, 'private.md'), '# Private\n')
  symlinkSync(join(outside, 'private.md'), join(root, 'docs/escape.md'))
  write('README.md', '[Escape](docs/escape.md#private)\n')
  const result = run('README.md')
  assert.equal(result.status, 1)
  assert.match(result.stdout + result.stderr, /outside the repository/)
})
