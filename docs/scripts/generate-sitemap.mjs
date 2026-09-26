// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Writes public/sitemap.xml from the pages directory before each build.
// Search engines and the docs MCP server (packages/interfold-mcp) read this file to find every page.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const PAGES = path.join(ROOT, 'pages')
const BASE_URL = 'https://docs.theinterfold.com'
const EXCLUDED = new Set(['/404'])

function routes(dir, prefix = '') {
  const found = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('_') || entry.name.startsWith('.')) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      found.push(...routes(full, `${prefix}/${entry.name}`))
    } else if (/\.mdx?$/.test(entry.name)) {
      const name = entry.name.replace(/\.mdx?$/, '')
      found.push(name === 'index' ? prefix || '/' : `${prefix}/${name}`)
    }
  }
  return found
}

const urls = routes(PAGES)
  .filter((route) => !EXCLUDED.has(route))
  .sort()
  .map((route) => `  <url><loc>${BASE_URL}${route === '/' ? '' : route}</loc></url>`)

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join('\n')}
</urlset>
`
fs.writeFileSync(path.join(ROOT, 'public', 'sitemap.xml'), xml)
console.log(`sitemap: wrote ${urls.length} URLs`)
