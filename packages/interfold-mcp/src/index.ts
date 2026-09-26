// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { parse } from 'node-html-parser'
import { z } from 'zod'
import pkg from '../package.json' with { type: 'json' }

const { version } = pkg

const BASE_URL = 'https://docs.theinterfold.com'
const FETCH_TIMEOUT_MS = 10_000

interface DocPage {
  slug: string
  title: string
  url: string
}

// Fallback corpus used when the sitemap cannot be fetched.
const STATIC_DOC_PAGES: DocPage[] = [
  { slug: 'learn', title: 'Overview', url: '/learn' },
  { slug: 'learn/what-is-e3', title: 'What is an E3?', url: '/learn/what-is-e3' },
  { slug: 'learn/architecture', title: 'Architecture', url: '/learn/architecture' },
  { slug: 'learn/e3-lifecycle', title: 'E3 Lifecycle', url: '/learn/e3-lifecycle' },
  { slug: 'learn/cryptography', title: 'Cryptography', url: '/learn/cryptography' },
  { slug: 'learn/use-cases', title: 'Use Cases', url: '/learn/use-cases' },
  { slug: 'build/installation', title: 'Installation', url: '/build/installation' },
  { slug: 'build/quick-start', title: 'Quick Start', url: '/build/quick-start' },
  { slug: 'build/hello-world', title: 'Hello World', url: '/build/hello-world' },
  { slug: 'build/project-template', title: 'Project Template', url: '/build/project-template' },
  { slug: 'build/e3-program', title: 'E3 Program Anatomy', url: '/build/e3-program' },
  { slug: 'build/e3-program/secure-process', title: 'Secure Process', url: '/build/e3-program/secure-process' },
  { slug: 'build/e3-program/program-contract', title: 'E3 Program Contract', url: '/build/e3-program/program-contract' },
  { slug: 'build/e3-program/compute-provider', title: 'Compute Provider', url: '/build/e3-program/compute-provider' },
  {
    slug: 'build/e3-program/verify-compute-provider',
    title: 'Verify the Compute Provider',
    url: '/build/e3-program/verify-compute-provider',
  },
  { slug: 'build/e3-program/complete-example', title: 'Complete Example', url: '/build/e3-program/complete-example' },
  { slug: 'build/interfold-contract', title: 'The Interfold Contract', url: '/build/interfold-contract' },
  { slug: 'build/requesting-an-e3', title: 'Request an E3', url: '/build/requesting-an-e3' },
  { slug: 'build/sdk', title: 'Interfold SDK', url: '/build/sdk' },
  { slug: 'build/client-and-server', title: 'Client & Server', url: '/build/client-and-server' },
  { slug: 'build/noir-circuits', title: 'Noir Circuits', url: '/build/noir-circuits' },
  { slug: 'build/best-practices', title: 'Best Practices', url: '/build/best-practices' },
  { slug: 'operate', title: 'Ciphernode Operators Overview', url: '/operate' },
  { slug: 'operate/requirements', title: 'Ciphernode Requirements', url: '/operate/requirements' },
  { slug: 'operate/running', title: 'Run a Ciphernode', url: '/operate/running' },
  { slug: 'operate/rpc-endpoints', title: 'RPC Endpoints', url: '/operate/rpc-endpoints' },
  { slug: 'operate/registration', title: 'Registration & Bonding', url: '/operate/registration' },
  { slug: 'operate/tickets-and-sortition', title: 'Tickets & Sortition', url: '/operate/tickets-and-sortition' },
  { slug: 'operate/upgrades', title: 'Upgrades', url: '/operate/upgrades' },
  { slug: 'operate/migrating', title: 'Migrate a Node', url: '/operate/migrating' },
  { slug: 'operate/exits-and-slashing', title: 'Exits, Rewards & Slashing', url: '/operate/exits-and-slashing' },
  { slug: 'operate/troubleshooting', title: 'Troubleshooting', url: '/operate/troubleshooting' },
  { slug: 'reference/cli', title: 'CLI Reference', url: '/reference/cli' },
  { slug: 'reference/configuration', title: 'Node Configuration', url: '/reference/configuration' },
  { slug: 'reference/contracts', title: 'Contracts & Addresses', url: '/reference/contracts' },
  { slug: 'reference/glossary', title: 'Glossary', url: '/reference/glossary' },
  { slug: 'CRISP/introduction', title: 'CRISP Introduction', url: '/CRISP/introduction' },
  { slug: 'CRISP/setup', title: 'CRISP Setup', url: '/CRISP/setup' },
  { slug: 'CRISP/running-e3', title: 'CRISP Running an E3 Program', url: '/CRISP/running-e3' },
  { slug: 'whitepaper', title: 'White Paper', url: '/whitepaper' },
]

function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  return fetch(url, { signal: controller.signal }).finally(() => clearTimeout(timer))
}

// Attempt to build the page corpus from the sitemap so it stays current
// without manual updates. Falls back to STATIC_DOC_PAGES on any failure.
async function loadDocPages(): Promise<DocPage[]> {
  try {
    const response = await fetchWithTimeout(`${BASE_URL}/sitemap.xml`)
    if (!response.ok) return STATIC_DOC_PAGES
    const xml = await response.text()
    const root = parse(xml)
    const locs = root.querySelectorAll('loc').map((el) => el.text.trim())
    if (locs.length === 0) return STATIC_DOC_PAGES
    return locs
      .filter((loc) => loc.startsWith(BASE_URL))
      .map((loc) => {
        const path = loc.slice(BASE_URL.length) || '/'
        const slug = path.replace(/^\//, '')
        const known = STATIC_DOC_PAGES.find((p) => p.slug === slug)
        const title =
          known?.title ??
          slug
            .split('/')
            .map((s) => s.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()))
            .join(' / ')
        return { slug, title, url: path }
      })
  } catch {
    return STATIC_DOC_PAGES
  }
}

async function fetchDocPage(url: string): Promise<string> {
  const fullUrl = `${BASE_URL}${url}`
  const response = await fetchWithTimeout(fullUrl)
  if (!response.ok) {
    throw new Error(`Failed to fetch ${fullUrl}: ${response.status} ${response.statusText}`)
  }
  const html = await response.text()
  const root = parse(html)

  // Remove nav, header, footer, scripts, styles
  root.querySelectorAll("nav, header, footer, script, style, [aria-hidden='true']").forEach((el) => el.remove())

  // Try to get the main article content
  const article = root.querySelector('article') ?? root.querySelector('main') ?? root.querySelector('.nextra-content')
  const content = article ?? root

  return content.text.replace(/\n{3,}/g, '\n\n').trim()
}

const DOC_PAGES = await loadDocPages()

const server = new McpServer({
  name: 'interfold-docs',
  version,
})

// Resource: list all doc pages
server.registerResource('docs-index', 'docs://index', { description: 'Index of all Interfold documentation pages' }, async () => ({
  contents: [
    {
      uri: 'docs://index',
      text: DOC_PAGES.map((p) => `- [${p.title}](docs://${p.slug})`).join('\n'),
      mimeType: 'text/markdown',
    },
  ],
}))

// Resource: individual doc pages
for (const page of DOC_PAGES) {
  server.registerResource(page.slug, `docs://${page.slug}`, { description: page.title }, async () => {
    const content = await fetchDocPage(page.url)
    return {
      contents: [{ uri: `docs://${page.slug}`, text: content, mimeType: 'text/plain' }],
    }
  })
}

// Tool: read a specific doc page
server.registerTool(
  'read_doc',
  {
    description: 'Fetch and read a specific Interfold documentation page by slug',
    inputSchema: z.object({ slug: z.string().describe("Page slug, e.g. 'learn', 'operate/running'") }),
  },
  async ({ slug }) => {
    const page = DOC_PAGES.find((p) => p.slug === slug)
    if (!page) {
      const available = DOC_PAGES.map((p) => p.slug).join(', ')
      return { content: [{ type: 'text', text: `Page "${slug}" not found. Available: ${available}` }], isError: true }
    }
    const content = await fetchDocPage(page.url)
    return { content: [{ type: 'text', text: `# ${page.title}\n\n${content}` }] }
  },
)

// Tool: search across all docs
server.registerTool(
  'search_docs',
  {
    description: 'Search for a keyword or phrase across all Interfold documentation pages',
    inputSchema: z.object({ query: z.string().describe('Search query') }),
  },
  async ({ query }) => {
    if (!query.trim()) {
      return { content: [{ type: 'text', text: 'Query must not be empty.' }], isError: true }
    }

    const lower = query.toLowerCase()
    const results: string[] = []
    const failures: string[] = []

    await Promise.all(
      DOC_PAGES.map(async (page) => {
        try {
          const content = await fetchDocPage(page.url)
          if (content.toLowerCase().includes(lower)) {
            const idx = content.toLowerCase().indexOf(lower)
            const start = Math.max(0, idx - 150)
            const end = Math.min(content.length, idx + 300)
            const snippet = content.slice(start, end).replace(/\n+/g, ' ').trim()
            results.push(`## ${page.title}\nURL: ${BASE_URL}${page.url}\n\n...${snippet}...`)
          }
        } catch {
          failures.push(`${page.title} (${page.url})`)
        }
      }),
    )

    const failureSummary = failures.length > 0 ? `\n\n---\n⚠️ Failed to load ${failures.length} page(s): ${failures.join(', ')}` : ''

    if (results.length === 0 && failures.length === DOC_PAGES.length) {
      return { content: [{ type: 'text', text: `All page fetches failed. Check network connectivity.${failureSummary}` }], isError: true }
    }

    if (results.length === 0) {
      return { content: [{ type: 'text', text: `No results found for "${query}".${failureSummary}` }] }
    }

    return {
      content: [
        {
          type: 'text',
          text: `Found ${results.length} page(s) matching "${query}":\n\n${results.join('\n\n---\n\n')}${failureSummary}`,
        },
      ],
    }
  },
)

// Tool: list all available doc pages
server.registerTool('list_docs', { description: 'List all available Interfold documentation pages' }, async () => {
  const list = DOC_PAGES.map((p) => `- **${p.title}** → slug: \`${p.slug}\``).join('\n')
  return { content: [{ type: 'text', text: `# Interfold Documentation Pages\n\n${list}` }] }
})

const transport = new StdioServerTransport()
await server.connect(transport)
