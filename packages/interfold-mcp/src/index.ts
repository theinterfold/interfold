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
  { slug: 'introduction', title: 'Introduction', url: '/introduction' },
  { slug: 'what-is-e3', title: 'What is an E3?', url: '/what-is-e3' },
  { slug: 'architecture-overview', title: 'Architecture Overview', url: '/architecture-overview' },
  { slug: 'computation-flow', title: 'E3 Computation Flow', url: '/computation-flow' },
  { slug: 'use-cases', title: 'Use Cases', url: '/use-cases' },
  { slug: 'building-with-interfold', title: 'Building with Interfold', url: '/building-with-interfold' },
  { slug: 'best-practices', title: 'Best Practices', url: '/best-practices' },
  { slug: 'installation', title: 'Installation', url: '/installation' },
  { slug: 'quick-start', title: 'Quick Start', url: '/quick-start' },
  { slug: 'hello-world-tutorial', title: 'Hello World Tutorial', url: '/hello-world-tutorial' },
  { slug: 'project-template', title: 'Project Template', url: '/project-template' },
  { slug: 'sdk', title: 'Interfold SDK', url: '/sdk' },
  { slug: 'setting-up-server', title: 'Setting Up the Server', url: '/setting-up-server' },
  { slug: 'noir-circuits', title: 'Noir Circuits', url: '/noir-circuits' },
  { slug: 'getting-started', title: 'Getting Started (Build an E3)', url: '/getting-started' },
  { slug: 'write-secure-program', title: 'Writing the Secure Process', url: '/write-secure-program' },
  { slug: 'write-e3-contract', title: 'Writing the E3 Program Contract', url: '/write-e3-contract' },
  { slug: 'compute-provider', title: 'Compute Provider Setup', url: '/compute-provider' },
  { slug: 'putting-it-together', title: 'Putting It All Together', url: '/putting-it-together' },
  { slug: 'whitepaper', title: 'White Paper', url: '/whitepaper' },
  { slug: 'ciphernode-operators', title: 'Ciphernode Operators Overview', url: '/ciphernode-operators' },
  { slug: 'ciphernode-operators/running', title: 'Running a Ciphernode', url: '/ciphernode-operators/running' },
  { slug: 'ciphernode-operators/registration', title: 'Registration & Licensing', url: '/ciphernode-operators/registration' },
  { slug: 'ciphernode-operators/tickets-and-sortition', title: 'Tickets & Sortition', url: '/ciphernode-operators/tickets-and-sortition' },
  { slug: 'ciphernode-operators/exits-and-slashing', title: 'Exits, Rewards & Slashing', url: '/ciphernode-operators/exits-and-slashing' },
  { slug: 'CRISP/introduction', title: 'CRISP Introduction', url: '/CRISP/introduction' },
  { slug: 'CRISP/setup', title: 'CRISP Setup', url: '/CRISP/setup' },
  { slug: 'CRISP/running-e3', title: 'CRISP Running an E3 Program', url: '/CRISP/running-e3' },
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
    inputSchema: z.object({ slug: z.string().describe("Page slug, e.g. 'introduction', 'ciphernode-operators/running'") }),
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
