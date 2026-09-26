// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// eslint-disable-next-line @typescript-eslint/no-require-imports
const nextra = require('nextra')

const withNextra = nextra({
  theme: 'nextra-theme-docs',
  themeConfig: './theme.config.jsx',
  latex: true,
})

// Pages that moved when the docs were grouped into Learn, Build, Operate, and Reference.
// External sites, released CLI versions, and the docs MCP server still use the old paths.
// Keep each entry. Remove an entry only when no published artifact can link to it.
const MOVED_PAGES = {
  '/introduction': '/learn',
  '/what-is-e3': '/learn/what-is-e3',
  '/architecture-overview': '/learn/architecture',
  '/computation-flow': '/learn/e3-lifecycle',
  '/cryptography': '/learn/cryptography',
  '/use-cases': '/learn/use-cases',
  '/installation': '/build/installation',
  '/quick-start': '/build/quick-start',
  '/hello-world-tutorial': '/build/hello-world',
  '/project-template': '/build/project-template',
  '/getting-started': '/build/e3-program',
  '/write-secure-program': '/build/e3-program/secure-process',
  '/write-e3-contract': '/build/e3-program/program-contract',
  '/compute-provider': '/build/e3-program/compute-provider',
  '/verifying-the-compute-provider': '/build/e3-program/verify-compute-provider',
  '/putting-it-together': '/build/e3-program/complete-example',
  '/building-with-interfold': '/build/interfold-contract',
  '/requestor-guide': '/build/requesting-an-e3',
  '/sdk': '/build/sdk',
  '/setting-up-server': '/build/client-and-server',
  '/noir-circuits': '/build/noir-circuits',
  '/best-practices': '/build/best-practices',
  '/tutorials/write-e3-program': '/build/tutorials/write-e3-program',
  '/tutorials/custom-zk-circuits': '/build/tutorials/custom-zk-circuits',
  '/tutorials/encrypt-and-submit': '/build/tutorials/encrypt-and-submit',
  '/tutorials/deploy-to-testnet': '/build/tutorials/deploy-to-testnet',
  '/tutorials/using-the-dashboard': '/operate/dashboard',
  '/tutorials/manage-tickets': '/operate/manage-tickets',
  '/tutorials/operator-troubleshooting': '/operate/troubleshooting',
  '/requirements': '/operate/requirements',
  '/ciphernode-operators': '/operate',
  '/ciphernode-operators/:page': '/operate/:page',
}

module.exports = withNextra({
  webpack: (config) => {
    // Nextra v2 skips addContextDependency in production, so webpack reuses
    // cached MDX compilations when only _meta.json changes. Disabling the
    // cache forces a full recompile on every build.
    config.cache = false
    return config
  },
  async redirects() {
    return Object.entries(MOVED_PAGES).map(([source, destination]) => ({
      source,
      destination,
      permanent: true,
    }))
  },
})
