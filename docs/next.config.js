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

module.exports = withNextra({
  webpack: (config) => {
    // Nextra v2 skips addContextDependency in production, so webpack reuses
    // cached MDX compilations when only _meta.json changes. Disabling the
    // cache forces a full recompile on every build.
    config.cache = false
    return config
  },
  async redirects() {
    return [
      {
        source: '/',
        destination: '/introduction',
        permanent: false,
      },
    ]
  },
})
