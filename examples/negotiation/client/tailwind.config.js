// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Tailwind carries layout and spacing; the values are the Interfold governance tokens of
// `src/design/tokens.css`, so a utility (`text-muted`) and a design class (`.note`) always agree.
// Both demo clients carry this file unchanged.
const config = {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx,mdx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-sans)'],
        serif: ['var(--font-serif)'],
        mono: ['var(--font-mono)'],
      },
      colors: {
        ink: 'var(--ink)',
        paper: 'var(--paper)',
        muted: { DEFAULT: 'var(--muted)', 2: 'var(--muted-2)' },
        surface: { muted: 'var(--surface-muted)', selected: 'var(--surface-selected)', hover: 'var(--surface-hover)' },
        rule: { DEFAULT: 'var(--rule)', strong: 'var(--rule-strong)' },
        brand: { green: 'var(--if-brand-green)', mint: 'var(--mint)', 'mint-pale': 'var(--mint-pale)', 'mint-line': 'var(--mint-line)' },
        vote: 'var(--vote-action)',
        negative: { DEFAULT: 'var(--negative)', tint: 'var(--status-bad-bg)' },
        warn: { DEFAULT: 'var(--status-warn-fg)', tint: 'var(--status-warn-bg)' },
      },
      borderRadius: {
        DEFAULT: 'var(--ui-radius)',
        ui: 'var(--ui-radius)',
      },
      spacing: {
        tight: 'var(--ui-space-tight)',
        related: 'var(--ui-space-related)',
        controls: 'var(--ui-space-controls)',
        section: 'var(--ui-space-section)',
      },
      maxWidth: {
        content: 'var(--site-content-width)',
      },
      minHeight: {
        action: 'var(--action-height)',
      },
      transitionDuration: {
        ui: 'var(--if-ui-duration)',
        page: 'var(--if-page-duration)',
      },
      transitionTimingFunction: {
        ui: 'var(--if-ui-ease)',
        page: 'var(--if-page-ease)',
      },
    },
  },
  plugins: [],
}
export default config
