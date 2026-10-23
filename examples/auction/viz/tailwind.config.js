// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Tailwind carries layout and spacing; the colours are the CSS variables of `src/editorial.css`,
// so a utility (`text-ink-soft`) and a design class (`.note`) always agree.
const config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        serif: ['Source Serif 4', 'Source Serif Pro', 'Iowan Old Style', 'Georgia', 'serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        paper: { DEFAULT: 'var(--paper)', 2: 'var(--paper-2)' },
        card: 'var(--card)',
        ink: { DEFAULT: 'var(--ink)', 2: 'var(--ink-2)', soft: 'var(--ink-soft)' },
        rule: { DEFAULT: 'var(--rule)', strong: 'var(--rule-strong)' },
        accent: { DEFAULT: 'var(--accent)', tint: 'var(--accent-tint)', soft: 'var(--accent-soft)' },
        warm: { DEFAULT: 'var(--warm)', tint: 'var(--warm-tint)' },
        danger: { DEFAULT: 'var(--danger)', tint: 'var(--danger-tint)' },
      },
    },
  },
  plugins: [],
}
export default config
