// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'

// Stroke icons on a 24 × 24 grid. Each entry is the inner SVG markup.
const PATHS = {
  arrow: <path d='M5 12h14M13 6l6 6-6 6' />,
  book: (
    <>
      <path d='M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5z' />
      <path d='M4 20.5A2.5 2.5 0 0 0 6.5 23H20v-5' />
    </>
  ),
  build: (
    <>
      <path d='m14.7 6.3 3-3a4 4 0 0 1-5.4 5.4l-6.6 6.6a1.9 1.9 0 1 1-2.7-2.7l6.6-6.6a4 4 0 0 1 5.1-5.1z' />
    </>
  ),
  chip: (
    <>
      <rect x='6' y='6' width='12' height='12' rx='2' />
      <path d='M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4' />
    </>
  ),
  circuit: (
    <>
      <circle cx='6' cy='6' r='2' />
      <circle cx='18' cy='18' r='2' />
      <circle cx='18' cy='6' r='2' />
      <path d='M8 6h8M18 8v8M6 8v4a6 6 0 0 0 6 6h4' />
    </>
  ),
  coin: (
    <>
      <circle cx='12' cy='12' r='9' />
      <path d='M15 9.5c-.5-1-1.6-1.5-3-1.5-1.7 0-3 .9-3 2s1 1.7 3 2 3 .9 3 2-1.3 2-3 2c-1.4 0-2.5-.5-3-1.5M12 6v2M12 16v2' />
    </>
  ),
  contract: (
    <>
      <path d='M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z' />
      <path d='M14 3v5h5M9 13h6M9 17h4' />
    </>
  ),
  dashboard: (
    <>
      <rect x='3' y='3' width='8' height='8' rx='1.5' />
      <rect x='13' y='3' width='8' height='5' rx='1.5' />
      <rect x='13' y='10' width='8' height='11' rx='1.5' />
      <rect x='3' y='13' width='8' height='8' rx='1.5' />
    </>
  ),
  eye: (
    <>
      <path d='M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z' />
      <circle cx='12' cy='12' r='3' />
    </>
  ),
  flow: (
    <>
      <rect x='3' y='4' width='6' height='6' rx='1.5' />
      <rect x='15' y='14' width='6' height='6' rx='1.5' />
      <path d='M9 7h4a3 3 0 0 1 3 3v4' />
    </>
  ),
  gavel: (
    <>
      <path d='m14 13-8.5 8.5a2.1 2.1 0 0 1-3-3L11 10' />
      <path d='m16 16 6-6M8 8l6-6M9 7l8 8M21 11l-8-8' />
    </>
  ),
  key: (
    <>
      <circle cx='7.5' cy='15.5' r='4.5' />
      <path d='m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2' />
    </>
  ),
  layers: (
    <>
      <path d='m12 2 10 5-10 5L2 7z' />
      <path d='m2 12 10 5 10-5M2 17l10 5 10-5' />
    </>
  ),
  lock: (
    <>
      <rect x='4' y='11' width='16' height='10' rx='2' />
      <path d='M8 11V7a4 4 0 0 1 8 0v4' />
    </>
  ),
  network: (
    <>
      <circle cx='12' cy='5' r='2.5' />
      <circle cx='5' cy='18' r='2.5' />
      <circle cx='19' cy='18' r='2.5' />
      <path d='M10.8 7.2 6.2 15.8M13.2 7.2l4.6 8.6M7.5 18h9' />
    </>
  ),
  node: (
    <>
      <rect x='3' y='4' width='18' height='7' rx='2' />
      <rect x='3' y='13' width='18' height='7' rx='2' />
      <path d='M7 7.5h.01M7 16.5h.01' />
    </>
  ),
  rocket: (
    <>
      <path d='M4.5 16.5c-1.5 1.3-2 5-2 5s3.7-.5 5-2c.7-.8.7-2.1-.1-2.9a2.2 2.2 0 0 0-2.9-.1z' />
      <path d='m12 15-3-3a22 22 0 0 1 2-3.9A12.9 12.9 0 0 1 22 2c0 2.7-.8 7.5-6 11a22.4 22.4 0 0 1-4 2z' />
      <path d='M9 12H4s.6-3 2-4c1.6-1.1 5 0 5 0M12 15v5s3-.6 4-2c1.1-1.6 0-5 0-5' />
    </>
  ),
  shield: (
    <>
      <path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' />
      <path d='m9 12 2 2 4-4' />
    </>
  ),
  sparkle: (
    <>
      <path d='M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8' />
    </>
  ),
  terminal: (
    <>
      <rect x='2' y='4' width='20' height='16' rx='2' />
      <path d='m6 9 3 3-3 3M12 15h6' />
    </>
  ),
  ticket: (
    <>
      <path d='M3 8a2 2 0 0 0 2-2h14a2 2 0 0 0 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 0-2 2H5a2 2 0 0 0-2-2v-2a2 2 0 0 0 0-4z' />
      <path d='M13 6v2M13 11v2M13 16v2' />
    </>
  ),
  upgrade: (
    <>
      <path d='M12 19V5M5 12l7-7 7 7' />
      <path d='M5 21h14' />
    </>
  ),
  vote: (
    <>
      <path d='m9 12 2 2 4-4' />
      <path d='M5 7V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2' />
      <rect x='3' y='7' width='18' height='14' rx='2' />
    </>
  ),
  wrench: (
    <>
      <path d='M14.7 6.3a4 4 0 0 0 5 5L22 14l-8 8-2.3-2.3a4 4 0 0 0-5-5L2 10l8-8z' />
    </>
  ),
} as const

export type IconName = keyof typeof PATHS

export function Icon({ name, size = 20, strokeWidth = 1.7 }: { name: IconName; size?: number; strokeWidth?: number }) {
  const path = PATHS[name] ?? PATHS.sparkle
  return (
    <svg
      width={size}
      height={size}
      viewBox='0 0 24 24'
      fill='none'
      stroke='currentColor'
      strokeWidth={strokeWidth}
      strokeLinecap='round'
      strokeLinejoin='round'
      aria-hidden='true'
      focusable='false'
    >
      {path}
    </svg>
  )
}
