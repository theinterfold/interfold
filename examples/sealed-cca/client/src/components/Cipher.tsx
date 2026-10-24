// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { useMemo } from 'react'

const HEX = '0123456789abcdef'

/** A deterministic-looking hex blob: what a ciphertext looks like. Purely decorative. */
const Cipher: React.FC<{ seed?: number; length?: number; blockSize?: number }> = ({ seed = 7, length = 256, blockSize = 4 }) => {
  const blocks = useMemo(() => {
    let state = seed + length
    let hex = ''
    for (let i = 0; i < length; i++) {
      state = (state * 16807 + 7) % 2147483647
      hex += HEX[state & 15]
    }
    const out: string[] = []
    for (let i = 0; i < length; i += blockSize) out.push(hex.slice(i, i + blockSize))
    return out
  }, [seed, length, blockSize])

  return (
    <span className='cipher' aria-hidden>
      {blocks.map((block, index) => (
        <span key={index} className={`blk ${index % 9 === 0 ? 'hot' : ''}`} style={{ animationDelay: `${index * 16}ms` }}>
          {block}
          {index < blocks.length - 1 ? ' ' : ''}
        </span>
      ))}
    </span>
  )
}

export default Cipher
