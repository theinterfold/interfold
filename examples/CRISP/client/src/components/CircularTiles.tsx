// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { memo, useState } from 'react'
import CircularTile from './CircularTile'

const generateRotations = (count: number) => [...Array(count)].map(() => [0, 90, 180, 270][Math.floor(Math.random() * 4)])

const CircularTiles = ({ count = 1, className }: { count?: number; className?: string }) => {
  const [rotations, setRotations] = useState(() => generateRotations(count))
  const [renderedCount, setRenderedCount] = useState(count)

  // Re-roll the rotations when the number of tiles changes, adjusting state
  // during render rather than in an effect.
  if (renderedCount !== count) {
    setRenderedCount(count)
    setRotations(generateRotations(count))
  }

  return (
    <>
      {rotations.map((rotation, index) => (
        <CircularTile key={index} className={className} rotation={rotation} />
      ))}
    </>
  )
}

export default memo(CircularTiles)
