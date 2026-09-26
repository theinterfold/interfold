// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React, { ReactNode } from 'react'
import classes from './ui.module.css'

export type BadgeTone = 'mainnet' | 'testnet' | 'local' | 'new' | 'warning' | 'neutral'

/** Inline status label, for example the network that a value applies to. */
export function Badge({ tone = 'neutral', children }: { tone?: BadgeTone; children: ReactNode }) {
  return <span className={`${classes.badge} ${classes[`badge_${tone}`]}`}>{children}</span>
}
