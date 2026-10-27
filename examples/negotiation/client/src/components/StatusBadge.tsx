// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import React from 'react'
import { type NegotiationPhase, PHASE_LABELS } from '@/utils/negotiation'

const TONES: Record<NegotiationPhase, string> = {
  'awaiting-key': 'wait',
  offers: 'live dot',
  computing: 'muted',
  decrypting: 'muted',
  settling: 'wait',
  settled: 'done',
  incomplete: 'bad',
  failed: 'bad',
}

const StatusBadge: React.FC<{ phase: NegotiationPhase }> = ({ phase }) => (
  <span className={`tag ${TONES[phase]}`}>{PHASE_LABELS[phase]}</span>
)

export default StatusBadge
