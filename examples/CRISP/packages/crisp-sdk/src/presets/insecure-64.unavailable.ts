// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CircuitBundle, CircuitPreset } from '../circuits'

export const preset: CircuitPreset = 'insecure-64'

export const loadCircuits = async (): Promise<CircuitBundle> => {
  throw new Error(
    'The insecure-64 circuits are not included in this @crisp-e3/sdk build. ' +
      'Install an SDK release channel that carries insecure-64.',
  )
}
