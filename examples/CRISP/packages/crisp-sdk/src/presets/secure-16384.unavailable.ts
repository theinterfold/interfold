// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CircuitBundle, CircuitPreset } from '../circuits'

export const preset: CircuitPreset = 'secure-16384'

export const loadCircuits = async (): Promise<CircuitBundle> => {
  throw new Error(
    'The secure-16384 circuits are not included in this @crisp-e3/sdk build. ' +
      'Install the production @crisp-e3/sdk release from the latest npm tag.',
  )
}
