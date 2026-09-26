// SPDX-License-Identifier: LGPL-3.0-only

import assert from 'node:assert/strict'
import test from 'node:test'
import { VerifierGenerator } from './generate-verifiers'

// `check:verifiers` must fail when a requested circuit is not discovered, instead of checking less.
test('verifier generation rejects a requested circuit it cannot find', async () => {
  const generator = new VerifierGenerator(undefined, { dryRun: true, circuits: ['dkg_aggregator', 'no_such_circuit'] })
  await assert.rejects(generator.generate(), /Cannot find requested circuits: no_such_circuit/)
})
