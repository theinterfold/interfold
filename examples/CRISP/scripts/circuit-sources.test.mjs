// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import assert from 'node:assert/strict'
import test from 'node:test'

import { isCircuitSourceFile } from './circuit-sources.mjs'

test('circuit source digest excludes generated witness TOML files', () => {
  assert.equal(isCircuitSourceFile('Prover.toml'), false)
  assert.equal(isCircuitSourceFile('Witness.toml'), false)
})

test('circuit source digest includes circuit code and Nargo manifests', () => {
  assert.equal(isCircuitSourceFile('main.nr'), true)
  assert.equal(isCircuitSourceFile('Nargo.toml'), true)
})

test('legacy digest can include witness TOML files for safe stamp migration', () => {
  assert.equal(isCircuitSourceFile('Prover.toml', true), true)
  assert.equal(isCircuitSourceFile('Witness.toml', true), true)
})
