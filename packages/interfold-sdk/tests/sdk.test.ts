// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'

import { InterfoldSDK } from '../src/interfold-sdk'
import { BFV_ENCRYPTION_SCHEME_ID, bfvPresetForParamSet } from '@interfold/contracts/bfv'
import { encodeAbiParameters, keccak256, stringToBytes, zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { generatePublicKey } from '../src/crypto'

describe('crypto configuration IDs', () => {
  it('uses the current circuit identity for every on-chain BFV parameter set', () => {
    const fixture = JSON.parse(
      readFileSync(new URL('../../../crates/bfv/params/tests/fixtures/bfv_protocol.json', import.meta.url), 'utf8'),
    )
    const current = fixture.vectors.filter((vector: { name: string }) => vector.name.startsWith('current-'))
    expect(current.map((vector: { paramSet: number }) => vector.paramSet).sort()).to.deep.equal([3, 4, 5, 6])
    for (const vector of current) {
      const preset = bfvPresetForParamSet(vector.paramSet)
      expect(preset).toBeDefined()
      const id = keccak256(
        encodeAbiParameters(
          [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
          [BFV_ENCRYPTION_SCHEME_ID as `0x${string}`, preset!.paramSetHash, keccak256(stringToBytes(vector.circuitVersion))],
        ),
      )
      expect(id).to.equal(vector.cryptoConfigId)
    }
  })
})

let publicKey: Uint8Array
beforeAll(async () => {
  publicKey = await generatePublicKey('INSECURE_THRESHOLD_64')
})

describe('encryptNumber', () => {
  describe('trbfv', () => {
    // create SDK with default config
    const sdk = InterfoldSDK.create({
      chain: hardhat,
      contracts: {
        interfold: zeroAddress,
        ciphernodeRegistry: zeroAddress,
        feeToken: zeroAddress,
      },
      rpcUrl: '',
      privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD_64',
    })

    it('should encrypt a number without crashing in a node environent', async () => {
      const value = await sdk.encryptNumber(10n, publicKey)
      expect(value).to.be.an.instanceof(Uint8Array)
      expect(value.length).to.equal(1_316)
      // TODO: test the encryption is correct
    })
    it('should encrypt a vector of numbers without crashing in a node environent', async () => {
      const value = await sdk.encryptVector(new BigUint64Array([1n, 2n]), publicKey)
      expect(value).to.be.an.instanceof(Uint8Array)
      expect(value.length).to.equal(1_316)
    })

    it('should validate a committee public key against its on-chain commitment', async () => {
      const commitment = await sdk.computePublicKeyCommitment(publicKey)

      expect(await sdk.validatePublicKeyCommitment(publicKey, commitment)).to.equal(true)

      const differentCommitment = commitment.slice()
      differentCommitment[0] ^= 1
      expect(await sdk.validatePublicKeyCommitment(publicKey, differentCommitment)).to.equal(false)
      expect(await sdk.validatePublicKeyCommitment(publicKey, new Uint8Array(31))).to.equal(false)
    })
  })
})
