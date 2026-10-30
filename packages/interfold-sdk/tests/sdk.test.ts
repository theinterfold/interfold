// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'

import { InterfoldSDK } from '../src/interfold-sdk'
import { cryptoConfigIdForParamSet } from '../src/utils'
import { zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { generatePublicKey, encryptNumber as standaloneEncryptNumber, encryptVector as standaloneEncryptVector } from '../src/crypto'

describe('crypto configuration IDs', () => {
  it('uses the current circuit identity for every on-chain BFV parameter set', () => {
    const fixture = JSON.parse(
      readFileSync(new URL('../../../crates/fhe-params/tests/fixtures/bfv_protocol.json', import.meta.url), 'utf8'),
    )
    const current = fixture.vectors.filter((vector: { name: string }) => vector.name.startsWith('current-'))
    expect(current.map((vector: { paramSet: number }) => vector.paramSet).sort()).to.deep.equal([0, 2, 3, 4])
    for (const vector of current) {
      expect(cryptoConfigIdForParamSet(vector.paramSet)).to.equal(vector.cryptoConfigId)
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

    it('should compute a SAFE commitment for encrypted data', async () => {
      const ciphertext = await sdk.encryptNumber(10n, publicKey)
      const commitment = await sdk.computeCiphertextCommitment(ciphertext)

      expect(commitment).to.be.an.instanceof(Uint8Array)
      expect(commitment.length).to.equal(32)
    })
  })

  describe('standalone encryption (no blockchain setup)', () => {
    it('should encrypt a number using standalone functions', async () => {
      const ct = await standaloneEncryptNumber(10n, publicKey, 'INSECURE_THRESHOLD_64')
      expect(ct).to.be.an.instanceof(Uint8Array)
      expect(ct.length).to.equal(1_316)
    })

    it('should encrypt a vector using standalone functions', async () => {
      const ct = await standaloneEncryptVector(new BigUint64Array([1n, 2n]), publicKey, 'INSECURE_THRESHOLD_64')
      expect(ct).to.be.an.instanceof(Uint8Array)
      expect(ct.length).to.equal(1_316)
    })
  })
})
