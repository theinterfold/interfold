// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { beforeAll, describe, expect, it } from 'vitest'

import { InterfoldSDK } from '../src/interfold-sdk'
import { cryptoConfigIdForParamSet } from '../src/utils'
import { zeroAddress } from 'viem'
import { hardhat } from 'viem/chains'
import { generatePublicKey, encryptNumber as standaloneEncryptNumber, encryptVector as standaloneEncryptVector } from '../src/crypto'

describe('crypto configuration IDs', () => {
  it('uses the v2 circuit identity for every BFV parameter set', () => {
    expect(cryptoConfigIdForParamSet(0)).to.equal('0x353ab90c0ebe9c13e1b9c2048539b7c2872f3eb12a9f1957f31410aa4bf44718')
    expect(cryptoConfigIdForParamSet(2)).to.equal('0x5ebb3432396f21cd97fca47e006b9dd38c021bf2902d3e555cf74cb91b28e44e')
    expect(cryptoConfigIdForParamSet(3)).to.equal('0x9c5c09ac7421582c4407c7e6ad923b8f9126aa708957c2575760fb0a38153655')
  })
})

let publicKey: Uint8Array
beforeAll(async () => {
  publicKey = await generatePublicKey('INSECURE_THRESHOLD')
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
      thresholdBfvParamsPresetName: 'INSECURE_THRESHOLD',
    })

    it('should encrypt a number without crashing in a node environent', async () => {
      const value = await sdk.encryptNumber(10n, publicKey)
      expect(value).to.be.an.instanceof(Uint8Array)
      expect(value.length).to.equal(5_398)
      // TODO: test the encryption is correct
    })
    it('should encrypt a vector of numbers without crashing in a node environent', async () => {
      const value = await sdk.encryptVector(new BigUint64Array([1n, 2n]), publicKey)
      expect(value).to.be.an.instanceof(Uint8Array)
      expect(value.length).to.equal(5_398)
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
      const ct = await standaloneEncryptNumber(10n, publicKey, 'INSECURE_THRESHOLD')
      expect(ct).to.be.an.instanceof(Uint8Array)
      expect(ct.length).to.equal(5_398)
    })

    it('should encrypt a vector using standalone functions', async () => {
      const ct = await standaloneEncryptVector(new BigUint64Array([1n, 2n]), publicKey, 'INSECURE_THRESHOLD')
      expect(ct).to.be.an.instanceof(Uint8Array)
      expect(ct.length).to.equal(5_398)
    })
  })
})
