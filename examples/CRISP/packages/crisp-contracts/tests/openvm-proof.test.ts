// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { network } from 'hardhat'

const names = ['OPENVM_TEST_IDENTITY', 'OPENVM_TEST_JOURNAL', 'OPENVM_TEST_VERIFIER', 'OPENVM_TEST_VERIFIER_SHA256'] as const
const enabled = names.every((name) => process.env[name]) && Boolean(process.env.OPENVM_TEST_PROOF || process.env.OPENVM_TEST_SEAL)
if (process.env.OPENVM_REQUIRE_PROOF_TEST === '1' && !enabled) {
  throw new Error(`Set ${names.join(', ')} and either OPENVM_TEST_PROOF or OPENVM_TEST_SEAL`)
}
;(enabled ? describe : describe.skip)('OpenVM real EVM proof', function () {
  this.timeout(300_000)
  it('accepts the proof and rejects changed journal words, identities, and proof bytes', async () => {
    const connection = await network.connect()
    expect(connection.networkConfig.type).to.equal('edr-simulated')
    const { ethers } = connection
    const [owner] = await ethers.getSigners()
    const json = (name: (typeof names)[number]) => JSON.parse(readFileSync(process.env[name]!, 'utf8'))
    const identity = json('OPENVM_TEST_IDENTITY')
    const commits = identity.app_commit ?? identity
    const journal = readFileSync(process.env.OPENVM_TEST_JOURNAL!)
    const artifact = readFileSync(process.env.OPENVM_TEST_VERIFIER!)
    expect(createHash('sha256').update(artifact).digest('hex')).to.equal(process.env.OPENVM_TEST_VERIFIER_SHA256)
    expect(journal.length).to.equal(288)
    const words = Array.from({ length: 9 }, (_, i) => ethers.hexlify(journal.subarray(i * 32, (i + 1) * 32)))
    const abi = ethers.AbiCoder.defaultAbiCoder()
    let data: string
    if (process.env.OPENVM_TEST_SEAL) {
      const encoded = ethers.hexlify(readFileSync(process.env.OPENVM_TEST_SEAL))
      const decoded = abi.decode(['uint8', 'bytes', 'bytes32[9]'], encoded)
      expect(decoded[0]).to.equal(1n)
      expect(Array.from(decoded[2])).to.deep.equal(words)
      data = decoded[1]
      expect(abi.encode(['uint8', 'bytes', 'bytes32[9]'], [1, data, words])).to.equal(encoded)
    } else {
      const proof = JSON.parse(readFileSync(process.env.OPENVM_TEST_PROOF!, 'utf8'))
      expect(proof.app_exe_commit).to.equal(commits.app_exe_commit)
      expect(proof.app_vm_commit).to.equal(commits.app_vm_commit)
      expect(proof.user_public_values).to.equal(ethers.sha256(journal))
      data = ethers.concat([proof.proof_data.accumulator, proof.proof_data.proof])
    }
    const halo2 = await new ethers.ContractFactory(
      ['function verify(bytes,bytes,bytes32,bytes32) view'],
      `0x${JSON.parse(artifact.toString()).bytecode}`,
      owner,
    ).deploy()
    await halo2.waitForDeployment()
    const receipt = await ethers.deployContract('OpenVmReceiptVerifier', [
      await halo2.getAddress(),
      commits.app_exe_commit,
      commits.app_vm_commit,
    ])
    const seal = (values = words, bytes = data) => abi.encode(['uint8', 'bytes', 'bytes32[9]'], [1, bytes, values])
    const digest = (values = words) => ethers.sha256(abi.encode(['bytes32[9]'], [values]))
    const imageId = await receipt.imageId()
    await expect(receipt.verify(seal(), imageId, digest())).not.to.revert(ethers)
    const protocol = await ethers.deployContract('OpenVmBfvCiphertextVerifier', [await receipt.getAddress(), imageId])
    expect(BigInt(words[0])).to.equal((await ethers.provider.getNetwork()).chainId)
    const envelope = abi.encode(['bytes', 'bytes32', 'bytes32'], [seal(), words[7], words[8]])
    const result = await ethers.provider.call({
      to: protocol.target,
      from: ethers.getAddress(ethers.dataSlice(words[1], 12)),
      data: protocol.interface.encodeFunctionData('verify', [BigInt(words[2]), words[3], words[7], words[4], words[5], words[6], envelope]),
    })
    expect(abi.decode(['bool'], result)[0]).to.equal(true)
    for (let i = 0; i < words.length; i++) {
      const changed = [...words]
      changed[i] = ethers.zeroPadValue(ethers.toBeHex(BigInt(changed[i]) ^ 1n), 32)
      await expect(receipt.verify(seal(changed), imageId, digest(changed))).to.revert(ethers)
    }
    const changed = ethers.getBytes(data)
    changed[changed.length - 1] ^= 1
    await expect(receipt.verify(seal(words, ethers.hexlify(changed)), imageId, digest())).to.revert(ethers)
    for (const field of ['app_exe_commit', 'app_vm_commit'] as const) {
      const other = { ...commits, [field]: ethers.zeroPadValue(ethers.toBeHex(BigInt(commits[field]) ^ 1n), 32) }
      const wrong = await ethers.deployContract('OpenVmReceiptVerifier', [
        await halo2.getAddress(),
        other.app_exe_commit,
        other.app_vm_commit,
      ])
      await expect(wrong.verify(seal(), await wrong.imageId(), digest())).to.revert(ethers)
    }
  })
})
