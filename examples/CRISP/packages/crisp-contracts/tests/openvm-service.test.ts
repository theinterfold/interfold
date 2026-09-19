// SPDX-License-Identifier: LGPL-3.0-only

import { expect } from 'chai'
import { createHash } from 'node:crypto'
import { spawn, type ChildProcess } from 'node:child_process'
import { createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

const enabled = process.env.OPENVM_E2E_ENABLED === '1'
const required = [
  'LOCAL_RPC_URL',
  'OPENVM_E2E_FIXTURE',
  'OPENVM_E2E_SERVER',
  'OPENVM_E2E_OUTPUT',
  'OPENVM_E2E_PROGRAM_URL',
  'OPENVM_E2E_CALLBACK_URL',
  'OPENVM_TEST_IDENTITY',
  'OPENVM_TEST_VERIFIER',
  'OPENVM_TEST_VERIFIER_SHA256',
] as const
if (enabled) {
  for (const name of required) if (!process.env[name]) throw new Error(`Set ${name}`)
  const rpc = new URL(process.env.LOCAL_RPC_URL!)
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(rpc.hostname)) throw new Error('The service test requires a loopback RPC')
}

;(enabled ? describe : describe.skip)('OpenVM live CRISP compute flow', function () {
  this.timeout(4 * 60 * 60 * 1000)

  it('dispatches indexed ballots over HTTP and automatically publishes a newly generated proof', async () => {
    const { connection, ethers, networkHelpers } = await import('../../../../../packages/interfold-contracts/test/fixtures/connection')
    expect(connection.networkConfig.type).to.equal('http')
    expect((await ethers.provider.getNetwork()).chainId).to.equal(31337n)
    const { deployInterfoldSystem } = await import('../../../../../packages/interfold-contracts/test/fixtures/system')
    const { buildMockDkgAttestationFixtureData } = await import('../../../../../packages/interfold-contracts/test/fixtures/dkgAttestation')
    const { BFV_PARAMS_SECURE, PRODUCTION_CRYPTO_CONFIG_ID, ENCRYPTION_SCHEME_ID } = await import(
      '../../../../../packages/interfold-contracts/test/fixtures/constants'
    )
    const { time } = networkHelpers
    const abi = ethers.AbiCoder.defaultAbiCoder()
    const directory = path.resolve(process.env.OPENVM_E2E_OUTPUT!)
    if (existsSync(directory)) throw new Error('The service-test output directory must not already exist')
    mkdirSync(directory, { recursive: true })
    const fixtureDirectory = path.resolve(process.env.OPENVM_E2E_FIXTURE!)
    const fixture = JSON.parse(readFileSync(path.join(fixtureDirectory, 'fixture.json'), 'utf8'))
    expect(fixture.params).to.equal(BFV_PARAMS_SECURE)
    expect(fixture.native_tally_checked).to.equal(true)
    const identity = JSON.parse(readFileSync(process.env.OPENVM_TEST_IDENTITY!, 'utf8'))
    const commits = identity.app_commit ?? identity
    const verifierBytes = readFileSync(process.env.OPENVM_TEST_VERIFIER!)
    expect(createHash('sha256').update(verifierBytes).digest('hex')).to.equal(process.env.OPENVM_TEST_VERIFIER_SHA256)
    const report: Record<string, unknown> = {
      started_at: new Date().toISOString(),
      input_count: fixture.inputs.length,
      preset: fixture.preset,
      network: 'local-http-evm',
      status: 'deploying',
      real_compute_proof_verified: false,
      callback_http_delivery_tested: false,
      automatic_ciphertext_publication: false,
      production_deployment: false,
      mocked_dependencies: [
        'randomness',
        'DKG proof',
        'DKG fold attestations',
        'ballot proofs and census',
        'data availability',
        'threshold decryption proof',
      ],
    }
    const save = (status: string, fields: Record<string, unknown> = {}) => {
      Object.assign(report, fields, { status, updated_at: new Date().toISOString() })
      writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report, null, 2))
      console.log(`OpenVM service round: ${status}`)
    }
    let server: ChildProcess | undefined
    const log = createWriteStream(path.join(directory, 'crisp-server.log'))
    const localServer = new URL(process.env.OPENVM_E2E_LOCAL_SERVER_URL ?? 'http://127.0.0.1:14000')
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(localServer.hostname)) throw new Error('The CRISP test listener must use loopback')
    async function waitFor(label: string, check: () => Promise<boolean>, timeoutMs = 120_000) {
      const end = Date.now() + timeoutMs
      let last: unknown
      while (Date.now() < end) {
        if (server && server.exitCode !== null) throw new Error(`CRISP exited with ${server.exitCode}; see crisp-server.log`)
        try {
          if (await check()) return
        } catch (error) {
          last = error
        }
        await delay(1000)
      }
      throw new Error(`Timed out waiting for ${label}${last ? `: ${last}` : ''}`)
    }
    const post = (route: string, body: unknown) =>
      fetch(new URL(route, localServer), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      })
    try {
      const health = await fetch(new URL('/health', process.env.OPENVM_E2E_PROGRAM_URL!), { signal: AbortSignal.timeout(30_000) })
      expect(health.ok).to.equal(true)
      const system = await deployInterfoldSystem({
        deploymentId: `openvm-service-${Date.now()}`,
        timeoutConfig: { dkgWindow: 3600, computeWindow: 21600, decryptionWindow: 3600 },
      })
      const { owner, operators, interfold, ciphernodeRegistry: registry, usdcToken } = system
      const relay = ethers.Wallet.createRandom().connect(ethers.provider)
      await (await owner.sendTransaction({ to: relay.address, value: ethers.parseEther('100') })).wait()
      const halo2 = await new ethers.ContractFactory(
        ['function verify(bytes,bytes,bytes32,bytes32) view'],
        `0x${JSON.parse(verifierBytes.toString()).bytecode}`,
        owner,
      ).deploy()
      await halo2.waitForDeployment()
      const receipt = await ethers.deployContract('OpenVmReceiptVerifier', [
        await halo2.getAddress(),
        commits.app_exe_commit,
        commits.app_vm_commit,
      ])
      const identityId = await receipt.imageId()
      const protocol = await ethers.deployContract('OpenVmBfvCiphertextVerifier', [await receipt.getAddress(), identityId])
      const honk = await ethers.deployContract('MockHonkVerifier')
      const availability = await ethers.deployContract('MockCrispDataAvailabilityVerifier')
      const poseidon = await ethers.deployContract('PoseidonT3')
      const program = await (
        await ethers.getContractFactory('CRISPProgram', {
          libraries: { 'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': await poseidon.getAddress() },
        })
      ).deploy(
        relay.address,
        await receipt.getAddress(),
        await honk.getAddress(),
        await honk.getAddress(),
        await availability.getAddress(),
        0,
        relay.address,
        identityId,
      )
      await (await interfold.registerE3Program(await program.getAddress())).wait()
      await (await program.connect(relay).bindInterfold(await interfold.getAddress())).wait()
      await (await interfold.setParamSet(1, BFV_PARAMS_SECURE)).wait()
      await (await interfold.setCiphertextVerifier(ENCRYPTION_SCHEME_ID, await protocol.getAddress())).wait()
      const rpc = process.env.LOCAL_RPC_URL!
      server = spawn(path.resolve(process.env.OPENVM_E2E_SERVER!), [], {
        cwd: directory,
        env: {
          PATH: process.env.PATH,
          RUST_LOG: 'info',
          RUST_BACKTRACE: '1',
          PRIVATE_KEY: relay.privateKey,
          INTERFOLD_SERVER_URL: process.env.OPENVM_E2E_CALLBACK_URL!,
          CRISP_BIND_ADDR: `${localServer.hostname}:${localServer.port}`,
          PROGRAM_SERVER_URL: process.env.OPENVM_E2E_PROGRAM_URL!,
          HTTP_RPC_URL: rpc,
          WS_RPC_URL: rpc.replace(/^http/, 'ws'),
          CHAIN_ID: '31337',
          INTERFOLD_ADDRESS: await interfold.getAddress(),
          E3_PROGRAM_ADDRESS: await program.getAddress(),
          CIPHERNODE_REGISTRY_ADDRESS: await registry.getAddress(),
          FEE_TOKEN_ADDRESS: await usdcToken.getAddress(),
          DATA_AVAILABILITY_MODE: 'mock',
          E3_PARAM_SET: '1',
          E3_COMMITTEE_SIZE: '0',
          E3_DURATION: '3600',
          E3_COMPUTE_PROVIDER_NAME: 'OpenVM',
          E3_COMPUTE_PROVIDER_PARALLEL: 'false',
          E3_COMPUTE_PROVIDER_BATCH_SIZE: '1',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      server.stdout!.pipe(log, { end: false })
      server.stderr!.pipe(log, { end: false })
      server.once('error', (error) => log.write(`Server spawn failed: ${error}\n`))
      await waitFor('CRISP listener', async () => {
        await fetch(localServer, { signal: AbortSignal.timeout(2000) })
        return true
      })
      await delay(2000)
      const start = Number(await time.latest()) + 60
      const end = start + 3600
      const request: typeof system.request = {
        ...system.request,
        e3Program: await program.getAddress(),
        inputWindow: [start, end],
        paramSet: 1,
        expectedCryptoConfigId: PRODUCTION_CRYPTO_CONFIG_ID,
        customParams: abi.encode(
          ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
          [ethers.ZeroAddress, 0, 2, 0, 3, 0, 1],
        ),
      }
      const e3Id = await interfold.nexte3Id()
      const fee = await interfold.getE3Quote(request)
      await (await usdcToken.approve(await interfold.getAddress(), fee)).wait()
      await (await interfold.request({ ...request, maxFee: fee })).wait()
      save('committee setup', {
        e3_id: e3Id.toString(),
        interfold: await interfold.getAddress(),
        program: await program.getAddress(),
        relay: relay.address,
        receipt_verifier: await receipt.getAddress(),
        protocol_verifier: await protocol.getAddress(),
        halo2_verifier: await halo2.getAddress(),
      })
      await time.increase(1)
      for (const operator of operators) await (await registry.connect(operator).submitTicket(e3Id, 1)).wait()
      await time.setNextBlockTimestamp((await registry.getCommitteeDeadline(e3Id)) + 1n)
      await (await registry.finalizeCommittee(e3Id)).wait()
      const keyCommitment = fixture.public_key_commitment
      const dkg = await buildMockDkgAttestationFixtureData(
        operators,
        e3Id,
        keyCommitment,
        await registry.dkgFoldAttestationVerifier(),
        await registry.getAddress(),
      )
      await (await registry.publishCommittee(e3Id, keyCommitment, dkg.proof, dkg.bundle)).wait()
      const publicKey = readFileSync(path.join(fixtureDirectory, 'public-key.bin'))
      const chunkSize = 90 * 1024
      for (let i = 0; i < Math.ceil(publicKey.length / chunkSize); i++) {
        await (
          await registry
            .connect(operators[0])
            .publishCommitteePublicKey(
              e3Id,
              ethers.keccak256(publicKey),
              i,
              Math.ceil(publicKey.length / chunkSize),
              publicKey.length,
              publicKey.subarray(i * chunkSize, (i + 1) * chunkSize),
            )
        ).wait()
      }
      await waitFor('indexed round and validated committee key', async () => (await post('/state/lite', { round_id: e3Id.toString() })).ok)
      await waitFor('server census publication', async () => (await program.getRoundData(e3Id)).merkleRoot !== 0n)
      if (Number(await time.latest()) < start) await time.increaseTo(start)
      save('submitting ballots through CRISP HTTP')
      for (const entry of fixture.inputs) {
        const bytes = readFileSync(path.join(fixtureDirectory, entry.file))
        expect(ethers.keccak256(bytes)).to.equal(entry.content_hash)
        const encoded = abi.encode(
          ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'bytes'],
          ['0x01', entry.slot, entry.commitment, entry.content_hash, entry.parent_index_plus_one, bytes],
        )
        let response = await post('/voting/broadcast', { round_id: e3Id.toString(), encoded_proof: encoded })
        while (response.status === 429) {
          await delay(10_000)
          response = await post('/voting/broadcast', { round_id: e3Id.toString(), encoded_proof: encoded })
        }
        const body = await response.text()
        expect(response.ok, body).to.equal(true)
        await waitFor(`input ${entry.index} finalization`, async () =>
          program.isInputPublished(e3Id, entry.content_hash, entry.commitment, entry.slot, entry.parent_index_plus_one),
        )
        if ((entry.index + 1) % 10 === 0) save('submitting ballots through CRISP HTTP', { finalized_inputs: entry.index + 1 })
      }
      const round = await program.getRoundData(e3Id)
      expect(round.numberOfVotes).to.equal(BigInt(fixture.inputs.length))
      expect(ethers.zeroPadValue(ethers.toBeHex(round.inputRoot), 32)).to.equal(fixture.input_root)
      expect(await program.pendingInputCount(e3Id)).to.equal(0n)
      const proofStarted = Date.now()
      await time.increaseTo(end + 1)
      save('waiting for live OpenVM computation and callback', {
        input_root: fixture.input_root,
        compute_started_at: new Date().toISOString(),
      })
      await waitFor(
        'automatic ciphertext publication',
        async () => {
          await ethers.provider.send('evm_mine', [])
          return (await interfold.getE3Stage(e3Id)) === 4n
        },
        3 * 60 * 60 * 1000,
      )
      const output = await interfold.getE3(e3Id)
      expect(output.ciphertextOutput).to.equal(fixture.ciphertext_hash)
      expect(output.ciphertextCommitment).to.equal(fixture.ciphertext_commitment)
      const events = await interfold.queryFilter(interfold.filters.CiphertextOutputReferencePublished(e3Id))
      expect(events).to.have.length(1)
      const publication = await ethers.provider.getTransaction(events[0].transactionHash)
      expect(publication!.from).to.equal(relay.address)
      const publicationReceipt = await publication!.wait()
      expect(publicationReceipt!.status).to.equal(1)
      const decoded = interfold.interface.parseTransaction({ data: publication!.data })!
      const reference = abi.decode(['tuple(bytes32,bytes32,bytes,bytes)'], decoded.args[1])[0]
      const computeProof = reference[2]
      const envelope = abi.decode(['bytes', 'bytes32', 'bytes32'], computeProof)
      const seal = abi.decode(['uint8', 'bytes', 'bytes32[9]'], envelope[0])
      expect(seal[2][8]).to.equal(fixture.input_root)
      expect(seal[2][4]).to.equal(keyCommitment)
      await expect(receipt.verify(envelope[0], identityId, ethers.sha256(abi.encode(['bytes32[9]'], [seal[2]])))).not.to.revert(ethers)
      const changed = ethers.getBytes(seal[1])
      changed[changed.length - 1] ^= 1
      const invalidSeal = abi.encode(['uint8', 'bytes', 'bytes32[9]'], [1, changed, seal[2]])
      writeFileSync(path.join(directory, 'seal.bin'), ethers.getBytes(envelope[0]))
      save('ciphertext published and verified', {
        real_compute_proof_verified: true,
        callback_http_delivery_tested: true,
        automatic_ciphertext_publication: true,
        compute_to_publication_ms: Date.now() - proofStarted,
        publication_tx: publication!.hash,
        publication_gas: publicationReceipt!.gasUsed.toString(),
        app_exe_commit: commits.app_exe_commit,
        app_vm_commit: commits.app_vm_commit,
      })
      // Hardhat's HTTP node can report a precompile rejection as an RPC internal error.
      // The execution trace must show an EVM revert, not merely a failed RPC request.
      const trace = await ethers.provider.send('debug_traceCall', [
        {
          to: await receipt.getAddress(),
          data: receipt.interface.encodeFunctionData('verify', [
            invalidSeal,
            identityId,
            ethers.sha256(abi.encode(['bytes32[9]'], [seal[2]])),
          ]),
        },
        'latest',
        { disableMemory: true, disableStack: true, disableStorage: true },
      ])
      expect(trace.failed).to.equal(true)
      expect(trace.structLogs.at(-1).op).to.equal('REVERT')

      // Finish the local lifecycle with native plaintext and the declared decryption mock.
      // This step does not test distributed decryption or its recursive proof.
      const escrow = await interfold.e3Payments(e3Id)
      const pricing = await interfold.getPricingConfig()
      const treasury = await system.treasury.getAddress()
      const feeToken = await usdcToken.getAddress()
      const treasuryBefore = await interfold.pendingTreasuryClaim(treasury, feeToken)
      const ownerAddress = await owner.getAddress()
      const protocolAmount = (escrow * pricing.protocolShareBps) / 10_000n
      const plaintext = readFileSync(path.join(fixtureDirectory, 'plaintext.bin'))
      const completed = await (await interfold.publishPlaintextOutput(e3Id, plaintext, '0x01')).wait()
      expect(completed!.status).to.equal(1)
      expect(await interfold.getE3Stage(e3Id)).to.equal(5n)
      expect((await interfold.getE3(e3Id)).plaintextOutput).to.equal(ethers.hexlify(plaintext))
      expect(await interfold.e3Payments(e3Id)).to.equal(0n)
      expect(await interfold.pendingReward(e3Id, ownerAddress)).to.equal(escrow - protocolAmount)
      expect(await interfold.pendingTreasuryClaim(treasury, feeToken)).to.equal(treasuryBefore + protocolAmount)
      const beforeClaim = await usdcToken.balanceOf(ownerAddress)
      await (await interfold.claimReward(e3Id)).wait()
      expect((await usdcToken.balanceOf(ownerAddress)) - beforeClaim).to.equal(escrow - protocolAmount)
      await waitFor('CRISP result indexing', async () => {
        const response = await post('/state/result', { round_id: e3Id.toString() })
        if (!response.ok) return false
        const result = await response.json()
        return JSON.stringify(result.tally) === JSON.stringify(fixture.expected_tally.map(String))
      })
      save('complete', {
        changed_proof_rejected: true,
        settlement_verified: true,
        expected_tally: fixture.expected_tally,
        indexed_tally: fixture.expected_tally,
        plaintext_publication_tx: completed!.hash,
        threshold_decryption_proof_generated: false,
        native_tally_checked: true,
      })
    } catch (error) {
      save('failed', { error: String(error) })
      throw error
    } finally {
      if (server && server.exitCode === null) {
        server.kill('SIGTERM')
        await Promise.race([new Promise((resolve) => server!.once('exit', resolve)), delay(10_000)])
        if (server.exitCode === null) server.kill('SIGKILL')
      }
      log.end()
    }
  })
})
