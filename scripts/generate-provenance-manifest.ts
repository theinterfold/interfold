#!/usr/bin/env tsx
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/** Record the OpenVM build, checked application identity, and deployed verifier bindings. */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'

const root = path.resolve(__dirname, '..')
const requireContracts = createRequire(path.join(root, 'packages/interfold-contracts/package.json'))
const { AbiCoder, Contract, FetchRequest, JsonRpcProvider, getAddress, id, keccak256 } = requireContracts('ethers')
type Args = Partial<Record<'config' | 'prover' | 'rpc' | 'verifier' | 'out', string>>

function parseArgs(): Args {
  const args: Args = {}
  const values = process.argv.slice(2)
  for (let i = 0; i < values.length; i += 2) {
    const name = values[i].slice(2) as keyof Args
    if (!['config', 'prover', 'rpc', 'verifier', 'out'].includes(name) || !values[i].startsWith('--')) {
      throw new Error('Unknown argument: ' + values[i])
    }
    if (!values[i + 1] || values[i + 1].startsWith('--')) throw new Error('Missing value: ' + values[i])
    args[name] = values[i + 1]
  }
  if (Boolean(args.rpc) !== Boolean(args.verifier)) throw new Error('Supply --rpc and --verifier together')
  if (args.prover && !args.config) throw new Error('--prover requires --config')
  return args
}

function command(binary: string, args: string[]): string | null {
  try {
    return execFileSync(binary, args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60_000 }).trim()
  } catch {
    return null
  }
}

async function digest(file: string): Promise<string | null> {
  if (!existsSync(file)) return null
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(file)) hash.update(chunk)
  return hash.digest('hex')
}

async function parameterDigests(directory: string, relative = ''): Promise<Record<string, string | null>> {
  const result: Record<string, string | null> = {}
  for (const entry of readdirSync(path.join(directory, relative), { withFileTypes: true })) {
    const name = path.join(relative, entry.name)
    if (entry.isDirectory()) Object.assign(result, await parameterDigests(directory, name))
    else if (entry.isFile()) result[name] = await digest(path.join(directory, name))
    else throw new Error('The parameter directory must contain only regular files and directories')
  }
  return result
}

async function main() {
  const args = parseArgs()
  const unresolved: string[] = []
  const files = [
    'Cargo.lock',
    'crates/support/Cargo.lock',
    'crates/support/openvm/guest/Cargo.lock',
    'crates/support/openvm/prover/Cargo.lock',
    'rust-toolchain.toml',
    'crates/support/openvm/guest/openvm.toml',
    'crates/support/openvm/fhe-optimizations.patch',
  ]
  const sourceDigests = Object.fromEntries(await Promise.all(files.map(async (file) => [file, await digest(path.join(root, file))])))
  const sourceCommit = command('git', ['rev-parse', 'HEAD'])
  const sourceStatus = command('git', ['status', '--porcelain'])
  if (!sourceCommit || sourceStatus !== '') unresolved.push('source must be a clean Git checkout')
  for (const [file, hash] of Object.entries(sourceDigests)) if (!hash) unresolved.push('source artifact: ' + file)

  let artifacts: Record<string, string | null> | null = null
  let parameters: Record<string, string | null> | null = null
  let commitments: { app_exe_commit: string; app_vm_commit: string } | null = null
  let workerChecked = false
  let deployment: Record<string, unknown> | null = null
  let verifierArtifact: { bytecode: string } | undefined
  if (args.config) {
    const configPath = path.resolve(args.config)
    const config = JSON.parse(readFileSync(configPath, 'utf8'))
    commitments = config.app_commit
    if (!commitments || ![commitments.app_exe_commit, commitments.app_vm_commit].every((value) => /^0x[0-9a-fA-F]{64}$/.test(value))) {
      throw new Error('The worker configuration must contain both 32-byte application commitments')
    }
    artifacts = {}
    for (const name of ['app_pk', 'executable', 'aggregation_pk', 'halo2_pk', 'verifier_artifact']) {
      if (typeof config[name] !== 'string' || !path.isAbsolute(config[name])) throw new Error('Invalid artifact path: ' + name)
      artifacts[name] = await digest(config[name])
      if (!artifacts[name]) unresolved.push('artifact: ' + name)
    }
    if (artifacts.verifier_artifact !== config.verifier_sha256) throw new Error('Verifier artifact checksum mismatch')
    verifierArtifact = JSON.parse(readFileSync(config.verifier_artifact, 'utf8'))
    if (!path.isAbsolute(config.halo2_params_dir)) throw new Error('The parameter directory must be an absolute path')
    parameters = await parameterDigests(config.halo2_params_dir)
    if (Object.keys(parameters).length === 0) unresolved.push('Halo2 parameters')
    if (args.prover) {
      const prover = path.resolve(args.prover)
      artifacts.worker = await digest(prover)
      workerChecked = command(prover, ['check', configPath]) !== null
    }
    if (!workerChecked) unresolved.push('worker identity check (supply a working --prover)')
  } else unresolved.push('worker configuration (supply --config)')

  if (args.rpc && args.verifier) {
    const request = new FetchRequest(args.rpc)
    request.timeout = 15_000
    const provider = new JsonRpcProvider(request)
    try {
      const protocolAddress = getAddress(args.verifier)
      const protocol = new Contract(
        protocolAddress,
        ['function imageId() view returns(bytes32)', 'function openVmVerifier() view returns(address)'],
        provider,
      )
      const receiptAddress = await protocol.openVmVerifier()
      const receipt = new Contract(
        receiptAddress,
        [
          'function imageId() view returns(bytes32)',
          'function verifier() view returns(address)',
          'function appExeCommit() view returns(bytes32)',
          'function appVmCommit() view returns(bytes32)',
        ],
        provider,
      )
      const halo2Address = await receipt.verifier()
      const [protocolCode, receiptCode, halo2Code] = await Promise.all(
        [protocolAddress, receiptAddress, halo2Address].map((address) => provider.getCode(address)),
      )
      if ([protocolCode, receiptCode, halo2Code].includes('0x')) throw new Error('A configured verifier has no deployed code')
      const [protocolId, receiptId, exe, vm, network] = await Promise.all([
        protocol.imageId(),
        receipt.imageId(),
        receipt.appExeCommit(),
        receipt.appVmCommit(),
        provider.getNetwork(),
      ])
      const expectedId = keccak256(
        AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'address', 'bytes32', 'bytes32'],
          [id('INTERFOLD_OPENVM_RECEIPT_V1'), halo2Address, exe, vm],
        ),
      )
      if (protocolId !== receiptId || receiptId !== expectedId) throw new Error('The deployed receipt identity is inconsistent')
      if (
        !commitments ||
        exe.toLowerCase() !== commitments.app_exe_commit.toLowerCase() ||
        vm.toLowerCase() !== commitments.app_vm_commit.toLowerCase()
      ) {
        throw new Error('The deployed application commitments differ from the configured guest')
      }
      if (!verifierArtifact || !/^(0x)?[0-9a-fA-F]+$/.test(verifierArtifact.bytecode)) throw new Error('Missing verifier creation bytecode')
      // Simulate creation without sending a transaction, then compare the resulting runtime.
      const runtime = await provider.call({ data: '0x' + verifierArtifact.bytecode.replace(/^0x/, '') })
      if (keccak256(runtime) !== keccak256(halo2Code)) throw new Error('The deployed Halo2 runtime differs from the checked artifact')
      deployment = {
        chainId: network.chainId.toString(),
        ciphertextVerifier: protocolAddress,
        receiptVerifier: receiptAddress,
        halo2Verifier: halo2Address,
        imageId: protocolId,
        ciphertextVerifierCodeHash: keccak256(protocolCode),
        receiptVerifierCodeHash: keccak256(receiptCode),
        halo2VerifierCodeHash: keccak256(halo2Code),
        identityMatches: true,
        halo2ArtifactMatches: true,
      }
    } catch (error) {
      unresolved.push('deployment check: ' + String(error))
    } finally {
      provider.destroy()
    }
  } else unresolved.push('deployment (supply --rpc and --verifier)')

  const manifest = {
    schema: 'interfold.openvm-provenance/1',
    backend: 'openvm',
    source: { commit: sourceCommit, clean: sourceStatus === '', sha256: sourceDigests },
    artifactsSha256: artifacts,
    halo2ParametersSha256: parameters,
    appCommit: commitments,
    workerIdentityChecked: workerChecked,
    deployment,
    complete: unresolved.length === 0,
    unresolved,
    auditStatus: 'The compute implementation and its OpenVM verifier integration are not audited.',
    sourceReproductionChecked: false,
    note: 'Artifact and identity checks do not establish reproducibility. Independently rebuild the guest from the recorded clean source.',
  }
  const output = JSON.stringify(manifest, null, 2) + '\n'
  if (args.out) writeFileSync(path.resolve(args.out), output, { flag: 'wx' })
  else process.stdout.write(output)
  if (unresolved.length) console.error('Incomplete OpenVM provenance: ' + unresolved.join('; '))
}

main().catch((error) => {
  console.error(String(error))
  process.exitCode = 1
})
