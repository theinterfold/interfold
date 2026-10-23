// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { execFile } from 'node:child_process'
import { mkdir, readdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { promisify } from 'node:util'
import type { Hex } from 'viem'

import type { DataAvailabilityConfig } from './config'

const execFileAsync = promisify(execFile)

// Avail finalization can take 300 seconds inside `submit`; the proof request uses 30 seconds.
const SUBMIT_TIMEOUT_MS = 600_000
const PROOF_TIMEOUT_MS = 60_000

/** The Avail transaction of a publication, as `auction-da submit` prints it. */
export interface PendingPublication {
  contentHash: Hex
  blockHash: Hex
  blockNumber: number
  extrinsicIndex: number
}

/** The VectorX proof of a publication, as `auction-da proof` prints it once it is ready. */
export interface ReadyProof {
  contentHash: Hex
  blockNumber: number
  /** A decimal string: the leaf index is a uint128. */
  leafIndex: string
  abiProof: Hex
}

export type ProofResult = { status: 'pending' } | ({ status: 'ready' } & ReadyProof)

/**
 * The durable state of one output on the Avail path. The ciphertext bytes are a file next to this
 * record. Each step writes its result before the next step starts, so a restart resumes where the
 * previous run stopped.
 */
export interface OutputRecord {
  e3Id: string
  contentHash: Hex
  ciphertextCommitment: Hex
  computeProof: Hex
  pending?: PendingPublication
  proof?: ReadyProof
  /** The hash of the mined `publishCiphertextOutput` transaction. */
  published?: Hex
  /** Why the server stopped: the compute window closed. The record stays for the operator. */
  abandoned?: string
}

function isHex(value: unknown): value is Hex {
  return typeof value === 'string' && /^0x[0-9a-fA-F]*$/.test(value)
}

function isPending(value: unknown): value is PendingPublication {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Record<string, unknown>
  return (
    isHex(candidate.contentHash) &&
    isHex(candidate.blockHash) &&
    Number.isInteger(candidate.blockNumber) &&
    Number.isInteger(candidate.extrinsicIndex)
  )
}

/** Parse the output of `auction-da submit`. */
export function parseSubmitOutput(stdout: string): PendingPublication {
  const parsed: unknown = JSON.parse(stdout)
  if (!isPending(parsed)) throw new Error('auction-da submit printed an unexpected document')
  return parsed
}

/** Parse the output of `auction-da proof`. */
export function parseProofOutput(stdout: string): ProofResult {
  const parsed = JSON.parse(stdout) as Record<string, unknown>
  if (parsed.status === 'pending') return { status: 'pending' }
  if (
    parsed.status === 'ready' &&
    isHex(parsed.contentHash) &&
    Number.isInteger(parsed.blockNumber) &&
    typeof parsed.leafIndex === 'string' &&
    isHex(parsed.abiProof)
  ) {
    return {
      status: 'ready',
      contentHash: parsed.contentHash,
      blockNumber: parsed.blockNumber as number,
      leafIndex: parsed.leafIndex,
      abiProof: parsed.abiProof,
    }
  }
  throw new Error('auction-da proof printed an unexpected document')
}

/** Runs the `auction-da` binary, which holds the Avail client. */
export class AvailHelper {
  private readonly baseEnv: Record<string, string>

  constructor(
    private readonly config: Extract<DataAvailabilityConfig, { mode: 'avail' }>,
    destinationChainId: number,
  ) {
    // The helper gets no other variable of this process: the operator key stays out of it.
    this.baseEnv = {
      AVAIL_RPC_URL: config.rpcUrl,
      AVAIL_APP_ID: String(config.appId),
      AVAIL_BRIDGE_API_URL: config.bridgeApiUrl,
      DESTINATION_CHAIN_ID: String(destinationChainId),
    }
    for (const name of ['PATH', 'RUST_LOG']) {
      const value = process.env[name]
      if (value !== undefined) this.baseEnv[name] = value
    }
  }

  private async run(args: string[], env: Record<string, string>, timeout: number): Promise<string> {
    try {
      const { stdout } = await execFileAsync(this.config.helperBinary, args, { env, timeout, maxBuffer: 16 * 1024 * 1024 })
      return stdout
    } catch (error) {
      // The helper explains a failure on stderr; the seed is only in its environment, never in its arguments.
      const stderr = (error as { stderr?: string }).stderr?.trim()
      throw new Error(`auction-da ${args[0]} failed: ${stderr || (error as Error).message}`)
    }
  }

  /** Publish a file to Avail. Resolves after Avail finalized it. Only this command gets the seed. */
  async submit(file: string): Promise<PendingPublication> {
    const env = { ...this.baseEnv, AVAIL_SEED: this.config.seed }
    return parseSubmitOutput(await this.run(['submit', '--file', file], env, SUBMIT_TIMEOUT_MS))
  }

  /** Ask the VectorX bridge API for the Ethereum proof of a publication. */
  async proof(pending: PendingPublication): Promise<ProofResult> {
    return parseProofOutput(await this.run(['proof', '--pending', JSON.stringify(pending)], this.baseEnv, PROOF_TIMEOUT_MS))
  }
}

async function writeAtomically(path: string, bytes: Buffer | string): Promise<void> {
  const temporaryPath = `${path}.${process.pid}.tmp`
  await writeFile(temporaryPath, bytes)
  await rename(temporaryPath, path)
}

/** Objects that the server publishes, and the Avail records of the outputs. */
export class AvailabilityStore {
  constructor(private readonly directory: string) {}

  private outputDirectory(e3Id: bigint | string): string {
    return join(this.directory, `e3-${e3Id}`)
  }

  /** Keep an object under its content hash, for `GET /availability/objects/:contentHash`. */
  async storeObject(contentHash: Hex, bytes: Buffer): Promise<void> {
    await mkdir(this.directory, { recursive: true })
    await writeAtomically(join(this.directory, contentHash.slice(2).toLowerCase()), bytes)
  }

  async readObject(contentHash: string): Promise<Buffer> {
    return readFile(join(this.directory, contentHash.slice(2).toLowerCase()))
  }

  ciphertextPath(e3Id: bigint | string): string {
    return join(this.outputDirectory(e3Id), 'ciphertext.bin')
  }

  /**
   * Persist a new output. An earlier record is kept once its output reached Avail (it has a
   * `pending` publication), was published, or was abandoned; before that a new output replaces it.
   */
  async createRecord(record: OutputRecord, ciphertext: Buffer): Promise<{ record: OutputRecord; created: boolean }> {
    const existing = await this.readRecord(record.e3Id)
    if (existing && (existing.pending || existing.published || existing.abandoned)) return { record: existing, created: false }
    await mkdir(this.outputDirectory(record.e3Id), { recursive: true })
    await writeAtomically(this.ciphertextPath(record.e3Id), ciphertext)
    await this.writeRecord(record)
    return { record, created: true }
  }

  async writeRecord(record: OutputRecord): Promise<void> {
    await writeAtomically(join(this.outputDirectory(record.e3Id), 'record.json'), JSON.stringify(record, null, 2))
  }

  async readRecord(e3Id: bigint | string): Promise<OutputRecord | undefined> {
    try {
      return JSON.parse(await readFile(join(this.outputDirectory(e3Id), 'record.json'), 'utf8')) as OutputRecord
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') return undefined
      throw error
    }
  }

  /** Every output record on disk. */
  async listRecords(): Promise<OutputRecord[]> {
    let names: string[]
    try {
      names = await readdir(this.directory)
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') return []
      throw error
    }
    const records: OutputRecord[] = []
    for (const name of names) {
      const match = /^e3-(\d+)$/.exec(name)
      if (!match) continue
      const record = await this.readRecord(match[1])
      if (record) records.push(record)
    }
    return records
  }
}
