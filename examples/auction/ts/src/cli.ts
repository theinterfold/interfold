// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * `tsx src/cli.ts --design vickrey-compact --bids 1,4,2 --levels 5 [--trace]`
 *
 * Prints the same summary as the Rust `auction-designs` binary, for the plaintext simulation.
 * It prints no key sizes, timings, or noise budgets, because nothing is encrypted.
 */

import { SetupError } from './designs/design'
import { designNames, designs, isCorrect, run, type AnyDesign, type RunResult } from './index'
import type { Profile } from './field'
import { seededRng, type Rng } from './rng'
import { formatTrace } from './trace'

const USAGE = `Usage: tsx src/cli.ts [options]

  --design <name>        One of: all, ${designNames.join(', ')} (default: all)
  --params <profile>     toy (N=1024, t=12289) or demo (N=16384, t=65537) (default: toy)
  --bids <list>          Comma-separated bids, one for each bidder. Random bids when not set.
  --bidders <n>          Number of bidders for random bids (default: 4)
  --levels <B>           Bids are in 0..B (default: 16)
  --seed <n>             Seed for bids, masks, and the tie draw. Random when not set.
  --tie-priority <list>  A tie priority (a permutation of 0..n) for the designs that draw one.
                         The rl-* designs pick the winner of a tie with a random lane instead.
  --sweep <list>         Comma-separated bidder counts: one table of costs for random bids.
  --trace                Print every intermediate slot vector, by region and level.
  --help                 Print this text.
`

interface Options {
  design: string
  params: Profile
  bids: number[] | null
  bidders: number
  levels: number
  seed: number | null
  tiePriority: number[] | null
  sweep: number[] | null
  trace: boolean
}

interface Process {
  argv: string[]
  exitCode?: number
}

/** The Node `process`, read without a dependency on the Node typings. */
const proc = (globalThis as unknown as { process: Process }).process

function numberList(text: string, flag: string): number[] {
  const values = text.split(',').map((part) => Number(part.trim()))
  if (values.some((value) => !Number.isInteger(value) || value < 0)) {
    throw new Error(`${flag} needs comma-separated non-negative integers, got "${text}"`)
  }
  return values
}

function parseArgs(args: string[]): Options | null {
  const options: Options = {
    design: 'all',
    params: 'toy',
    bids: null,
    bidders: 4,
    levels: 16,
    seed: null,
    tiePriority: null,
    sweep: null,
    trace: false,
  }
  for (let i = 0; i < args.length; i++) {
    const flag = args[i]
    if (flag === '--help' || flag === '-h') return null
    if (flag === '--trace') {
      options.trace = true
      continue
    }
    const value = args[++i]
    if (value === undefined) throw new Error(`${flag} needs a value`)
    switch (flag) {
      case '--design':
        if (value !== 'all' && designs[value] === undefined) throw new Error(`unknown design "${value}"`)
        options.design = value
        break
      case '--params':
        if (value !== 'toy' && value !== 'demo') throw new Error(`--params is toy or demo, got "${value}"`)
        options.params = value
        break
      case '--bids':
        options.bids = numberList(value, flag)
        break
      case '--bidders':
        options.bidders = Number(value)
        break
      case '--levels':
        options.levels = Number(value)
        break
      case '--seed':
        options.seed = Number(value)
        break
      case '--tie-priority':
        options.tiePriority = numberList(value, flag)
        break
      case '--sweep':
        options.sweep = numberList(value, flag)
        break
      default:
        throw new Error(`unknown option ${flag}`)
    }
  }
  if (options.sweep !== null && options.bids !== null) throw new Error('--sweep and --bids cannot be used together')
  return options
}

const optionText = (value: number | null) => (value === null ? '-' : String(value))
const list = (values: number[]) => values.map((value, index) => `${index}: ${value}`).join(', ')
const profileName = (profile: Profile) => (profile === 'toy' ? 'Toy' : 'Demo')

function selectedDesigns(options: Options): AnyDesign[] {
  return options.design === 'all' ? designNames.map((name) => designs[name]) : [designs[options.design]]
}

/** The priority for one design: the given one, if the design draws a priority. */
function priorityFor(design: AnyDesign, options: Options): number[] | undefined {
  if (options.tiePriority === null) return undefined
  return design.randomTieOrder ? options.tiePriority : undefined
}

/** Runs and prints one design. Returns the run, or `null` when the design did not run. */
function show(design: AnyDesign, options: Options, bids: number[], rng: Rng): RunResult | null {
  console.log(`\n== ${design.name} ==`)
  let result: RunResult
  try {
    result = run(design, options.params, bids, options.levels, priorityFor(design, options), rng, { trace: options.trace })
  } catch (error) {
    if (error instanceof SetupError) {
      console.log(`not run: ${error.message}`)
      return null
    }
    throw error
  }
  const { opCounts, setup } = result
  console.log(`reveals      ${design.disclosure}`)
  console.log(`readout      ${design.readout}`)
  console.log(`parameters   N=${setup.ring.degree} t=${setup.ring.t} depth=${result.depth}`)
  console.log(`bidder       ciphertexts ${result.inputs[0].length}`)
  console.log(`program      ${opCounts.ciphertextProducts} ct×ct, ${opCounts.plaintextProducts} ct×pt`)
  console.log(`public       winner ${optionText(result.result.winner)}, price ${optionText(result.result.price)}`)
  if (design.randomLane) {
    const { tieSet = [], random } = result.result
    console.log(
      `ties         tie set [${tieSet.join(', ')}], random lane ${optionText(random ?? null)}: winner = tie set[random mod ${tieSet.length}]`,
    )
  }
  if (design.randomTieOrder) {
    const source = options.tiePriority === null ? 'random' : 'given'
    console.log(`ties         ${source} priority [${setup.tiePriority.join(', ')}] (higher wins a tie)`)
  }
  if (result.ownRanks !== null) {
    const ranks = result.ownRanks.map((rank, index) => `${index}: ${optionText(rank)}`)
    console.log(`private      own rank ${ranks.join(', ')}`)
  }
  console.log(
    `check        ${isCorrect(result) ? 'OK' : 'WRONG'} (expected winner ${optionText(result.expected.winner)}, price ${optionText(result.expected.price)})`,
  )
  if (options.trace) {
    console.log('')
    for (const line of formatTrace(result)) console.log(line)
  }
  return result
}

function summary(results: RunResult[]): void {
  console.log('\n| design | depth | ct×ct | ct×pt | ciphertexts/bidder |')
  console.log('|---|---|---|---|---|')
  for (const r of results) {
    const { opCounts } = r
    console.log(
      `| ${r.design.name} | ${r.depth} | ${opCounts.ciphertextProducts} | ${opCounts.plaintextProducts} | ${r.inputs[0].length} |`,
    )
  }
}

/** Runs the selected designs for each bidder count and prints one table. Returns false on a wrong result. */
function sweep(options: Options, counts: number[], rng: Rng): boolean {
  console.log('\n| bidders | design | depth | ct×ct | ct×pt | result |')
  console.log('|---|---|---|---|---|---|')
  let correct = true
  for (const count of counts) {
    const bids = Array.from({ length: count }, () => rng.range(0, options.levels))
    for (const design of selectedDesigns(options)) {
      try {
        const r = run(design, options.params, bids, options.levels, priorityFor(design, options), rng)
        const ok = isCorrect(r)
        correct &&= ok
        console.log(
          `| ${count} | ${design.name} | ${r.depth} | ${r.opCounts.ciphertextProducts} | ${r.opCounts.plaintextProducts} | ${ok ? 'OK' : 'WRONG'} |`,
        )
      } catch (error) {
        if (!(error instanceof SetupError)) throw error
        console.log(`| ${count} | ${design.name} | - | - | - | not run: ${error.message} |`)
      }
    }
  }
  return correct
}

function main(): void {
  let options: Options | null
  try {
    options = parseArgs(proc.argv.slice(2))
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    console.error(USAGE)
    proc.exitCode = 2
    return
  }
  if (options === null) {
    console.log(USAGE)
    return
  }
  const seed = options.seed ?? Math.floor(Math.random() * 2 ** 32)
  const rng = seededRng(seed)
  console.log(`seed ${seed}, ${profileName(options.params)} profile, ${options.levels} levels`)
  if (options.sweep !== null) {
    proc.exitCode = sweep(options, options.sweep, rng) ? 0 : 1
    return
  }
  const bids = options.bids ?? Array.from({ length: options.bidders }, () => rng.range(0, options.levels))
  console.log(`bids ${list(bids)}`)

  const results: RunResult[] = []
  let failed = false
  for (const design of selectedDesigns(options)) {
    const result = show(design, options, bids, rng)
    if (result === null) {
      failed = true
      continue
    }
    failed ||= !isCorrect(result)
    results.push(result)
  }
  if (results.length > 1) summary(results)
  proc.exitCode = failed ? 1 : 0
}

main()
