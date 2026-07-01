// SPDX-License-Identifier: LGPL-3.0-only
//
// Adapted from Uniswap's uniswap-cca `cca-supply-schedule` MCP logic:
// https://github.com/Uniswap/uniswap-ai/tree/main/packages/plugins/uniswap-cca
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

export const TOTAL_TARGET = 10_000_000n;
const DEFAULT_NUM_STEPS = 12;
const DEFAULT_FINAL_BLOCK_PCT = 0.3;
const DEFAULT_ALPHA = 1.2;
const MPS_MAX = (1n << 24n) - 1n;
const BLOCK_DELTA_MAX = (1n << 40n) - 1n;

export type ScheduleStep = { mps: bigint; blockDelta: bigint };

interface SaleConfigLike {
  auction: {
    startBlock: string;
    endBlock: string;
    auctionStepsData: string;
  };
}

const args = process.argv.slice(2);

function arg(name: string): string | undefined {
  const prefix = `--${name}=`;
  const withEquals = args.find((value) => value.startsWith(prefix));
  if (withEquals) return withEquals.slice(prefix.length);
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
}

function hasFlag(name: string): boolean {
  return args.includes(`--${name}`);
}

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

export function generateSchedule(opts: {
  auctionBlocks: number;
  prebidBlocks: number;
  numSteps: number;
  finalBlockPct: number;
  alpha: number;
  roundToNearest?: number;
}): ScheduleStep[] {
  if (opts.auctionBlocks <= 0) throw new Error("auctionBlocks must be > 0");
  if (opts.prebidBlocks < 0) throw new Error("prebidBlocks must be >= 0");
  if (opts.numSteps <= 0) throw new Error("numSteps must be > 0");
  if (opts.finalBlockPct <= 0.1 || opts.finalBlockPct >= 0.9) {
    throw new Error("finalBlockPct must be between 0.1 and 0.9");
  }
  if (opts.alpha <= 0) throw new Error("alpha must be > 0");

  const schedule: ScheduleStep[] = [];
  if (opts.prebidBlocks > 0) {
    schedule.push({ mps: 0n, blockDelta: BigInt(opts.prebidBlocks) });
  }

  const mainSupplyPct = 1 - opts.finalBlockPct;
  const stepTokensPct = mainSupplyPct / opts.numSteps;
  const boundaries: number[] = [0];
  for (let i = 1; i <= opts.numSteps; i++) {
    const cumulativePct = (i * stepTokensPct) / mainSupplyPct;
    boundaries.push(
      Math.round(cumulativePct ** (1 / opts.alpha) * opts.auctionBlocks),
    );
  }

  if (opts.roundToNearest && opts.roundToNearest > 0) {
    for (let i = 0; i < boundaries.length; i++) {
      boundaries[i] =
        Math.round(boundaries[i] / opts.roundToNearest) * opts.roundToNearest;
    }
    boundaries[boundaries.length - 1] = opts.auctionBlocks;
  }

  let cumulativeTokens = 0n;
  for (let i = 0; i < opts.numSteps; i++) {
    const duration = boundaries[i + 1] - boundaries[i];
    if (duration <= 0) {
      throw new Error(
        `zero-duration step ${i + 1}; reduce --round-to-nearest or --num-steps`,
      );
    }
    const stepTokens = Math.round(stepTokensPct * Number(TOTAL_TARGET));
    const mps = BigInt(Math.max(1, Math.round(stepTokens / duration)));
    const blockDelta = BigInt(duration);
    schedule.push({ mps, blockDelta });
    cumulativeTokens += mps * blockDelta;
  }

  const finalTokens = TOTAL_TARGET - cumulativeTokens;
  if (finalTokens <= 0n) {
    throw new Error(
      `final block would be ${finalTokens}; adjust schedule parameters`,
    );
  }
  schedule.push({ mps: finalTokens, blockDelta: 1n });

  validateSchedule(schedule);
  return schedule;
}

export function validateSchedule(schedule: ScheduleStep[]): void {
  if (schedule.length === 0) throw new Error("schedule cannot be empty");
  const total = schedule.reduce(
    (sum, step) => sum + step.mps * step.blockDelta,
    0n,
  );
  if (total !== TOTAL_TARGET) {
    throw new Error(`schedule totals ${total}, expected ${TOTAL_TARGET}`);
  }
  for (const [index, step] of schedule.entries()) {
    if (step.mps < 0n || step.mps > MPS_MAX) {
      throw new Error(`step ${index + 1} mps ${step.mps} exceeds uint24`);
    }
    if (step.blockDelta <= 0n || step.blockDelta > BLOCK_DELTA_MAX) {
      throw new Error(
        `step ${index + 1} blockDelta ${step.blockDelta} must be between 1 and uint40 max`,
      );
    }
  }
}

export function encodeSchedule(schedule: ScheduleStep[]): string {
  validateSchedule(schedule);
  return `0x${schedule
    .map((step) => {
      const packed = (step.mps << 40n) | step.blockDelta;
      return packed.toString(16).padStart(16, "0");
    })
    .join("")}`;
}

export function decodeSchedule(encoded: string): ScheduleStep[] {
  if (!/^0x([0-9a-fA-F]{16})+$/.test(encoded)) {
    throw new Error("auctionStepsData must be 0x-prefixed packed uint64 bytes");
  }
  const steps: ScheduleStep[] = [];
  for (let offset = 2; offset < encoded.length; offset += 16) {
    const packed = BigInt(`0x${encoded.slice(offset, offset + 16)}`);
    steps.push({
      mps: packed >> 40n,
      blockDelta: packed & BLOCK_DELTA_MAX,
    });
  }
  validateSchedule(steps);
  return steps;
}

export function summarize(schedule: ScheduleStep[]) {
  const totalBlocks = schedule.reduce((sum, step) => sum + step.blockDelta, 0n);
  const final = schedule[schedule.length - 1];
  return {
    totalMps: TOTAL_TARGET.toString(),
    totalBlocks: totalBlocks.toString(),
    phases: schedule.length,
    finalBlockMps: final.mps.toString(),
    finalBlockPercentage: Number((final.mps * 10_000n) / TOTAL_TARGET) / 100,
  };
}

function printHelp(): void {
  console.log(`
Interfold CCA schedule helper

Generate or validate packed auctionStepsData using the Uniswap CCA convex schedule.

Examples:
  pnpm cca:schedule -- --auction-blocks 14399
  pnpm cca:schedule -- --config deploy/sale/mainnet-sale.config.json --update-config
  pnpm cca:schedule -- --decode 0x...

Flags:
  --config <file>             Read sale config and fit schedule to endBlock-startBlock
  --update-config             Write generated auctionStepsData back to --config
  --auction-blocks N          Main sale blocks before final block
  --prebid-blocks N           Optional zero-MPS prebid blocks
  --num-steps N               Default ${DEFAULT_NUM_STEPS}
  --final-block-pct N         Default ${DEFAULT_FINAL_BLOCK_PCT}
  --alpha N                   Default ${DEFAULT_ALPHA}
  --round-to-nearest N        Optional boundary rounding
  --decode 0x...              Decode and validate existing auctionStepsData
`);
}

function main(): void {
  if (hasFlag("help")) return printHelp();

  const decode = arg("decode");
  if (decode) {
    const schedule = decodeSchedule(decode);
    console.log(
      JSON.stringify(
        {
          schedule,
          encoded: encodeSchedule(schedule),
          summary: summarize(schedule),
        },
        bigintReplacer,
        2,
      ),
    );
    return;
  }

  const configFile = arg("config");
  const config = configFile ? readJson<SaleConfigLike>(configFile) : undefined;
  const prebidBlocks = Number(arg("prebid-blocks") ?? "0");

  let auctionBlocks = Number(arg("auction-blocks") ?? "0");
  if (!auctionBlocks && config) {
    const totalScheduleBlocks = Number(
      BigInt(config.auction.endBlock) - BigInt(config.auction.startBlock),
    );
    auctionBlocks = totalScheduleBlocks - prebidBlocks - 1;
    if (auctionBlocks <= 0) {
      throw new Error(
        `config block window ${totalScheduleBlocks} is too short for prebid=${prebidBlocks} plus final block`,
      );
    }
  }
  if (!auctionBlocks) {
    throw new Error("Provide --auction-blocks or --config");
  }

  const schedule = generateSchedule({
    auctionBlocks,
    prebidBlocks,
    numSteps: Number(arg("num-steps") ?? DEFAULT_NUM_STEPS),
    finalBlockPct: Number(arg("final-block-pct") ?? DEFAULT_FINAL_BLOCK_PCT),
    alpha: Number(arg("alpha") ?? DEFAULT_ALPHA),
    roundToNearest: arg("round-to-nearest")
      ? Number(arg("round-to-nearest"))
      : undefined,
  });
  const encoded = encodeSchedule(schedule);
  const summary = summarize(schedule);

  if (config && hasFlag("update-config")) {
    config.auction.auctionStepsData = encoded;
    writeJson(configFile!, config);
  }

  console.log(
    JSON.stringify({ schedule, encoded, summary }, bigintReplacer, 2),
  );
}

function bigintReplacer(_: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString() : value;
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  main();
}
