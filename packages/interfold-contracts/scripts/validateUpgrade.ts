// SPDX-License-Identifier: LGPL-3.0-only
//
// H-22: storage-layout snapshot + diff for upgradeable contracts.
//
// This script does NOT depend on `@openzeppelin/hardhat-upgrades` (the OZ
// upgrades plugin is currently not compatible with Hardhat 3 — once it ships
// Hardhat 3 support, prefer it). Instead it reads the `storageLayout` solc
// output produced by `hardhat.config.ts` (see the `outputSelection` block)
// from the latest build-info file, then for each upgradeable contract:
//
//   * If `audits/storage-layouts/<Contract>.json` exists, diff the live
//     layout against the committed snapshot and FAIL on any of:
//       - a slot whose `type` or `label` changed,
//       - a slot whose `offset` or `slot` index moved,
//       - a state variable that was removed.
//     Appending new variables at the END is allowed (this is what `__gap`
//     reservations are for).
//   * If the snapshot is missing, write it (first run / new contract).
//
// Run with: `pnpm hardhat compile && pnpm exec ts-node scripts/validateUpgrade.ts`
//
// Marked as a best-effort guard; CI should call this on every PR that
// touches an upgradeable contract.
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

interface StorageVar {
  astId: number;
  contract: string;
  label: string;
  offset: number;
  slot: string;
  type: string;
}

interface StorageLayout {
  storage: StorageVar[];
  types: Record<string, unknown> | null;
}

const UPGRADEABLE_CONTRACTS: { source: string; contract: string }[] = [
  { source: "contracts/Interfold.sol", contract: "Interfold" },
  {
    source: "contracts/registry/CiphernodeRegistryOwnable.sol",
    contract: "CiphernodeRegistryOwnable",
  },
  {
    source: "contracts/registry/BondingRegistry.sol",
    contract: "BondingRegistry",
  },
  {
    source: "contracts/E3RefundManager.sol",
    contract: "E3RefundManager",
  },
];

const SNAPSHOT_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../audits/storage-layouts",
);
const BUILD_INFO_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../artifacts/build-info",
);

function latestBuildInfo(): string {
  if (!fs.existsSync(BUILD_INFO_DIR)) {
    throw new Error(
      `No build-info dir at ${BUILD_INFO_DIR}. Run \`pnpm hardhat compile\` first.`,
    );
  }
  const outputs = fs
    .readdirSync(BUILD_INFO_DIR)
    .filter((f) => f.endsWith(".output.json"))
    .map((f) => ({
      f,
      mtime: fs.statSync(path.join(BUILD_INFO_DIR, f)).mtimeMs,
    }))
    .sort((a, b) => b.mtime - a.mtime);
  if (outputs.length === 0) {
    throw new Error(`No *.output.json under ${BUILD_INFO_DIR}.`);
  }
  return path.join(BUILD_INFO_DIR, outputs[0].f);
}

function loadLayout(
  buildInfoPath: string,
  source: string,
  contract: string,
): StorageLayout {
  const buildInfo = JSON.parse(fs.readFileSync(buildInfoPath, "utf8")) as {
    output: {
      contracts: Record<
        string,
        Record<string, { storageLayout?: StorageLayout }>
      >;
    };
  };
  const node = buildInfo.output.contracts?.[source]?.[contract];
  if (!node) {
    throw new Error(`Contract ${source}:${contract} not in build-info.`);
  }
  if (!node.storageLayout) {
    throw new Error(
      `No storageLayout for ${contract}. Ensure hardhat.config.ts outputSelection includes "storageLayout".`,
    );
  }
  return node.storageLayout;
}

function diffLayouts(
  contract: string,
  prev: StorageLayout,
  curr: StorageLayout,
): string[] {
  const errors: string[] = [];
  const prevByLabel = new Map(prev.storage.map((s) => [s.label, s]));
  for (const p of prev.storage) {
    const c = curr.storage.find((x) => x.label === p.label);
    if (!c) {
      // Removal is only safe if the variable was the LAST one (could be
      // converted into a __gap entry). We still flag it for review.
      errors.push(
        `${contract}: state variable \`${p.label}\` (slot ${p.slot}) was removed.`,
      );
      continue;
    }
    if (c.slot !== p.slot || c.offset !== p.offset) {
      errors.push(
        `${contract}: \`${p.label}\` moved from slot ${p.slot}+${p.offset} to ${c.slot}+${c.offset}.`,
      );
    }
    if (c.type !== p.type) {
      errors.push(
        `${contract}: \`${p.label}\` type changed from ${p.type} to ${c.type}.`,
      );
    }
  }
  // Appended new variables are OK (consume __gap or appended).
  for (const c of curr.storage) {
    if (!prevByLabel.has(c.label)) {
      // informational only
      console.log(
        `  + ${contract}: new state variable \`${c.label}\` at slot ${c.slot}+${c.offset} (${c.type}).`,
      );
    }
  }
  return errors;
}

async function main(): Promise<void> {
  if (!fs.existsSync(SNAPSHOT_DIR)) {
    fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  }
  const buildInfoPath = latestBuildInfo();
  console.log(`Using build-info: ${path.basename(buildInfoPath)}`);

  let totalErrors = 0;
  for (const { source, contract } of UPGRADEABLE_CONTRACTS) {
    const snapshotPath = path.join(SNAPSHOT_DIR, `${contract}.json`);
    const layout = loadLayout(buildInfoPath, source, contract);
    if (!fs.existsSync(snapshotPath)) {
      fs.writeFileSync(snapshotPath, JSON.stringify(layout, null, 2) + "\n");
      console.log(`  * ${contract}: snapshot CREATED at ${snapshotPath}.`);
      continue;
    }
    const prev = JSON.parse(
      fs.readFileSync(snapshotPath, "utf8"),
    ) as StorageLayout;
    const errs = diffLayouts(contract, prev, layout);
    if (errs.length === 0) {
      console.log(`  ✓ ${contract}: storage layout compatible.`);
    } else {
      totalErrors += errs.length;
      for (const e of errs) console.error(`  ✗ ${e}`);
    }
  }

  if (totalErrors > 0) {
    console.error(
      `\nvalidateUpgrade FAILED with ${totalErrors} storage incompatibilit${
        totalErrors === 1 ? "y" : "ies"
      }.`,
    );
    console.error(
      `If the change is intentional, update the snapshot under audits/storage-layouts/ and re-run.`,
    );
    process.exit(1);
  }
  console.log("\nvalidateUpgrade OK.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
