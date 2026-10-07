// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Generates `deployments/manifest.json` from `deployed_contracts.json`.
 *
 * The manifest is the published, machine-readable answer to "which addresses is
 * this network on right now". It is attached to each GitHub release so a running
 * `interfold` binary can fetch it without being rebuilt — the compiled-in
 * `CONTRACT_DEPLOYMENTS` table (see `crates/cli/build.rs`) freezes at build time
 * and goes stale the moment the contracts are redeployed.
 *
 * Contract keys are deliberately the `interfold.config.yaml` keys, not the
 * Solidity contract names, so `interfold config check` can compare an operator's
 * config against the manifest without a translation table in the middle.
 *
 * Run: `pnpm gen:manifest`
 */
import fs from "fs";
import { fileURLToPath } from "node:url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../../..");
const DEPLOYED = path.join(
  REPO_ROOT,
  "packages/interfold-contracts/deployed_contracts.json",
);
const OUT = path.join(REPO_ROOT, "deployments/manifest.json");

/** Bumped only on a breaking change to the manifest shape. */
const SCHEMA_VERSION = 1;

const CHAIN_IDS: Record<string, number> = {
  mainnet: 1,
  sepolia: 11155111,
  localhost: 31337,
  hardhat: 31337,
  devnet: 31337,
};

/**
 * `interfold.config.yaml` key -> the deployed_contracts.json names that can
 * satisfy it, most-preferred first. The mock entries are the fallbacks so a
 * mock deployment still produces a usable manifest, and `mocks` records which
 * way it resolved.
 */
const CONTRACT_KEYS: Record<string, string[]> = {
  interfold: ["Interfold"],
  ciphernode_registry: ["CiphernodeRegistryOwnable"],
  bonding_registry: ["BondingRegistry"],
  slashing_manager: ["SlashingManager"],
  fee_token: ["FeeToken", "MockUSDC"],
  faucet: ["Faucet"],
  // `e3_program` is deliberately absent. Many E3 programs can be registered on
  // one deployment (CRISP runs its own CRISPProgram), so the protocol manifest
  // has no authority over which one a given node should point at. Publishing
  // one would make `config check` call every application's own program stale.
  dkg_fold_attestation_verifier: [
    "DkgFoldAttestationVerifier",
    "MockDkgFoldAttestationVerifier",
  ],
};

/**
 * Not part of the node config, but operators, the dashboard and the docs all
 * need them. Carried under `reference` so consumers cannot mistake them for
 * something `interfold.config.yaml` accepts.
 */
const REFERENCE_KEYS = [
  "InterfoldToken",
  "InterfoldTicketToken",
  "E3RefundManager",
  "NodeReleaseRegistry",
  "MockE3Program",
  "MockComputeProvider",
  "MockDecryptionVerifier",
  "MockCiphertextVerifier",
  "MockPkVerifier",
  "DkgAggregatorVerifier",
  "DecryptionAggregatorVerifier",
  "BfvDecryptionVerifier",
  "BfvPkVerifier",
  "BfvDecryptionVerifierRouter",
  "BfvPkVerifierRouter",
  "Risc0BfvCiphertextVerifier",
  "OpenVmBfvCiphertextVerifier",
  "OpenVmReceiptVerifier",
  "OpenVmHalo2Verifier",
];

/**
 * A record under any of these names means the network accepts some proofs
 * without verifying them, which is what the `mocks` flag claims downstream.
 * The flag reads the records, not the chain, so a record must leave
 * deployed_contracts.json when governance replaces that mock verifier or
 * unregisters that mock program. Otherwise the manifest calls a verified
 * network a mock deployment. Deliberately excludes `MockUSDC`: a mock fee
 * token says nothing about whether proofs are checked, and including it would
 * make a real-verifier deployment report itself as unverified.
 */
const MOCK_NAMES = [
  "MockE3Program",
  "MockDecryptionVerifier",
  "MockCiphertextVerifier",
  "MockPkVerifier",
  "MockDkgFoldAttestationVerifier",
];

type Deployment = { address?: string; blockNumber?: number };
type Entry = { address: string; deploy_block?: number };

const entryFor = (d: Deployment | undefined): Entry | undefined => {
  if (!d?.address) return undefined;
  return d.blockNumber === undefined
    ? { address: d.address }
    : { address: d.address, deploy_block: d.blockNumber };
};

export const generate = (): string => {
  const deployed = JSON.parse(fs.readFileSync(DEPLOYED, "utf8")) as Record<
    string,
    Record<string, Deployment>
  >;

  const networks: Record<string, unknown> = {};

  for (const [network, contracts] of Object.entries(deployed)) {
    const resolved: Record<string, Entry> = {};
    for (const [key, candidates] of Object.entries(CONTRACT_KEYS)) {
      for (const name of candidates) {
        const entry = entryFor(contracts[name]);
        if (entry) {
          resolved[key] = entry;
          break;
        }
      }
    }

    // A manifest that cannot answer the three required config keys is worse
    // than no manifest — it would make `config check` report false staleness.
    for (const required of [
      "interfold",
      "ciphernode_registry",
      "bonding_registry",
    ]) {
      if (!resolved[required]) {
        throw new Error(
          `${network}: cannot resolve required contract "${required}" from ` +
            `deployed_contracts.json (looked for ${CONTRACT_KEYS[required].join(", ")})`,
        );
      }
    }

    // An unknown network would serialise `chain_id: undefined`, which
    // JSON.stringify drops. The CLI reads an absent chain_id as "do not
    // compare", silently disabling the one check that catches a config whose
    // addresses all match but whose RPC points at another network.
    const chainId = CHAIN_IDS[network];
    if (chainId === undefined) {
      throw new Error(
        `${network}: no chain ID known for this network. Add it to CHAIN_IDS in ` +
          `scripts/genManifest.ts so \`interfold config check\` can verify it.`,
      );
    }

    const reference: Record<string, Entry> = {};
    for (const name of REFERENCE_KEYS) {
      const entry = entryFor(contracts[name]);
      if (entry) reference[name] = entry;
    }

    networks[network] = {
      chain_id: chainId,
      mocks: MOCK_NAMES.some((n) => contracts[n]?.address),
      contracts: resolved,
      ...(Object.keys(reference).length > 0 ? { reference } : {}),
    };
  }

  // No timestamp: the output must be a pure function of the input so CI can
  // assert the committed manifest is up to date without a spurious diff.
  return `${JSON.stringify({ schema_version: SCHEMA_VERSION, networks }, null, 2)}\n`;
};

const main = () => {
  const json = generate();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });

  const check = process.argv.includes("--check");
  if (check) {
    const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, "utf8") : "";
    if (current !== json) {
      console.error(
        `${path.relative(REPO_ROOT, OUT)} is out of date. Run \`pnpm gen:manifest\`.`,
      );
      process.exit(1);
    }
    console.log(`${path.relative(REPO_ROOT, OUT)} is up to date.`);
    return;
  }

  fs.writeFileSync(OUT, json);
  console.log(`Wrote ${path.relative(REPO_ROOT, OUT)}`);
};

main();
