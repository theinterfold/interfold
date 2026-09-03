// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Shared helpers for the three-leg CKKS app program specs (salary survey
 * on ParamSet 3, auction on ParamSet 2). Fixtures are REAL proofs from
 * `cargo run -p e3-zk-helpers --example gen_ckks_app_prover -- <app> <dir>`
 * (ONE encryption per app) + `nargo execute` + `bb prove -t evm` for the
 * Greco ct0/ct1 legs and the app leg.
 */
import { network } from "hardhat";

export const HONK_VERIFY_GAS_LIMIT = 100_000_000;

export interface LegFixture {
  proof: string;
  publicInputs: string[];
}

export interface AppFixture {
  ciphertext: string;
  ct0: LegFixture;
  ct1: LegFixture;
  app: LegFixture;
  value: number;
  cap: number;
  mCommitment: string;
  extra: Record<string, string | number>;
}

type Ethers = Awaited<ReturnType<typeof network.connect>>["ethers"];

/** Honk verifiers use external libraries; deploy + link per leg. */
export async function deployVerifier(
  ethers: Ethers,
  solFile: string,
  contractName: string,
) {
  const base = `contracts/verifiers/bfv/honk/${solFile}`;
  const zkLib = await (
    await ethers.getContractFactory(`${base}:ZKTranscriptLib`)
  ).deploy();
  const relLib = await (
    await ethers.getContractFactory(`${base}:RelationsLib`)
  ).deploy();
  const factory = await ethers.getContractFactory(`${base}:${contractName}`, {
    libraries: {
      [`project/${base}:ZKTranscriptLib`]: await zkLib.getAddress(),
      [`project/${base}:RelationsLib`]: await relLib.getAddress(),
    },
  });
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();
  return verifier;
}

export interface Overrides {
  ct0Proof: string;
  ct1Proof: string;
  appProof: string;
  ct0PublicInputs: string[];
  appPublicInputs: string[];
}

/** ABI-encodes the `CkksAppE3ProgramBase` three-leg envelope. */
export function encodeThreeLegInput(
  ethers: Ethers,
  f: AppFixture,
  overrides?: Partial<Overrides>,
): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]", "bytes", "bytes32[]"],
    [
      f.ciphertext,
      overrides?.ct0Proof ?? f.ct0.proof,
      overrides?.ct0PublicInputs ?? f.ct0.publicInputs,
      overrides?.ct1Proof ?? f.ct1.proof,
      f.ct1.publicInputs,
      overrides?.appProof ?? f.app.proof,
      overrides?.appPublicInputs ?? f.app.publicInputs,
    ],
  );
}

/** Flips one hex nibble deep inside a proof. */
export function tamperProof(proof: string): string {
  const i = 200;
  return (
    proof.slice(0, i) + (proof[i] === "0" ? "1" : "0") + proof.slice(i + 1)
  );
}

export function word(value: bigint): string {
  return "0x" + value.toString(16).padStart(64, "0");
}
