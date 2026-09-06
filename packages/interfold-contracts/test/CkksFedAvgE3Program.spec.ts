// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksFedAvgE3Program: FIVE-leg gate (Greco ct0 + ct1 for the GRADIENT
 * ciphertext, Greco ct0 + ct1 for the COUNT ciphertext, and the fedavg
 * validity leg proving `gradient_block(g)` with `sum g_j^2 <= B` and
 * `constant(n)` with `1 <= n < 1024`) on ParamSet 5 (N=512, 3 limbs,
 * delta=2^40), driven by a REAL fixture (update
 * [0.5,-0.25,0.75,-1,0.125,0,-0.5,0.3], count 137, bound 2.5, slot 0,
 * Alice = hardhat account #0).
 *
 * Fixture recipe: `scripts/ckks-fedavg-fixtures.sh` (witness → nargo →
 * bb write_vk/prove -t evm → fixture JSON), then
 * `scripts/generate-verifiers.ts --write --no-compile --circuits ckks_fedavg_validity_ps5`.
 */
import { expect } from "chai";
import { readFileSync } from "fs";
import { network } from "hardhat";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import type { LegFixture } from "./helpers/ckksApp";
import {
  HONK_VERIFY_GAS_LIMIT,
  deployVerifier,
  tamperProof,
  word,
} from "./helpers/ckksApp";

const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "ckks_fedavg_ps5",
);

interface PairFixture {
  ct0: LegFixture;
  ct1: LegFixture;
}

interface FedAvgFixture {
  ciphertextG: string;
  ciphertextC: string;
  gradient: PairFixture;
  count: PairFixture;
  app: LegFixture;
  d: number;
  index: number;
  countValue: number;
  update: number[];
  updateF64: number[];
  squaredNorm: number;
  squaredNormF64: number;
  normBound: number;
  normBoundWord: string;
  mCommitmentG: string;
  mCommitmentC: string;
  extra: { address: string; addressWord: string; indexWord: string };
}

interface OverBoundFixture {
  update: number[];
  squaredNorm: number;
  normBound: number;
  appPublicInputs: string[];
  nargoExecute: { exitCode: number; failedAssertion: string };
}

type Ethers = Awaited<ReturnType<typeof network.connect>>["ethers"];

interface Overrides {
  ct0ProofG: string;
  ct1ProofG: string;
  ct0ProofC: string;
  ct1ProofC: string;
  appProof: string;
  appPublicInputs: string[];
  ct0PublicInputsC: string[];
}

/** ABI-encodes the five-leg envelope `CkksFedAvgE3Program.publishInput` takes. */
function encodeFiveLegInput(
  ethers: Ethers,
  f: FedAvgFixture,
  o?: Partial<Overrides>,
): string {
  // Matches `Update { GrecoPair gradient; GrecoPair count; bytes appProof;
  // bytes32[] appPub; }` — nested tuples, each with its own head/tail.
  const grecoPair = "(bytes,bytes,bytes32[],bytes,bytes32[])";
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [`tuple(${grecoPair},${grecoPair},bytes,bytes32[])`],
    [
      [
        [
          f.ciphertextG,
          o?.ct0ProofG ?? f.gradient.ct0.proof,
          f.gradient.ct0.publicInputs,
          o?.ct1ProofG ?? f.gradient.ct1.proof,
          f.gradient.ct1.publicInputs,
        ],
        [
          f.ciphertextC,
          o?.ct0ProofC ?? f.count.ct0.proof,
          o?.ct0PublicInputsC ?? f.count.ct0.publicInputs,
          o?.ct1ProofC ?? f.count.ct1.proof,
          f.count.ct1.publicInputs,
        ],
        o?.appProof ?? f.app.proof,
        o?.appPublicInputs ?? f.app.publicInputs,
      ],
    ],
  );
}

/** The FLAT 12-field envelope the contract must refuse. */
function encodeFlatInput(ethers: Ethers, f: FedAvgFixture): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]", "bytes", "bytes", "bytes32[]", "bytes", "bytes32[]", "bytes", "bytes32[]"],
    [
      f.ciphertextG, f.gradient.ct0.proof, f.gradient.ct0.publicInputs, f.gradient.ct1.proof, f.gradient.ct1.publicInputs,
      f.ciphertextC, f.count.ct0.proof, f.count.ct0.publicInputs, f.count.ct1.proof, f.count.ct1.publicInputs,
      f.app.proof, f.app.publicInputs,
    ],
  );
}

/** Big-endian int128 words → bytes (what `e3_trckks::program::encode_fixed_point_output` emits). */
function encodeOutput(words: bigint[]): string {
  const two128 = 1n << 128n;
  return (
    "0x" +
    words
      .map((w) => ((w + two128) % two128).toString(16).padStart(32, "0"))
      .join("")
  );
}

describe("CkksFedAvgE3Program (two Greco pairs + fedavg validity, ParamSet 5)", function () {
  let fixture: FedAvgFixture;
  let overBound: OverBoundFixture;

  before(function () {
    fixture = JSON.parse(
      readFileSync(join(fixtureDir, "verified_input.json"), "utf-8"),
    ) as FedAvgFixture;
    overBound = JSON.parse(
      readFileSync(join(fixtureDir, "over_norm_bound.json"), "utf-8"),
    ) as OverBoundFixture;
  });

  async function deployAll() {
    const { ethers, networkHelpers } = await network.connect();
    await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);
    const ct0 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt0Ps5Verifier.sol",
      "UserDataEncryptionCkksCt0Ps5Verifier",
    );
    const ct1 = await deployVerifier(
      ethers,
      "UserDataEncryptionCkksCt1Ps5Verifier.sol",
      "UserDataEncryptionCkksCt1Ps5Verifier",
    );
    const app = await deployVerifier(
      ethers,
      "CkksFedavgValidityPs5Verifier.sol",
      "CkksFedavgValidityPs5Verifier",
    );
    const { CkksFedAvgE3Program__factory } = await import("../types");
    const [deployer, bob, carol] = await ethers.getSigners();
    const program = await new CkksFedAvgE3Program__factory(deployer).deploy(
      await ct0.getAddress(),
      await ct1.getAddress(),
      await app.getAddress(),
    );
    return { ethers, program, alice: deployer, bob, carol };
  }

  /** Registers round 7 with Alice at slot 0, Bob at slot 1, Carol at slot 2. */
  async function registerDefault(
    program: Awaited<ReturnType<typeof deployAll>>["program"],
    clients: string[],
    opts?: { normBound?: bigint; minClients?: bigint },
  ) {
    await program.registerRound(
      7n,
      opts?.normBound ?? BigInt(fixture.normBound),
      opts?.minClients ?? 1n,
      clients,
    );
  }

  it("fixture legs are bound: two u commitments, two m commitments, norm-bound + index words", function () {
    for (const pair of [fixture.gradient, fixture.count]) {
      expect(pair.ct0.publicInputs).to.have.length(4);
      expect(pair.ct1.publicInputs).to.have.length(3);
      expect(pair.ct0.publicInputs[3]).to.equal(pair.ct1.publicInputs[2]);
    }
    expect(fixture.app.publicInputs).to.have.length(5);
    expect(fixture.gradient.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[3]);
    expect(fixture.count.ct0.publicInputs[2]).to.equal(fixture.app.publicInputs[4]);
    expect(fixture.app.publicInputs[3]).to.equal(fixture.mCommitmentG);
    expect(fixture.app.publicInputs[4]).to.equal(fixture.mCommitmentC);
    expect(fixture.mCommitmentG).to.not.equal(fixture.mCommitmentC);
    expect(fixture.gradient.ct0.publicInputs[3]).to.not.equal(fixture.count.ct0.publicInputs[3]);
    expect(fixture.app.publicInputs[0]).to.equal(word(BigInt(fixture.normBound)));
    expect(fixture.app.publicInputs[1]).to.equal(fixture.extra.addressWord);
    expect(fixture.app.publicInputs[2]).to.equal(word(BigInt(fixture.index)));
    // The update and the count are PRIVATE: never public inputs (only the
    // bound, the address, the slot and the two commitments are).
    expect(fixture.app.publicInputs).to.not.include(word(BigInt(fixture.countValue)));
    expect(fixture.app.publicInputs).to.not.include(word(BigInt(fixture.squaredNorm)));
    for (const g of fixture.update) {
      if (g > 0) expect(fixture.app.publicInputs).to.not.include(word(BigInt(g)));
    }
    expect(fixture.countValue).to.equal(137);
    expect(fixture.d).to.equal(8);
    expect(fixture.squaredNorm).to.be.lessThan(fixture.normBound);
    expect(fixture.normBound).to.equal(Math.floor(2.5 * 2 ** 32));
  });

  it("accepts a genuine update from the registered sender at its slot", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    expect((await alice.getAddress()).toLowerCase()).to.equal(
      String(fixture.extra.address),
    );
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()]);
    const data = encodeFiveLegInput(ethers, fixture);
    const tx = await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    const receipt = await tx.wait();
    const parsed = receipt!.logs
      .map((l: { topics: readonly string[]; data: string }) => program.interface.parseLog(l))
      .find((e: { name: string } | null) => e?.name === "UpdatePublished");
    expect(parsed, "UpdatePublished must fire").to.not.be.undefined;
    expect(parsed!.args.client).to.equal(await alice.getAddress());
    expect(parsed!.args.index).to.equal(0n);
    expect(parsed!.args.mCommitmentGrad).to.equal(fixture.mCommitmentG);
    expect(parsed!.args.mCommitmentCount).to.equal(fixture.mCommitmentC);
    expect(parsed!.args.gradientCiphertextHash).to.equal(ethers.keccak256(fixture.ciphertextG));
    expect(parsed!.args.countCiphertextHash).to.equal(ethers.keccak256(fixture.ciphertextC));
    expect(await program.submissionCount(7n)).to.equal(1n);
    const stored = await program.submissionAt(7n, 0n);
    expect(stored.client).to.equal(await alice.getAddress());
    expect(stored.uCommitmentGrad).to.equal(fixture.gradient.ct0.publicInputs[3]);
    expect(stored.uCommitmentCount).to.equal(fixture.count.ct0.publicInputs[3]);
    expect(await program.hasSubmitted(7n, await alice.getAddress())).to.equal(true);
  });

  it("rejects the flat 12-field envelope (the ABI is a nested tuple)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()]);
    await expect(
      program.publishInput(7n, encodeFlatInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revert(ethers);
  });

  it("rejects an update before the round is registered", async function () {
    const { ethers, program } = await deployAll();
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "RoundNotRegistered");
  });

  it("rejects a norm-bound mismatch (round bound differs; forged word breaks the proof)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    // Round registered with a tighter bound (1.0 * 2^32) than the proof carries.
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()], {
      normBound: 1n << 32n,
    });
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongNormBound");
    // Relabelling the norm-bound word to the round's breaks the app proof.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[0] = word(1n << 32n);
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects an update relayed by a different sender (wrong-sender)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()]);
    const data = encodeFiveLegInput(ethers, fixture);
    await expect(
      program.connect(bob).publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongSender");
    // Bob cannot relabel Alice's proof with his own address either.
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[1] = word(BigInt(await bob.getAddress()));
    appPublicInputs[2] = word(1n);
    await expect(
      program.connect(bob).publishInput(7n, encodeFiveLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("rejects a wrong slot index and an unregistered sender", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await bob.getAddress(), await alice.getAddress()]);
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongIndex");
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[2] = word(1n);
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
    const { ethers: e2, program: p2, bob: b2 } = await deployAll();
    await registerDefault(p2, [await b2.getAddress()]);
    await expect(
      p2.publishInput(7n, encodeFiveLegInput(e2, fixture), { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(p2, "NotRegistered");
  });

  it("rejects each tampered leg", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()]);
    for (const [key, error, proof] of [
      ["ct0ProofG", "Ct0ProofInvalid", fixture.gradient.ct0.proof],
      ["ct1ProofG", "Ct1ProofInvalid", fixture.gradient.ct1.proof],
      ["ct0ProofC", "Ct0ProofInvalid", fixture.count.ct0.proof],
      ["ct1ProofC", "Ct1ProofInvalid", fixture.count.ct1.proof],
      ["appProof", "AppProofInvalid", fixture.app.proof],
    ] as const) {
      const data = encodeFiveLegInput(ethers, fixture, { [key]: tamperProof(proof) });
      await expect(
        program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
        key,
      ).to.be.revertedWithCustomError(program, error);
    }
  });

  it("rejects a cross-leg m_commitment mismatch on either ciphertext", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()]);
    const appPublicInputs = [...fixture.app.publicInputs];
    appPublicInputs[3] = fixture.gradient.ct0.publicInputs[1];
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "MCommitmentMismatch");
    await expect(
      program.publishInput(
        7n,
        encodeFiveLegInput(ethers, fixture, { ct0PublicInputsC: fixture.gradient.ct0.publicInputs }),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      ),
    ).to.be.revertedWithCustomError(program, "UCommitmentMismatch");
  });

  it("rejects a duplicate update (same sender / same u commitments)", async function () {
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()]);
    const data = encodeFiveLegInput(ethers, fixture);
    await program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    await expect(
      program.publishInput(7n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "AlreadySubmitted");
  });

  it("an over-bound update has no proof: the circuit rejects it at proving time", async function () {
    expect(overBound.squaredNorm).to.be.greaterThan(overBound.normBound);
    expect(overBound.nargoExecute.exitCode).to.equal(1);
    expect(overBound.nargoExecute.failedAssertion).to.contain("norm_bound - norm");
    const { ethers, program, alice, bob } = await deployAll();
    await registerDefault(program, [await alice.getAddress(), await bob.getAddress()], {
      normBound: BigInt(overBound.normBound),
    });
    const appPublicInputs = [...overBound.appPublicInputs];
    appPublicInputs[3] = fixture.app.publicInputs[3];
    appPublicInputs[4] = fixture.app.publicInputs[4];
    await expect(
      program.publishInput(7n, encodeFiveLegInput(ethers, fixture, { appPublicInputs }), {
        gasLimit: HONK_VERIFY_GAS_LIMIT,
      }),
    ).to.be.revertedWithCustomError(program, "AppProofInvalid");
  });

  it("only the owner registers a round, once, with a valid bound/min/list", async function () {
    const { program, alice, bob, carol } = await deployAll();
    const a = await alice.getAddress();
    const b = await bob.getAddress();
    const c = await carol.getAddress();
    const bound = BigInt(fixture.normBound);
    await expect(program.connect(bob).registerRound(7n, bound, 1n, [a, b])).to.be.revertedWithCustomError(program, "NotOwner");
    await expect(program.registerRound(7n, 0n, 1n, [a, b])).to.be.revertedWithCustomError(program, "InvalidNormBound");
    await expect(program.registerRound(7n, 1n << 40n, 1n, [a, b])).to.be.revertedWithCustomError(program, "InvalidNormBound");
    await expect(program.registerRound(7n, bound, 1n, [])).to.be.revertedWithCustomError(program, "NoClients");
    await expect(program.registerRound(7n, bound, 0n, [a, b])).to.be.revertedWithCustomError(program, "InvalidMinClients");
    await expect(program.registerRound(7n, bound, 3n, [a, b])).to.be.revertedWithCustomError(program, "InvalidMinClients");
    await expect(program.registerRound(7n, bound, 1n, [a, a])).to.be.revertedWithCustomError(program, "DuplicateClient");
    await program.registerRound(7n, bound, 3n, [a, b, c]);
    await expect(program.registerRound(7n, bound, 3n, [a, b, c])).to.be.revertedWithCustomError(program, "RoundAlreadyRegistered");
    expect(await program.clients(7n)).to.deep.equal([a, b, c]);
    expect(await program.clientSlot(7n, c)).to.equal(3n);
    const r = await program.round(7n);
    expect(r.normBound).to.equal(bound);
    expect(r.minClients).to.equal(3n);
    expect(r.registered).to.equal(true);
  });

  it("decodes the 64-word int128 output and computes the weighted mean", async function () {
    const { program } = await deployAll();
    // Two clients: n = [137, 63], g_0 = [0.5, -0.25]; total 200, sum n·g_0 = 68.5 - 15.75 = 52.75.
    const words = new Array<bigint>(64).fill(0n);
    words[1] = 527500n; // 52.75 at 4 decimals
    words[2] = -1000000n; // -100.0
    words[9] = 2000000n; // 200 clients-samples at 4 decimals (D + 1 = 9)
    const out = encodeOutput(words);
    const decoded = await program.decodeOutput(out);
    expect(decoded[1]).to.equal(527500n);
    expect(decoded[2]).to.equal(-1000000n);
    const [mean, total] = await program.meanFromOutput(out);
    expect(total).to.equal(200n);
    expect(mean[0]).to.equal(2637n); // 0.26375 → 0.2637 (toward zero)
    expect(mean[1]).to.equal(-5000n); // -0.5
    expect(mean[7]).to.equal(0n);
    await expect(program.decodeOutput(out.slice(0, -32))).to.be.revertedWithCustomError(program, "InvalidOutputLength");
    const zero = encodeOutput(new Array<bigint>(64).fill(0n));
    await expect(program.meanFromOutput(zero)).to.be.revertedWithCustomError(program, "ZeroTotalCount");
  });
});
