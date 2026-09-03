// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * CkksE3Program — on-chain Greco gate for CKKS bids.
 *
 * Uses REAL fixtures generated from the live e2e committee:
 * `ckks_encrypt --circuit-inputs` produced the witness JSON against the
 * DKG-published joint public key; `bb prove -t evm` produced the Honk
 * proofs for both legs (fixtures/ckks_greco/verified_input.json).
 *
 * The bb-emitted `public_inputs` carries only the circuit outputs
 * (4 for ct0, 3 for ct1); the verifier's NUMBER_OF_PUBLIC_INPUTS
 * additionally counts the 8 pairing-point fields it reads from the
 * proof tail. The program contract therefore expects 4/3-word arrays.
 */
import { expect } from "chai";
import { readFileSync } from "fs";
import { network } from "hardhat";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const HONK_VERIFY_GAS_LIMIT = 100_000_000;

interface LegFixture {
  proof: string;
  publicInputs: string[];
}
interface GrecoFixture {
  ct0: LegFixture;
  ct1: LegFixture;
  ciphertext: string;
}

const fixturePath = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "ckks_greco",
  "verified_input.json",
);

describe("CkksE3Program (Greco-gated bids)", function () {
  let fixture: GrecoFixture;

  before(function () {
    fixture = JSON.parse(readFileSync(fixturePath, "utf-8")) as GrecoFixture;
  });

  async function deployAll() {
    const { ethers, networkHelpers } = await network.connect();
    await networkHelpers.setBlockGasLimit(HONK_VERIFY_GAS_LIMIT);

    // Honk verifiers use external libraries; deploy + link per leg.
    async function deployVerifier(solFile: string, contractName: string) {
      const base = `contracts/verifiers/bfv/honk/${solFile}`;
      const zkLib = await (
        await ethers.getContractFactory(`${base}:ZKTranscriptLib`)
      ).deploy();
      const relLib = await (
        await ethers.getContractFactory(`${base}:RelationsLib`)
      ).deploy();
      const factory = await ethers.getContractFactory(
        `${base}:${contractName}`,
        {
          libraries: {
            [`project/${base}:ZKTranscriptLib`]: await zkLib.getAddress(),
            [`project/${base}:RelationsLib`]: await relLib.getAddress(),
          },
        },
      );
      const verifier = await factory.deploy();
      await verifier.waitForDeployment();
      return verifier;
    }

    const ct0Verifier = await deployVerifier(
      "UserDataEncryptionCkksCt0Verifier.sol",
      "UserDataEncryptionCkksCt0Verifier",
    );
    const ct1Verifier = await deployVerifier(
      "UserDataEncryptionCkksCt1Verifier.sol",
      "UserDataEncryptionCkksCt1Verifier",
    );
    const program = await (
      await ethers.getContractFactory("CkksE3Program")
    ).deploy(
      await ct0Verifier.getAddress(),
      await ct1Verifier.getAddress(),
    );
    return { ethers, program, ct0Verifier, ct1Verifier };
  }

  function encodeInput(
    ethers: Awaited<ReturnType<typeof network.connect>>["ethers"],
    f: GrecoFixture,
    overrides?: Partial<{
      ct0PublicInputs: string[];
      ct1PublicInputs: string[];
      ct0Proof: string;
      ciphertext: string;
    }>,
  ): string {
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]"],
      [
        overrides?.ciphertext ?? f.ciphertext,
        overrides?.ct0Proof ?? f.ct0.proof,
        overrides?.ct0PublicInputs ?? f.ct0.publicInputs,
        f.ct1.proof,
        overrides?.ct1PublicInputs ?? f.ct1.publicInputs,
      ],
    );
  }

  it("binds the CKKS scheme id", async function () {
    const { program } = await deployAll();
    expect(await program.ENCRYPTION_SCHEME_ID()).to.equal(
      "0x29e51be310a1e9aef3685b008f3062ba01e6c2e5e30729caed85eb4e390d99b0",
    );
  });

  it("accepts a genuinely proven ciphertext and emits commitments", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeInput(ethers, fixture);
    const tx = await program.publishInput(1n, data, {
      gasLimit: HONK_VERIFY_GAS_LIMIT,
    });
    const receipt = await tx.wait();
    const parsed = receipt!.logs
      .map((l) => program.interface.parseLog(l))
      .find((e) => e?.name === "VerifiedInputPublished");
    expect(parsed, "VerifiedInputPublished must fire").to.not.be.undefined;
    expect(parsed!.args.ciphertextHash).to.equal(
      ethers.keccak256(fixture.ciphertext),
    );
    // u commitment shared across legs
    expect(parsed!.args.uCommitment).to.equal(fixture.ct0.publicInputs[3]);
    expect(fixture.ct0.publicInputs[3]).to.equal(fixture.ct1.publicInputs[2]);
  });

  it("rejects a duplicate submission (bid-copy / replay dedup)", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeInput(ethers, fixture);
    await program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
    // Same tuple again (any sender): same u_commitment -> rejected.
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "DuplicateSubmission");
    // A different e3Id keeps its own dedup space.
    await program.publishInput(2n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT });
  });

  it("rejects when the u commitments disagree across legs", async function () {
    const { ethers, program } = await deployAll();
    const badCt1 = [...fixture.ct1.publicInputs];
    badCt1[2] = ethers.zeroPadValue("0x01", 32);
    const data = encodeInput(ethers, fixture, { ct1PublicInputs: badCt1 });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "UCommitmentMismatch");
  });

  it("rejects a tampered proof", async function () {
    const { ethers, program } = await deployAll();
    // flip one byte deep in the ct0 proof
    const tampered =
      fixture.ct0.proof.slice(0, 200) +
      (fixture.ct0.proof[200] === "0" ? "1" : "0") +
      fixture.ct0.proof.slice(201);
    const data = encodeInput(ethers, fixture, { ct0Proof: tampered });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "Ct0ProofInvalid");
  });

  it("rejects tampered public inputs (ciphertext commitment swap)", async function () {
    const { ethers, program } = await deployAll();
    const badCt0 = [...fixture.ct0.publicInputs];
    badCt0[1] = ethers.zeroPadValue("0x02", 32); // fake ct0_commitment
    const data = encodeInput(ethers, fixture, { ct0PublicInputs: badCt0 });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "Ct0ProofInvalid");
  });

  it("rejects wrong public-input counts", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeInput(ethers, fixture, {
      ct0PublicInputs: fixture.ct0.publicInputs.slice(0, 3),
    });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "WrongPublicInputCount");
  });

  it("rejects an empty ciphertext", async function () {
    const { ethers, program } = await deployAll();
    const data = encodeInput(ethers, fixture, { ciphertext: "0x" });
    await expect(
      program.publishInput(1n, data, { gasLimit: HONK_VERIFY_GAS_LIMIT }),
    ).to.be.revertedWithCustomError(program, "InvalidInputEncoding");
  });
});
