// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { isHexString } from "ethers";
import fs from "fs";
import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";

import { readDeploymentArgs } from "../scripts/utils";

export const publishInput = task(
  "e3-program:publishInput",
  "Publish input for an E3 program",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: "0",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "data",
    description: "data to publish",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "dataFile",
    description: "file containing data to publish",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  // MockProgram. Defaults to the address in deployed_contracts.json for the
  // active network; pass --program-address to override.
  .addOption({
    name: "programAddress",
    description:
      "Address of the E3 program (defaults to deployed MockE3Program)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "ciphertextCommitmentFile",
    description: "file containing the 32-byte ciphertext commitment",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async (
      { e3Id, data, dataFile, programAddress, ciphertextCommitmentFile },
      hre,
    ) => {
      const { deployAndSaveMockProgram } = await import(
        "../scripts/deployAndSave/mockProgram"
      );
      const { MockE3ProgramHarness__factory } = await import("../types");

      const { ethers } = await hre.network.connect();
      const [signer] = await ethers.getSigners();

      let actualProgramAddress = programAddress;
      if (!actualProgramAddress) {
        const deployed = readDeploymentArgs(
          "MockE3Program",
          hre.globalOptions.network,
        );
        if (deployed?.address) {
          actualProgramAddress = deployed.address;
        } else {
          actualProgramAddress = await deployAndSaveMockProgram({ hre }).then(
            ({ e3Program }) => e3Program.getAddress(),
          );
        }
      }

      const program = MockE3ProgramHarness__factory.connect(
        actualProgramAddress,
        signer,
      );

      let dataToSend = data;

      if (dataFile) {
        const file = fs.readFileSync(dataFile);
        // Hex-encode binary file contents so ethers ABI-encodes them as `bytes`.
        dataToSend = "0x" + file.toString("hex");
      }

      if (ciphertextCommitmentFile) {
        const commitment =
          "0x" + fs.readFileSync(ciphertextCommitmentFile).toString("hex");
        if (!isHexString(commitment, 32)) {
          throw new Error("Ciphertext commitment file must contain 32 bytes");
        }
        const publishInputWithCommitment = program.getFunction(
          "publishInputWithCommitment",
        );
        await publishInputWithCommitment(e3Id, dataToSend, commitment);
      } else {
        await program.publishInput(e3Id, dataToSend);
      }

      console.log(`Input published to ${actualProgramAddress} (e3Id=${e3Id})`);
    },
  }))
  .build();


/**
 * Publish a Greco-verified CKKS input: reads the ciphertext plus the two
 * bb-emitted proof/public-input files (`bb prove -t evm` output for the
 * `user_data_encryption_ckks_ct0` / `_ct1` circuits), ABI-encodes them in
 * the `CkksE3Program.publishInput` envelope, and submits. The transaction
 * REVERTS unless both Honk proofs verify on-chain and the shared
 * u-commitment matches across legs.
 */
export const publishVerifiedInput = task(
  "e3-program:publishVerifiedInput",
  "Publish a CKKS input gated by on-chain Greco verification",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: "0",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "ciphertextFile",
    description: "file containing the CKKS ciphertext bytes",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "ct0ProofDir",
    description: "bb output dir for the ct0 leg (proof + public_inputs)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "ct1ProofDir",
    description: "bb output dir for the ct1 leg (proof + public_inputs)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "programAddress",
    description:
      "Address of the CkksE3Program (defaults to deployed CkksE3Program)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async (
      { e3Id, ciphertextFile, ct0ProofDir, ct1ProofDir, programAddress },
      hre,
    ) => {
      if (!ciphertextFile || !ct0ProofDir || !ct1ProofDir) {
        throw new Error(
          "--ciphertext-file, --ct0-proof-dir and --ct1-proof-dir are required",
        );
      }

      const { ethers } = await hre.network.connect();
      const [signer] = await ethers.getSigners();

      let actualProgramAddress = programAddress;
      if (!actualProgramAddress) {
        const deployed = readDeploymentArgs(
          "CkksE3Program",
          hre.globalOptions.network,
        );
        if (!deployed?.address) {
          throw new Error(
            "CkksE3Program not deployed on this network; pass --program-address",
          );
        }
        actualProgramAddress = deployed.address;
      }

      const readWords = (file: string): string[] => {
        const buf = fs.readFileSync(file);
        if (buf.length % 32 !== 0) {
          throw new Error(`${file}: length ${buf.length} not a multiple of 32`);
        }
        const words: string[] = [];
        for (let i = 0; i < buf.length; i += 32) {
          words.push("0x" + buf.subarray(i, i + 32).toString("hex"));
        }
        return words;
      };

      const ciphertext = "0x" + fs.readFileSync(ciphertextFile).toString("hex");
      const ct0Proof =
        "0x" + fs.readFileSync(`${ct0ProofDir}/proof`).toString("hex");
      const ct0PublicInputs = readWords(`${ct0ProofDir}/public_inputs`);
      const ct1Proof =
        "0x" + fs.readFileSync(`${ct1ProofDir}/proof`).toString("hex");
      const ct1PublicInputs = readWords(`${ct1ProofDir}/public_inputs`);

      const data = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]"],
        [ciphertext, ct0Proof, ct0PublicInputs, ct1Proof, ct1PublicInputs],
      );

      const program = new ethers.Contract(
        actualProgramAddress,
        [
          "function publishInput(uint256 e3Id, bytes data)",
          "event VerifiedInputPublished(uint256 indexed e3Id, address indexed publisher, bytes32 ciphertextHash, bytes32 ct0Commitment, bytes32 ct1Commitment, bytes32 uCommitment)",
        ],
        signer,
      );

      // Two ZK-Honk verifies fit comfortably in a default 30M block.
      const tx = await program.publishInput(e3Id, data, {
        gasLimit: 29_000_000,
      });
      const receipt = await tx.wait();
      const parsed = receipt.logs
        .map((l: { topics: readonly string[]; data: string }) => {
          try {
            return program.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find(
          (e: { name: string } | null) =>
            e?.name === "VerifiedInputPublished",
        );
      if (!parsed) {
        throw new Error(
          "publishInput succeeded but VerifiedInputPublished was not emitted",
        );
      }
      console.log(
        `Verified input published to ${actualProgramAddress} (e3Id=${e3Id})`,
      );
      console.log(`  ciphertextHash: ${parsed.args.ciphertextHash}`);
      console.log(`  ct0Commitment:  ${parsed.args.ct0Commitment}`);
      console.log(`  ct1Commitment:  ${parsed.args.ct1Commitment}`);
      console.log(`  uCommitment:    ${parsed.args.uCommitment}`);
    },
  }))
  .build();

/**
 * Publish a Greco-verified CKKS input from a participant's
 * `submission.json` (the `ckks_participant` CLI output: paramSet,
 * ciphertextHex and both legs' proof/publicInputs). ABI-encodes the
 * `CkksE3Program.publishInput` envelope and submits. The transaction
 * REVERTS unless both Honk proofs verify on-chain and the shared
 * u-commitment matches; a repeated u-commitment reverts with
 * `DuplicateSubmission` (printed as DUPLICATE_SUBMISSION for callers).
 */
export const publishInputFromSubmission = task(
  "program:publish-input",
  "Publish a CKKS participant submission.json through the Greco gate",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: "0",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "dataFile",
    description: "path to the participant CLI's submission.json",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "programAddress",
    description:
      "CkksE3Program address (defaults to the deployment for the submission's paramSet)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, dataFile, programAddress }, hre) => {
      if (!dataFile) throw new Error("--data-file is required");
      const submission = JSON.parse(fs.readFileSync(dataFile, "utf-8")) as {
        paramSet: number;
        ciphertextHex: string;
        ct0: { proofHex: string; publicInputs: string[] };
        ct1: { proofHex: string; publicInputs: string[] };
      };

      const { ethers } = await hre.network.connect();
      const [signer] = await ethers.getSigners();

      let actualProgramAddress = programAddress;
      if (!actualProgramAddress) {
        const suffix =
          Number(submission.paramSet) === 0 ? "" : `Ps${submission.paramSet}`;
        const name = `CkksE3Program${suffix}`;
        const deployed = readDeploymentArgs(name, hre.globalOptions.network);
        if (!deployed?.address) {
          throw new Error(
            `${name} not deployed on this network; pass --program-address`,
          );
        }
        actualProgramAddress = deployed.address;
      }

      const data = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]"],
        [
          submission.ciphertextHex,
          submission.ct0.proofHex,
          submission.ct0.publicInputs,
          submission.ct1.proofHex,
          submission.ct1.publicInputs,
        ],
      );

      const program = new ethers.Contract(
        actualProgramAddress,
        [
          "function publishInput(uint256 e3Id, bytes data)",
          "error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)",
          "event VerifiedInputPublished(uint256 indexed e3Id, address indexed publisher, bytes32 ciphertextHash, bytes32 ct0Commitment, bytes32 ct1Commitment, bytes32 uCommitment)",
        ],
        signer,
      );

      try {
        // Preflight with a static call: a mined revert carries no error
        // data, but eth_call surfaces the custom error selector — this
        // is where DuplicateSubmission (and proof failures) are caught.
        await program.publishInput.staticCall(e3Id, data, {
          gasLimit: 29_000_000,
        });
        // Two ZK-Honk verifies fit comfortably in a default 30M block.
        const tx = await program.publishInput(e3Id, data, {
          gasLimit: 29_000_000,
        });
        const receipt = await tx.wait();
        const parsed = receipt.logs
          .map((l: { topics: readonly string[]; data: string }) => {
            try {
              return program.interface.parseLog(l);
            } catch {
              return null;
            }
          })
          .find(
            (e: { name: string } | null) => e?.name === "VerifiedInputPublished",
          );
        if (!parsed) {
          throw new Error(
            "publishInput succeeded but VerifiedInputPublished was not emitted",
          );
        }
        console.log(`ACCEPTED tx=${receipt.hash}`);
        console.log(`  program:        ${actualProgramAddress}`);
        console.log(`  ciphertextHash: ${parsed.args.ciphertextHash}`);
        console.log(`  uCommitment:    ${parsed.args.uCommitment}`);
      } catch (err) {
        // Surface the dedup revert as a stable machine-readable marker.
        const revertData = (() => {
          const e = err as {
            data?: string;
            info?: { error?: { data?: string } };
          };
          if (typeof e?.data === "string") return e.data;
          if (typeof e?.info?.error?.data === "string")
            return e.info.error.data;
          return null;
        })();
        const parsedError = revertData
          ? (() => {
              try {
                return program.interface.parseError(revertData);
              } catch {
                return null;
              }
            })()
          : null;
        if (parsedError?.name === "DuplicateSubmission") {
          console.error(
            `DUPLICATE_SUBMISSION uCommitment=${parsedError.args.uCommitment}`,
          );
          process.exitCode = 3;
          return;
        }
        throw err;
      }
    },
  }))
  .build();

// Wire the local MockE3ProgramHarness to Interfold so `publishInput` forwards to
// `publishCiphertextOutput`. Off by default; the proof-aggregation integration
// flow opts in by calling this once after deploy. The non-aggregation `base`
// flow does NOT wire it, preserving the pre-existing fake_encrypt path which
// posts the ciphertext via `e3:publishCiphertext` directly.
export const setMockProgramInterfold = task(
  "e3-program:setMockInterfold",
  "Wire the mock test harness to Interfold for proof-aggregation tests",
)
  .setAction(async () => ({
    default: async (_args, hre) => {
      const { ethers } = await hre.network.connect();
      const [signer] = await ethers.getSigners();
      const network = hre.globalOptions.network;

      const mockArgs = readDeploymentArgs("MockE3Program", network);
      const interfoldArgs = readDeploymentArgs("Interfold", network);
      if (!mockArgs?.address || !interfoldArgs?.address) {
        throw new Error(
          "MockE3Program or Interfold deployment not found; deploy first.",
        );
      }

      // Use ABI fragments directly so this works even when typechain types
      // haven't been regenerated.
      const mockProgram = new ethers.Contract(
        mockArgs.address,
        [
          "function interfold() view returns (address)",
          "function setInterfold(address) external",
        ],
        signer,
      );
      const current: string = await mockProgram.interfold();
      if (current.toLowerCase() === interfoldArgs.address.toLowerCase()) {
        console.log(
          `MockE3ProgramHarness already wired to ${interfoldArgs.address}`,
        );
        return;
      }
      await mockProgram.setInterfold(interfoldArgs.address);
      console.log(
        `MockE3ProgramHarness ${mockArgs.address} → Interfold ${interfoldArgs.address}`,
      );
    },
  }))
  .build();
