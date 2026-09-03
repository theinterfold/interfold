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

const THREE_LEG_ENVELOPE = [
  "bytes",
  "bytes",
  "bytes32[]",
  "bytes",
  "bytes32[]",
  "bytes",
  "bytes32[]",
];

/**
 * Publish a THREE-leg CKKS app submission (Greco ct0 + ct1 + app-validity
 * proof) through `CkksSalaryE3Program` / `CkksAuctionE3Program`. The
 * `submission.json` carries `app` ("salary" | "auction"), `ciphertextHex`
 * and the legs `ct0` / `ct1` / `appLeg`, each `{ proofHex, publicInputs }`.
 * The transaction REVERTS unless every proof verifies, the commitments
 * bind across legs, the cap matches, and (auction) `msg.sender` is the
 * proven address and the balance root for the E3 is set.
 */
export const publishAppInputFromSubmission = task(
  "program:publish-app-input",
  "Publish a three-leg CKKS app submission.json through the app gate",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3",
    defaultValue: "0",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "dataFile",
    description: "path to the participant's submission.json",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "programAddress",
    description:
      "Program address (defaults to the deployment for the submission's app)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, dataFile, programAddress }, hre) => {
      if (!dataFile) throw new Error("--data-file is required");
      const submission = JSON.parse(fs.readFileSync(dataFile, "utf-8")) as {
        app: "salary" | "auction";
        ciphertextHex: string;
        ct0: { proofHex: string; publicInputs: string[] };
        ct1: { proofHex: string; publicInputs: string[] };
        appLeg: { proofHex: string; publicInputs: string[] };
      };
      const { ethers } = await hre.network.connect();
      const [signer] = await ethers.getSigners();

      let actualProgramAddress = programAddress;
      if (!actualProgramAddress) {
        const name =
          submission.app === "auction"
            ? "CkksAuctionE3Program"
            : "CkksSalaryE3Program";
        const deployed = readDeploymentArgs(name, hre.globalOptions.network);
        if (!deployed?.address) {
          throw new Error(
            `${name} not deployed on this network; pass --program-address`,
          );
        }
        actualProgramAddress = deployed.address;
      }

      const data = ethers.AbiCoder.defaultAbiCoder().encode(
        THREE_LEG_ENVELOPE,
        [
          submission.ciphertextHex,
          submission.ct0.proofHex,
          submission.ct0.publicInputs,
          submission.ct1.proofHex,
          submission.ct1.publicInputs,
          submission.appLeg.proofHex,
          submission.appLeg.publicInputs,
        ],
      );
      const program = new ethers.Contract(
        actualProgramAddress,
        [
          "function publishInput(uint256 e3Id, bytes data)",
          "error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)",
          "event VerifiedInputPublished(uint256 indexed e3Id, address indexed publisher, bytes32 ciphertextHash, bytes32 ct0Commitment, bytes32 ct1Commitment, bytes32 mCommitment, bytes32 uCommitment)",
        ],
        signer,
      );
      // Preflight: eth_call surfaces custom-error selectors a mined revert
      // would not. Three ZK-Honk verifies (~3M gas) fit in a 30M block.
      await program.publishInput.staticCall(e3Id, data, {
        gasLimit: 29_000_000,
      });
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
      console.log(`  program:      ${actualProgramAddress}`);
      console.log(`  mCommitment:  ${parsed.args.mCommitment}`);
      console.log(`  uCommitment:  ${parsed.args.uCommitment}`);
    },
  }))
  .build();

/**
 * Publish the balance Merkle root for an auction E3 (owner only, once).
 * The root is the Poseidon binary tree over `poseidon([address, balance])`
 * leaves — see `e3_zk_helpers::threshold::ckks_app_validity::BalanceTree`.
 */
export const setAuctionBalanceRoot = task(
  "program:set-balance-root",
  "Set the balance Merkle root for a CkksAuctionE3Program E3",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3",
    defaultValue: "0",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "root",
    description: "32-byte hex root",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "programAddress",
    description: "CkksAuctionE3Program address (defaults to deployment)",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, root, programAddress }, hre) => {
      if (!isHexString(root, 32)) throw new Error("--root must be 32 bytes");
      const { ethers } = await hre.network.connect();
      const [signer] = await ethers.getSigners();
      let actualProgramAddress = programAddress;
      if (!actualProgramAddress) {
        const deployed = readDeploymentArgs(
          "CkksAuctionE3Program",
          hre.globalOptions.network,
        );
        if (!deployed?.address) {
          throw new Error(
            "CkksAuctionE3Program not deployed on this network; pass --program-address",
          );
        }
        actualProgramAddress = deployed.address;
      }
      const program = new ethers.Contract(
        actualProgramAddress,
        ["function setBalanceRoot(uint256 e3Id, bytes32 root)"],
        signer,
      );
      const tx = await program.setBalanceRoot(e3Id, root);
      await tx.wait();
      console.log(`balance root set for e3Id=${e3Id}: ${root}`);
    },
  }))
  .build();
