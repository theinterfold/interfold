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
import { stageMockDataAvailabilityObject } from "./mockDataAvailability";

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
  .addOption({
    name: "mockDataAvailabilityDirectory",
    description: "test-only directory served by the local mock DA endpoint",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async (
      {
        e3Id,
        data,
        dataFile,
        programAddress,
        ciphertextCommitmentFile,
        mockDataAvailabilityDirectory,
      },
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

      if (mockDataAvailabilityDirectory) {
        stageMockDataAvailabilityObject(
          mockDataAvailabilityDirectory,
          dataToSend,
        );
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
