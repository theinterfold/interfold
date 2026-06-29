// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import {
  BigNumberish,
  ZeroAddress,
  ZeroHash,
  isHexString,
  zeroPadValue,
} from "ethers";
import fs from "fs";
import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";
import path from "path";

import { readDeploymentArgs } from "../scripts/utils";

function ensureParentDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function decodePlaintextBytesToCsv(bytes: Uint8Array): string {
  if (bytes.length % 8 !== 0) {
    throw new Error("Plaintext output length must be a multiple of 8 bytes");
  }

  const values: string[] = [];
  for (let index = 0; index < bytes.length; index += 8) {
    let value = 0n;
    for (let offset = 0; offset < 8; offset++) {
      value |= BigInt(bytes[index + offset]!) << BigInt(offset * 8);
    }
    values.push(value.toString());
  }

  return values.join(",");
}

async function getRegistryConnection(hre: any) {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;
  const deployment = readDeploymentArgs("CiphernodeRegistryOwnable", chain);

  if (!deployment?.address) {
    throw new Error("CiphernodeRegistryOwnable deployment not found");
  }

  return {
    ethers,
    deployment,
    registry: await ethers.getContractAt(
      "CiphernodeRegistryOwnable",
      deployment.address,
      signer,
    ),
  };
}

async function getInterfoldConnection(hre: any) {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const chain = hre.globalOptions.network;
  const deployment = readDeploymentArgs("Interfold", chain);

  if (!deployment?.address) {
    throw new Error("Interfold deployment not found");
  }

  return {
    ethers,
    interfold: await ethers.getContractAt(
      "Interfold",
      deployment.address,
      signer,
    ),
  };
}

export const requestCommittee = task(
  "committee:new",
  "Request a new ciphernode committee, will use E3 mock contracts by default",
)
  .addOption({
    name: "filter",
    description: "address of filter contract to use",
    defaultValue: ZeroAddress,
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "committeeSize",
    description: "committee size (0=Minimum, 1=Micro, 2=Small)",
    defaultValue: 0,
    type: ArgumentType.INT,
  })
  .addOption({
    name: "inputWindowStart",
    description: "start of input submission window (default: now + 300)",
    defaultValue: Math.floor(Date.now() / 1000) + 300,
    type: ArgumentType.INT,
  })
  .addOption({
    name: "inputWindowEnd",
    description: "deadline for input submission (default: now + 2 days)",
    defaultValue: Math.floor(Date.now() / 1000) + 86400 * 2,
    type: ArgumentType.INT,
  })
  .addOption({
    name: "e3Address",
    description: "address of the E3 program",
    defaultValue: ZeroAddress,
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "e3Params",
    description: "parameters for the E3 program",
    defaultValue: ZeroAddress,
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "computeParams",
    description: "parameters for the compute provider",
    defaultValue: ZeroAddress,
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "customParams",
    description: "parameters for the custom params",
    defaultValue: ZeroAddress,
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "proofAggregationEnabled",
    description: "whether to enable proof aggregation (default: false)",
    defaultValue: false,
    type: ArgumentType.BOOLEAN,
  })
  .setAction(async () => ({
    default: async (
      {
        committeeSize,
        inputWindowStart,
        inputWindowEnd,
        e3Address,
        e3Params: _e3Params,
        computeParams,
        customParams,
        proofAggregationEnabled,
      },
      hre,
    ) => {
      if (![0, 1, 2].includes(committeeSize)) {
        throw new Error(
          "Invalid committee size - expected 0 (Minimum), 1 (Micro), or 2 (Small).",
        );
      }

      const connection = await hre.network.connect();
      const { ethers } = connection;

      const { deployAndSaveInterfold } = await import(
        "../scripts/deployAndSave/interfold"
      );
      const { deployAndSaveMockStableToken } = await import(
        "../scripts/deployAndSave/mockStableToken"
      );

      const { interfold } = await deployAndSaveInterfold({
        hre,
      });

      const { mockStableToken: mockUSDC } = await deployAndSaveMockStableToken({
        hre,
      });

      const [signer] = await ethers.getSigners();
      const interfoldContract = interfold.connect(signer);
      const mockUSDCContract = mockUSDC.connect(signer);

      const interfoldArgs = readDeploymentArgs(
        "Interfold",
        hre.globalOptions.network,
      );

      if (!interfoldArgs) {
        throw new Error("Interfold deployment arguments not found");
      }

      const registryArgs = readDeploymentArgs(
        "CiphernodeRegistryOwnable",
        hre.globalOptions.network,
      );

      if (!registryArgs) {
        throw new Error("CiphernodeRegistry deployment arguments not found");
      }

      const mockE3ProgramArgs = readDeploymentArgs(
        "MockE3Program",
        hre.globalOptions.network,
      );

      // paramSet: 0 = Insecure512, 1 = Secure8192
      const paramSet = 0;

      let computeProviderParams = computeParams;
      const mockDecryptionVerifierArgs = readDeploymentArgs(
        "MockDecryptionVerifier",
        hre.globalOptions.network,
      );
      if (computeProviderParams === ZeroAddress) {
        if (!mockDecryptionVerifierArgs) {
          throw new Error(
            "MockDecryptionVerifier deployment arguments not found",
          );
        }
        computeProviderParams = zeroPadValue(
          mockDecryptionVerifierArgs.address,
          32,
        );
      }

      console.log("Preparing request with the following parameters:", {
        computeParams,
        computeProviderParams,
      });

      const requestParams = {
        committeeSize,
        inputWindow: [inputWindowStart, inputWindowEnd] as [
          BigNumberish,
          BigNumberish,
        ],
        e3Program:
          e3Address === ZeroAddress ? mockE3ProgramArgs!.address : e3Address,
        paramSet,
        computeProviderParams,
        customParams,
        proofAggregationEnabled,
      };

      console.log("Request parameters:", requestParams);

      const fee = await interfoldContract.getE3Quote(requestParams);
      console.log(`E3 fee: ${ethers.formatUnits(fee, 6)} USDC`);

      const usdcBalance = await mockUSDCContract.balanceOf(signer.address);
      console.log(`USDC balance: ${ethers.formatUnits(usdcBalance, 6)} USDC`);

      if (usdcBalance < fee) {
        const mintAmount = fee - usdcBalance + ethers.parseUnits("1000", 6);
        console.log(`Minting ${ethers.formatUnits(mintAmount, 6)} USDC...`);
        const mintTx = await mockUSDCContract.mint(signer.address, mintAmount);
        await mintTx.wait();
        console.log("USDC minted");
      }

      console.log("Approving USDC spending...");
      const approveTx = await mockUSDCContract.approve(
        await interfoldContract.getAddress(),
        fee,
      );
      await approveTx.wait();
      console.log("USDC approved");

      const tx = await interfoldContract.request(requestParams);

      console.log("Requesting committee... ", tx.hash);
      await tx.wait();

      console.log(`Committee requested`);
    },
  }))
  .build();

export const enableE3 = task("interfold:enableE3", "Enable an E3 program")
  .addOption({
    name: "e3Address",
    description: "address of the E3 program",
    defaultValue: ZeroAddress,
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Address }, hre) => {
      const { deployAndSaveInterfold } = await import(
        "../scripts/deployAndSave/interfold"
      );

      const { interfold } = await deployAndSaveInterfold({
        hre,
      });

      const tx = await interfold.registerE3Program(e3Address);

      console.log("Enabling E3 program... ", tx.hash);
      await tx.wait();

      console.log(`E3 program enabled`);
    },
  }))
  .build();

export const publishCommittee = task(
  "committee:publish",
  "Publish the publickey of the committee",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: 0,
    type: ArgumentType.INT,
  })
  .addOption({
    name: "nodes",
    description: "list of node address in the committee, comma separated",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "publicKey",
    description: "public key of the committee",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "pkCommitment",
    description:
      "Hash-based aggregated PK commitment (bytes32 hex); required even when proof aggregation is disabled",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "proof",
    description:
      "ABI-encoded DkgAggregator (EVM) proof (bytes rawProof, bytes32[] publicInputs); pass 0x when proof aggregation is disabled",
    defaultValue: "0x",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, nodes, publicKey, pkCommitment, proof }, hre) => {
      const { deployAndSaveCiphernodeRegistryOwnable } = await import(
        "../scripts/deployAndSave/ciphernodeRegistryOwnable"
      );

      const { deployAndSavePoseidonT3 } = await import(
        "../scripts/deployAndSave/poseidonT3"
      );
      const poseidonT3 = await deployAndSavePoseidonT3({ hre });

      const { ciphernodeRegistry } =
        await deployAndSaveCiphernodeRegistryOwnable({
          hre,
          poseidonT3Address: poseidonT3,
        });

      const nodesToSend = nodes
        .split(",")
        .map((node) => node.trim())
        .filter((node) => node.length > 0);

      if (nodesToSend.length === 0 && nodes.length > 0) {
        throw new Error("Invalid nodes format: no valid addresses found");
      }

      if (!pkCommitment) {
        throw new Error("pkCommitment is required");
      }
      // pkCommitment is stored and emitted unconditionally by the registry, so off-chain
      // consumers can read an unusable key if the values are inconsistent. Validate format
      // and require both publicKey and pkCommitment to be present and non-zero.
      if (!isHexString(pkCommitment, 32)) {
        throw new Error(
          `pkCommitment must be a 32-byte hex string (got ${pkCommitment})`,
        );
      }
      if (pkCommitment === ZeroHash) {
        throw new Error("pkCommitment must not be the zero hash");
      }
      if (!isHexString(publicKey) || publicKey === "0x") {
        throw new Error(
          "publicKey is required and must be a non-empty hex string",
        );
      }

      const tx = await ciphernodeRegistry.publishCommittee(
        e3Id,
        publicKey,
        pkCommitment,
        proof,
        "0x",
      );

      console.log("Publishing committee... ", tx.hash);
      await tx.wait();
      console.log(`Committee public key published`);
    },
  }))
  .build();

export const getCommitteePublicKey = task(
  "committee:getPublicKey",
  "Read the latest published committee public key for an E3",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: 0,
    type: ArgumentType.INT,
  })
  .addOption({
    name: "outFile",
    description: "file to write the raw committee public key bytes to",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, outFile }, hre) => {
      const { ethers, deployment, registry } = await getRegistryConnection(hre);
      const filter = registry.filters.CommitteePublished(e3Id);
      const logs = await registry.queryFilter(
        filter,
        deployment.blockNumber ?? 0,
        "latest",
      );
      const event = logs.at(-1) as any;

      if (!event) {
        throw new Error(`CommitteePublished event not found for e3Id=${e3Id}`);
      }

      const publicKey = (event.args.publicKey ?? event.args[2]) as string;
      if (!publicKey || publicKey === "0x") {
        throw new Error(`Committee public key is empty for e3Id=${e3Id}`);
      }

      if (outFile) {
        ensureParentDir(outFile);
        fs.writeFileSync(outFile, Buffer.from(ethers.getBytes(publicKey)));
      }

      console.log(publicKey);
    },
  }))
  .build();

export const getActiveAggregator = task(
  "committee:getActiveAggregator",
  "Read the active aggregator address for an E3",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: 0,
    type: ArgumentType.INT,
  })
  .setAction(async () => ({
    default: async ({ e3Id }, hre) => {
      const { registry } = await getRegistryConnection(hre);
      const [activeNodes, activeScores]: [string[], bigint[]] =
        await registry.getActiveCommitteeNodes(e3Id);

      if (activeNodes.length !== activeScores.length) {
        throw new Error(
          `Mismatched active committee data for e3Id=${e3Id}: nodes=${activeNodes.length}, scores=${activeScores.length}`,
        );
      }

      if (activeNodes.length === 0) {
        throw new Error(`No active committee nodes found for e3Id=${e3Id}`);
      }

      // The finalized committee is stored in canonical party-id order. Runtime
      // aggregator selection uses the first active party, then failover promotes
      // the next active party. Scores are only for committee selection and must
      // not be used to choose the active aggregator after finalization.
      console.log(activeNodes[0]);
    },
  }))
  .build();

export const publishCiphertext = task(
  "e3:publishCiphertext",
  "Publish ciphertext output for an E3 program",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: 0,
    type: ArgumentType.INT,
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
  .addOption({
    name: "proof",
    description: "proof to publish",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "proofFile",
    description: "file containing proof to publish",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, data, dataFile, proof, proofFile }, hre) => {
      const { deployAndSaveInterfold } = await import(
        "../scripts/deployAndSave/interfold"
      );

      const { interfold } = await deployAndSaveInterfold({
        hre,
      });

      let dataToSend = data;

      if (dataFile) {
        const file = fs.readFileSync(dataFile);
        dataToSend = "0x" + file.toString("hex");
      }

      let proofToSend = proof;

      if (proofFile) {
        const file = fs.readFileSync(proofFile);
        proofToSend = file.toString();
      }

      const tx = await interfold.publishCiphertextOutput(
        e3Id,
        dataToSend,
        proofToSend,
      );

      console.log("Publishing ciphertext... ", tx.hash);
      await tx.wait();

      console.log(`Ciphertext published`);
    },
  }))
  .build();

export const publishPlaintext = task(
  "e3:publishPlaintext",
  "Publish plaintext output for an E3 program",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: 0,
    type: ArgumentType.INT,
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
  .addOption({
    name: "proof",
    description: "proof to publish",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "proofFile",
    description: "file containing proof to publish",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, data, dataFile, proof, proofFile }, hre) => {
      const { deployAndSaveInterfold } = await import(
        "../scripts/deployAndSave/interfold"
      );

      const { interfold } = await deployAndSaveInterfold({
        hre,
      });

      let dataToSend = data;

      if (dataFile) {
        const file = fs.readFileSync(dataFile);
        dataToSend = file.toString();
      }

      let proofToSend = proof;

      if (proofFile) {
        const file = fs.readFileSync(proofFile);
        proofToSend = file.toString();
      }

      const tx = await interfold.publishPlaintextOutput(
        e3Id,
        dataToSend,
        proofToSend,
      );

      console.log("Publishing plaintext... ", tx.hash);
      await tx.wait();

      console.log(`Plaintext published`);
    },
  }))
  .build();

export const getPlaintextOutput = task(
  "e3:getPlaintext",
  "Read the published plaintext output for an E3",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: 0,
    type: ArgumentType.INT,
  })
  .addOption({
    name: "outFile",
    description: "file to write the decoded plaintext CSV output to",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async ({ e3Id, outFile }, hre) => {
      const { ethers, interfold } = await getInterfoldConnection(hre);
      const e3 = await interfold.getE3(e3Id);

      if (!e3.plaintextOutput || e3.plaintextOutput === "0x") {
        throw new Error(`Plaintext output not published for e3Id=${e3Id}`);
      }

      const decoded = decodePlaintextBytesToCsv(
        ethers.getBytes(e3.plaintextOutput),
      );

      if (outFile) {
        ensureParentDir(outFile);
        fs.writeFileSync(outFile, decoded);
      }

      console.log(decoded);
    },
  }))
  .build();
