// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import {
  BigNumberish,
  type Log,
  MaxUint256,
  ZeroAddress,
  ZeroHash,
  getBytes,
  isHexString,
  keccak256,
  zeroPadValue,
} from "ethers";
import fs from "fs";
import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";
import path from "path";

import { readDeploymentArgs } from "../scripts/utils";
import { assembleUniqueCommitteePublicKey } from "./committeePublicKey";
import { stageMockDataAvailabilityObject } from "./mockDataAvailability";

function cryptoConfigIdForParamSet(paramSet: number): string {
  if (paramSet === 0) {
    return "0x04f3677e73b0f5066d6caf5cbd92e3fb2e38338edaf5cfc971ab28f7b684da78";
  }
  if (paramSet === 1) {
    return "0xd9c86e581f8291ffb5b63595600e8d096ed30b16e2e0a6634a76c22b1f58fb4e";
  }
  throw new Error(`Unsupported BFV parameter set: ${paramSet}`);
}

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

async function fulfillConfiguredLocalRandomness(
  hre: any,
  e3Id: bigint,
  requestBlockNumber: number,
): Promise<void> {
  const mockDeployment = readDeploymentArgs(
    "MockRandomnessProvider",
    hre.globalOptions.network,
  );
  const chainlinkDeployment = readDeploymentArgs(
    "ChainlinkVrfRandomnessProvider",
    hre.globalOptions.network,
  );

  const { ethers, registry } = await getRegistryConnection(hre);
  const configuredProvider = await registry.randomnessProvider();
  const selected = [
    { kind: "mock", deployment: mockDeployment },
    { kind: "coordinator", deployment: chainlinkDeployment },
  ].find(
    ({ deployment }) =>
      deployment?.address?.toLowerCase() === configuredProvider.toLowerCase(),
  );
  if (!selected) {
    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    if (chainId === 1_337 || chainId === 31_337) {
      throw new Error(
        `Configured local randomness provider ${configuredProvider} has no deployment record`,
      );
    }
    return;
  }
  const selectedDeployment = selected.deployment;
  if (!selectedDeployment) {
    throw new Error(
      `Configured local randomness provider ${configuredProvider} has no deployment record`,
    );
  }

  const [signer] = await ethers.getSigners();
  const provider = await ethers.getContractAt(
    selected.kind === "mock"
      ? "MockRandomnessProvider"
      : "ChainlinkVrfRandomnessProvider",
    selectedDeployment.address,
    signer,
  );
  const requestId = await provider.requestIdByE3Id(e3Id);
  if (requestId === 0n) {
    throw new Error(`Mock randomness request not found for E3 ${e3Id}`);
  }

  const [alreadyFulfilled] = await provider.getRandomness(requestId);
  if (!alreadyFulfilled) {
    const randomWord = BigInt(
      ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["string", "uint256", "uint256"],
          ["interfold-local-randomness", e3Id, requestId],
        ),
      ),
    );
    const fulfillment =
      selected.kind === "mock"
        ? await provider.fulfill(requestId, randomWord)
        : await (
            await ethers.getContractAt(
              "ChainlinkVrfCoordinatorV2_5Mock",
              await provider.s_vrfCoordinator(),
              signer,
            )
          ).fulfillRandomWordsWithOverride(requestId, configuredProvider, [
            randomWord,
          ]);
    const receipt = await fulfillment.wait();
    if (!receipt) {
      throw new Error(
        `Local randomness fulfillment was not mined for E3 ${e3Id}`,
      );
    }
    if (receipt.blockNumber <= requestBlockNumber) {
      throw new Error(
        `Local randomness for E3 ${e3Id} must be fulfilled after request block ${requestBlockNumber}`,
      );
    }
  }

  const [usable] = await registry.sortitionSeed(e3Id);
  if (!usable) {
    throw new Error(`Registry did not accept local randomness for E3 ${e3Id}`);
  }
  console.log(`Local randomness fulfilled for E3 ${e3Id}`);
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

      const { deployAndSaveMockStableToken } = await import(
        "../scripts/deployAndSave/mockStableToken"
      );

      const { interfold } = await getInterfoldConnection(hre);

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

      const quoteParams = {
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
        expectedFeeToken: await mockUSDCContract.getAddress(),
        expectedCryptoConfigId: cryptoConfigIdForParamSet(paramSet),
        maxFee: MaxUint256,
      };

      const fee = await interfoldContract.getE3Quote(quoteParams);
      const requestParams = { ...quoteParams, maxFee: fee };
      console.log("Request parameters:", requestParams);
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
      const receipt = await tx.wait();
      if (!receipt) {
        throw new Error("Committee request transaction was not mined");
      }

      const interfoldAddress = (
        await interfoldContract.getAddress()
      ).toLowerCase();
      const requestedTopic =
        interfoldContract.interface.getEvent("E3Requested").topicHash;
      const requestedLog = receipt.logs.find(
        (log: Log) =>
          log.address.toLowerCase() === interfoldAddress &&
          log.topics[0] === requestedTopic,
      );
      if (!requestedLog) {
        throw new Error("Committee request did not emit E3Requested");
      }

      const requestedEvent = interfoldContract.interface.parseLog(requestedLog);
      if (!requestedEvent) {
        throw new Error("Unable to decode the E3Requested event");
      }

      const e3Id = requestedEvent.args.e3Id;

      await fulfillConfiguredLocalRandomness(hre, e3Id, receipt.blockNumber);

      console.log(`Committee requested for E3 ${e3Id}`);
      console.log(`E3_ID=${e3Id}`);
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
      const { ethers, interfold } = await getInterfoldConnection(hre);

      if (await interfold.e3Programs(e3Address)) {
        console.log(`E3 program already enabled: ${e3Address}`);
        return;
      }

      const ownerAddress = (await interfold.owner()).toLowerCase();
      const signers = await ethers.getSigners();
      const ownerSigner = (
        await Promise.all(
          signers.map(async (signer: any) => ({
            address: (await signer.getAddress()).toLowerCase(),
            signer,
          })),
        )
      ).find(({ address }) => address === ownerAddress)?.signer;

      if (!ownerSigner) {
        throw new Error(
          `Interfold owner ${ownerAddress} is not an available signer. Submit registerE3Program through the owner Safe.`,
        );
      }

      const tx = await interfold
        .connect(ownerSigner)
        .registerE3Program(e3Address);

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
    defaultValue: "0",
    type: ArgumentType.STRING,
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
    description: "Hash-based aggregated PK commitment (bytes32 hex); required",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "proof",
    description:
      "Required ABI-encoded DkgAggregator (EVM) proof (bytes rawProof, bytes32[] publicInputs)",
    defaultValue: "0x",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "dkgAttestationBundle",
    description:
      "Required ABI-encoded DKG fold attestation bundle (Attestation[], PartySlotBinding[])",
    defaultValue: "0x",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: async (
      { e3Id, nodes, publicKey, pkCommitment, proof, dkgAttestationBundle },
      hre,
    ) => {
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
      if (!isHexString(proof) || proof === "0x") {
        throw new Error("proof is required and must be a non-empty hex string");
      }
      if (!isHexString(dkgAttestationBundle) || dkgAttestationBundle === "0x") {
        throw new Error(
          "dkgAttestationBundle is required and must be a non-empty hex string",
        );
      }

      let publishedCommitment = ZeroHash;
      try {
        publishedCommitment = await ciphernodeRegistry.committeePublicKey(e3Id);
      } catch {
        // No committee proof has been published for this E3 yet.
      }
      if (publishedCommitment === pkCommitment) {
        console.log("Committee proof already published");
      } else {
        const tx = await ciphernodeRegistry.publishCommittee(
          e3Id,
          pkCommitment,
          proof,
          dkgAttestationBundle,
        );

        console.log("Publishing committee... ", tx.hash);
        await tx.wait();
      }

      const publicKeyBytes = getBytes(publicKey);
      const chunkBytes = 90 * 1024;
      const chunkCount = Math.ceil(publicKeyBytes.length / chunkBytes);
      const candidateHash = keccak256(publicKey);
      for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const chunk = publicKeyBytes.slice(
          chunkIndex * chunkBytes,
          (chunkIndex + 1) * chunkBytes,
        );
        const publicKeyTx = await ciphernodeRegistry.publishCommitteePublicKey(
          e3Id,
          candidateHash,
          chunkIndex,
          chunkCount,
          publicKeyBytes.length,
          chunk,
        );
        console.log(
          `Publishing committee public-key chunk ${chunkIndex + 1}/${chunkCount}... `,
          publicKeyTx.hash,
        );
        await publicKeyTx.wait();
      }
      console.log(`Committee proof and public key published`);
    },
  }))
  .build();

export const getCommitteePublicKey = task(
  "committee:getPublicKey",
  "Reassemble the published committee public key for an E3",
)
  .addOption({
    name: "e3Id",
    description: "Id of the E3 program",
    defaultValue: "0",
    type: ArgumentType.STRING,
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
      const filter = registry.filters.CommitteePublicKeyChunkPublished(e3Id);
      const logs = await registry.queryFilter(
        filter,
        deployment.blockNumber ?? 0,
        "latest",
      );
      const expectedPkCommitment = await registry.committeePublicKey(e3Id);
      const publicKeyBytes = assembleUniqueCommitteePublicKey(
        logs.map((log: any) => ({
          publisher: log.args.publisher ?? log.args[1],
          candidateHash: log.args.candidateHash ?? log.args[2],
          pkCommitment: log.args.pkCommitment ?? log.args[4],
          chunkIndex: Number(log.args.chunkIndex ?? log.args[5]),
          chunkCount: Number(log.args.chunkCount ?? log.args[6]),
          totalLength: Number(log.args.totalLength ?? log.args[7]),
          chunk: log.args.chunk ?? log.args[8],
        })),
        expectedPkCommitment,
      );

      if (outFile) {
        ensureParentDir(outFile);
        fs.writeFileSync(outFile, Buffer.from(publicKeyBytes));
      }

      console.log(ethers.hexlify(publicKeyBytes));
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
    defaultValue: "0",
    type: ArgumentType.STRING,
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
  .addOption({
    name: "ciphertextCommitment",
    description: "circuit-compatible SAFE commitment to the decoded ciphertext",
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
    name: "availabilityProof",
    description:
      "VectorX proof bytes; defaults to the ciphertext for the local mock",
    defaultValue: "",
    type: ArgumentType.STRING,
  })
  .addOption({
    name: "availabilityProofFile",
    description: "file containing the ABI-encoded VectorX proof",
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
        proof,
        proofFile,
        ciphertextCommitment,
        ciphertextCommitmentFile,
        availabilityProof,
        availabilityProofFile,
        mockDataAvailabilityDirectory,
      },
      hre,
    ) => {
      const { ethers, interfold } = await getInterfoldConnection(hre);

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

      let commitmentToSend = ciphertextCommitment;
      if (ciphertextCommitmentFile) {
        commitmentToSend =
          "0x" + fs.readFileSync(ciphertextCommitmentFile).toString("hex");
      }
      if (!isHexString(commitmentToSend, 32)) {
        throw new Error(
          "A 32-byte --ciphertext-commitment or --ciphertext-commitment-file is required",
        );
      }

      if (!isHexString(dataToSend) || dataToSend === "0x") {
        throw new Error("A non-empty --data or --data-file is required");
      }
      if (!isHexString(proofToSend) || proofToSend === "0x") {
        throw new Error("A non-empty --proof or --proof-file is required");
      }

      let availabilityProofToSend = availabilityProof || dataToSend;
      if (availabilityProofFile) {
        availabilityProofToSend = fs
          .readFileSync(availabilityProofFile)
          .toString();
      }
      if (
        !isHexString(availabilityProofToSend) ||
        availabilityProofToSend === "0x"
      ) {
        throw new Error("The availability proof must be non-empty hex bytes");
      }

      const contentHash = mockDataAvailabilityDirectory
        ? stageMockDataAvailabilityObject(
            mockDataAvailabilityDirectory,
            dataToSend,
          )
        : ethers.keccak256(dataToSend);

      const encodedOutputReference = ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes computeProof,bytes availabilityProof)",
        ],
        [
          {
            contentHash,
            ciphertextCommitment: commitmentToSend,
            computeProof: proofToSend,
            availabilityProof: availabilityProofToSend,
          },
        ],
      );

      const tx = await interfold.publishCiphertextOutput(
        e3Id,
        encodedOutputReference,
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
      const { interfold } = await getInterfoldConnection(hre);

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
    defaultValue: "0",
    type: ArgumentType.STRING,
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
