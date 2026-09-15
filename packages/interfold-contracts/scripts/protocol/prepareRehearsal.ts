// SPDX-License-Identifier: LGPL-3.0-only
import { deployMockBondingRegistryProxy } from "../sale/deployContracts";
import { bfvConfigsForChain } from "../utils";
import { arg, connect } from "./cli";
import { ZERO } from "./constants";
import { protocolDir, writeJson } from "./files";
import type { ProtocolConfigFile } from "./types";
import { address, deployedAddress, requireContract } from "./values";

export async function actionPrepareRehearsal(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== 11155111 && chainId !== 31337) {
    throw new Error(
      "Protocol rehearsal preparation is restricted to Sepolia and local Hardhat",
    );
  }

  const committeeThresholds = new Map<
    number,
    { size: string; quorum: string; total: string }
  >();
  for (const config of bfvConfigsForChain(chainId)) {
    const threshold = {
      size: config.committeeSize.toString(),
      quorum: config.h.toString(),
      total: config.n.toString(),
    };
    const existing = committeeThresholds.get(config.committeeSize);
    if (
      existing &&
      (existing.quorum !== threshold.quorum ||
        existing.total !== threshold.total)
    ) {
      throw new Error(
        `BFV presets disagree on committee size ${config.committeeSize}`,
      );
    }
    committeeThresholds.set(config.committeeSize, threshold);
  }

  const [operator] = await ethers.getSigners();
  const protocolOwner = address(await operator.getAddress(), "protocolOwner");
  const e3Program = address(arg("e3-program") ?? "", "e3-program");
  const ciphertextVerifier = address(
    arg("ciphertext-verifier") ?? "",
    "ciphertext-verifier",
  );
  await Promise.all([
    requireContract(ethers.provider, e3Program, "e3-program"),
    requireContract(ethers.provider, ciphertextVerifier, "ciphertext-verifier"),
  ]);

  const registry = await deployMockBondingRegistryProxy(ethers, protocolOwner);
  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read the latest block");
  const day = 24n * 60n * 60n;
  const ccaStart = BigInt(latest.timestamp) + day;
  const ccaEnd = ccaStart + day;
  const noMoreLocks = ccaEnd + 41n * day;
  const fold = await ethers.deployContract("InterfoldToken", [
    protocolOwner,
    ccaStart,
    ccaEnd,
    noMoreLocks,
    registry.proxy,
  ]);
  await fold.waitForDeployment();
  const feeToken = await ethers.deployContract("MockFeeOnTransferToken", [0]);
  await feeToken.waitForDeployment();
  const ticketUnderlying = await ethers.deployContract(
    "MockFeeOnTransferToken",
    [0],
  );
  await ticketUnderlying.waitForDeployment();

  let randomness: NonNullable<ProtocolConfigFile["randomness"]>;
  if (chainId === 31337) {
    const coordinator = await ethers.deployContract(
      "ChainlinkVrfCoordinatorV2_5Mock",
      [0, 0, ethers.parseEther("1")],
    );
    await coordinator.waitForDeployment();
    await coordinator.createSubscription();
    const [subscriptionId] = await coordinator.getActiveSubscriptionIds(0, 1);
    if (!subscriptionId) throw new Error("VRF subscription was not created");
    await coordinator.fundSubscription(
      subscriptionId,
      ethers.parseEther("100"),
    );
    randomness = {
      coordinator: await deployedAddress(coordinator),
      subscriptionId: subscriptionId.toString(),
      keyHash: `0x${"11".repeat(32)}`,
      requestConfirmations: 3,
      callbackGasLimit: 150_000,
      nativePayment: false,
      minimumSubscriptionBalance: "1000000000000000000",
      requestTimeout: "3600",
    };
  } else {
    const coordinator = address(
      arg("vrf-coordinator") ?? "",
      "vrf-coordinator",
    );
    const subscriptionId = arg("vrf-subscription-id") ?? "";
    const keyHash = arg("vrf-key-hash") ?? "";
    if (!/^\d+$/.test(subscriptionId) || BigInt(subscriptionId) === 0n) {
      throw new Error("--vrf-subscription-id must be a positive integer");
    }
    if (!ethers.isHexString(keyHash, 32)) {
      throw new Error("--vrf-key-hash must be a bytes32 value");
    }
    randomness = {
      coordinator,
      subscriptionId,
      keyHash,
      requestConfirmations: 3,
      callbackGasLimit: 150_000,
      nativePayment: false,
      minimumSubscriptionBalance: "1000000000000000000",
      requestTimeout: "3600",
    };
  }

  const config: ProtocolConfigFile = {
    name:
      chainId === 11155111
        ? "sepolia-protocol-rehearsal"
        : "localhost-protocol-rehearsal",
    chainId,
    protocolOwner,
    fold: await deployedAddress(fold),
    bondingRegistryProxy: registry.proxy,
    bondingRegistryProxyAdmin: registry.proxyAdmin,
    feeToken: await deployedAddress(feeToken),
    feeTokenDecimals: 18,
    ticketUnderlyingToken: await deployedAddress(ticketUnderlying),
    protocolTreasury: protocolOwner,
    slashedFundsTreasury: protocolOwner,
    slasher: ZERO,
    randomness,
    ticketToken: { lockRegistry: true },
    bonding: {
      ticketPrice: "1000000000000000000000",
      requiredCiphernodeBond: "32000000000000000000000",
      ticketTokenDecimals: 18,
      ciphernodeBondTokenDecimals: 18,
      minTicketBalance: "1",
      exitDelay: "2592000",
    },
    registry: { sortitionSubmissionWindow: "600" },
    slashing: { initialDelay: "172800" },
    interfold: {
      maxDuration: "2592000",
      markFailedGracePeriod: "3600",
      timeoutConfig: {
        dkgWindow: "21600",
        computeWindow: "604800",
        decryptionWindow: "21600",
      },
      pricing: {
        randomnessFlatFee: "1000000000000000000",
        keyGenFixedPerNode: "100000000000000000",
        keyGenPerEncryptionProof: "100000000000000000",
        coordinationPerPair: "10000000000000000",
        availabilityPerNodePerSec: "10000000000000",
        decryptionPerNode: "300000000000000000",
        publicationBase: "1000000000000000000",
        verificationPerProof: "5000000000000000",
        protocolTreasury: protocolOwner,
        marginBps: "1000",
        protocolShareBps: "182",
        dkgUtilizationBps: "3000",
        computeUtilizationBps: "4000",
        decryptUtilizationBps: "3000",
        minCommitteeSize: "3",
        minThreshold: "2",
      },
      committeeThresholds: [...committeeThresholds.values()],
      registerActiveBfvParamSet: true,
      allowFeeToken: true,
    },
    verifiers: { deploy: true },
    ciphertextVerifier,
    bindInitialE3Program: true,
    e3Programs: [e3Program],
  };

  const file = `${protocolDir}/${config.name}.config.json`;
  writeJson(file, config);
  console.log(`
Protocol rehearsal prerequisites deployed
  protocol owner:              ${protocolOwner}
  FOLD test token:             ${config.fold}
  fee test token:              ${config.feeToken}
  ticket-underlying test token:${config.ticketUnderlyingToken}
  BondingRegistry proxy:       ${config.bondingRegistryProxy}
  BondingRegistry ProxyAdmin:  ${config.bondingRegistryProxyAdmin}
  CRISP program:               ${e3Program}
  ciphertext verifier:         ${ciphertextVerifier}
  config:                      ${file}
`);
}
