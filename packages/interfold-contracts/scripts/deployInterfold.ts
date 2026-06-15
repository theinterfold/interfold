// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { ethers as ethersLib } from "ethers";
import hre from "hardhat";

import { autoCleanForLocalhost } from "./cleanIgnitionState";
import { configureLocalSlashingPolicies } from "./configureLocalSlashingPolicies";
import { deployAndSaveBfvDecryptionVerifier } from "./deployAndSave/bfvDecryptionVerifier";
import { deployAndSaveBfvPkVerifier } from "./deployAndSave/bfvPkVerifier";
import { deployAndSaveBondingRegistry } from "./deployAndSave/bondingRegistry";
import { deployAndSaveCiphernodeRegistryOwnable } from "./deployAndSave/ciphernodeRegistryOwnable";
import { deployAndSaveDkgFoldAttestationVerifier } from "./deployAndSave/dkgFoldAttestationVerifier";
import { deployAndSaveE3RefundManager } from "./deployAndSave/e3RefundManager";
import { deployAndSaveInterfold } from "./deployAndSave/interfold";
import { deployAndSaveInterfoldTicketToken } from "./deployAndSave/interfoldTicketToken";
import { deployAndSaveInterfoldToken } from "./deployAndSave/interfoldToken";
import { deployAndSaveMockStableToken } from "./deployAndSave/mockStableToken";
import { deployAndSavePoseidonT3 } from "./deployAndSave/poseidonT3";
import { deployAndSaveSlashingManager } from "./deployAndSave/slashingManager";
import { deployAndSaveAllVerifiers } from "./deployAndSave/verifiers";
import { deployMocks } from "./deployMocks";
import { isLocalDeploymentChain } from "./utils";

// BFV parameter presets — hardcoded from crates/fhe-params/src/constants.rs
// to avoid a cyclic dependency on @interfold/sdk.
const BFV_PARAMS = {
  insecure512: {
    degree: 512n,
    plaintextModulus: 100n,
    moduli: [0xffffee001n, 0xffffc4001n],
    error1Variance: "3",
  },
  secure8192: {
    degree: 8192n,
    plaintextModulus: 131072n,
    moduli: [0x0400000001460001n, 0x0400000000ea0001n, 0x0400000000920001n],
    error1Variance: "2331171231419734472395201298275918858425592709120",
  },
} as const;

function encodeBfvParams(params: {
  degree: bigint;
  plaintextModulus: bigint;
  moduli: readonly bigint[];
  error1Variance: string;
}): string {
  const abiCoder = ethersLib.AbiCoder.defaultAbiCoder();
  return abiCoder.encode(
    [
      "tuple(uint256 degree, uint256 plaintext_modulus, uint256[] moduli, string error1_variance)",
    ],
    [
      [
        params.degree,
        params.plaintextModulus,
        [...params.moduli],
        params.error1Variance,
      ],
    ],
  );
}

/**
 * Default timeout configuration (in seconds)
 */
const DEFAULT_TIMEOUT_CONFIG = {
  dkgWindow: 7200,
  computeWindow: 86400,
  decryptionWindow: 3600,
};

function parseRequiredUint64(value: string, label: string): bigint {
  if (!/^\d+$/.test(value)) {
    throw new Error(`${label} must be a base-10 unix timestamp`);
  }
  const parsed = BigInt(value);
  const maxUint64 = (1n << 64n) - 1n;
  if (parsed > maxUint64) {
    throw new Error(`${label} must fit in uint64`);
  }
  return parsed;
}

/** Circuit names required for BFV ZK verification in this script */
const DKG_AGGREGATOR_VERIFIER = "DkgAggregatorVerifier";
const DECRYPTION_AGGREGATOR_VERIFIER = "DecryptionAggregatorVerifier";

/**
 * Deploys the Interfold contracts
 */
export const deployInterfold = async (
  withMocks?: boolean,
  withZKVerification?: boolean,
) => {
  const { ethers } = await hre.network.connect();

  // Auto-clean state for local networks to prevent stale state issues
  const networkName = hre.globalOptions.network ?? "localhost";
  await autoCleanForLocalhost(networkName);

  const [owner] = await ethers.getSigners();

  const ownerAddress = await owner.getAddress();
  const latestBlock = await ethers.provider.getBlock("latest");
  if (!latestBlock) {
    throw new Error("Could not read latest block for local TGE timestamp");
  }

  const encodedInsecure = encodeBfvParams(BFV_PARAMS.insecure512);
  const encodedSecure = encodeBfvParams(BFV_PARAMS.secure8192);

  const THIRTY_DAYS_IN_SECONDS = 60 * 60 * 24 * 30;
  const SEVEN_DAYS_IN_SECONDS = 60 * 60 * 24 * 7;
  const TGE_COOLDOWN_SECONDS = 60 * 60 * 24 * 45;
  const FOUR_YEARS_IN_SECONDS = 60 * 60 * 24 * 365 * 4;
  const SORTITION_SUBMISSION_WINDOW = 10;
  const addressOne = "0x0000000000000000000000000000000000000001";

  const poseidonT3 = await deployAndSavePoseidonT3({ hre });

  const shouldDeployMocks = process.env.DEPLOY_MOCKS === "true" || withMocks;
  const shouldHaveZKVerification =
    process.env.ENABLE_ZK_VERIFICATION === "true" || withZKVerification;

  // H-23: refuse to deploy mocks (MockUSDC / MockE3Program) and the
  // `insecure512` BFV preset on any chain that is not a recognised local /
  // test network. Override via `ALLOW_MOCKS_ON_PRODUCTION=true` only for
  // explicit dry-runs.
  if (shouldDeployMocks) {
    const network = await ethers.provider.getNetwork();
    const chainId = Number(network.chainId);
    const LOCAL_CHAIN_IDS = new Set<number>([
      31337, // hardhat
      1337, // ganache / local
      11155111, // sepolia (testnet)
      5, // goerli (testnet)
      80001, // polygon mumbai (testnet)
    ]);
    if (
      !LOCAL_CHAIN_IDS.has(chainId) &&
      process.env.ALLOW_MOCKS_ON_PRODUCTION !== "true"
    ) {
      throw new Error(
        `Refusing to deploy mocks / insecure512 BFV preset on chainId ${chainId}. ` +
          `Set ALLOW_MOCKS_ON_PRODUCTION=true to override (H-23).`,
      );
    }
  }

  let feeTokenAddress: string;

  if (shouldDeployMocks) {
    console.log("Deploying mock Fee token...");
    const { mockStableToken } = await deployAndSaveMockStableToken({
      initialSupply: 1000000,
      hre,
    });
    feeTokenAddress = await mockStableToken.getAddress();
    console.log("MockFeeToken deployed to:", feeTokenAddress);
  } else {
    throw new Error(
      "Fee token address must be provided for production deployment",
    );
  }

  // ── CCA window ──────────────────────────────────────────────────────────
  // For local dev the CCA window starts soon after deployment and runs for
  // 7 days.  Production deployments must set INTERFOLD_CCA_START.
  const ccaStartEnv = process.env.INTERFOLD_CCA_START;
  let ccaStart: bigint;
  if (ccaStartEnv?.trim()) {
    ccaStart = parseRequiredUint64(ccaStartEnv.trim(), "INTERFOLD_CCA_START");
  } else if (isLocalDeploymentChain(networkName)) {
    const now = BigInt(latestBlock.timestamp);
    ccaStart = now + 3600n; // 1 hour from now
    console.warn(
      `[WARN] INTERFOLD_CCA_START not set; using ${ccaStart} (block.timestamp + 1h) for local deployment.`,
    );
  } else {
    throw new Error(
      "INTERFOLD_CCA_START must be set for non-local token-lock deployment",
    );
  }
  const ccaEnd = ccaStart + BigInt(SEVEN_DAYS_IN_SECONDS);

  console.log("Deploying InterfoldTicketToken...");
  const { interfoldTicketToken } = await deployAndSaveInterfoldTicketToken({
    baseToken: feeTokenAddress,
    registry: addressOne,
    owner: ownerAddress,
    hre,
  });
  const interfoldTicketTokenAddress = await interfoldTicketToken.getAddress();
  console.log("InterfoldTicketToken deployed to:", interfoldTicketTokenAddress);

  console.log("Deploying SlashingManager...");
  const { slashingManager } = await deployAndSaveSlashingManager({
    admin: ownerAddress,
    hre,
  });
  const slashingManagerAddress = await slashingManager.getAddress();
  console.log("SlashingManager deployed to:", slashingManagerAddress);

  console.log("Deploying CiphernodeRegistry...");
  const { ciphernodeRegistry } = await deployAndSaveCiphernodeRegistryOwnable({
    poseidonT3Address: poseidonT3,
    owner: ownerAddress,
    submissionWindow: SORTITION_SUBMISSION_WINDOW,
    hre,
  });
  const ciphernodeRegistryAddress = await ciphernodeRegistry.getAddress();
  console.log("CiphernodeRegistry deployed to:", ciphernodeRegistryAddress);

  // BondingRegistry is deployed before INTF so its address can be passed to
  // the token constructor.  The license token is set to address(0) temporarily
  // and fixed after INTF is deployed via setLicenseToken().
  console.log("Deploying BondingRegistry...");
  const { bondingRegistry } = await deployAndSaveBondingRegistry({
    owner: ownerAddress,
    ticketToken: interfoldTicketTokenAddress,
    licenseToken: ethers.ZeroAddress,
    registry: ciphernodeRegistryAddress,
    slashedFundsTreasury: ownerAddress,
    ticketPrice: ethers.parseUnits("10", 6).toString(),
    licenseRequiredBond: ethers.parseEther("100").toString(),
    minTicketBalance: 1,
    exitDelay: 7 * 24 * 60 * 60,
    hre,
  });
  const bondingRegistryAddress = await bondingRegistry.getAddress();
  console.log("BondingRegistry deployed to:", bondingRegistryAddress);

  // INTF is deployed with BondingRegistry's real address.  claimSource uses
  // the deployer as a placeholder; the actual Interfold protocol contract is
  // deployed later (its address is not known at this point).  CLAIM_SOURCE is
  // immutable, so local deployments use the deployer as the claim source.
  console.log("Deploying INTF token...");
  const { interfoldToken } = await deployAndSaveInterfoldToken({
    owner: ownerAddress,
    ccaStart,
    ccaEnd,
    claimSource: ownerAddress,
    bondingRegistry: bondingRegistryAddress,
    noMoreLocks: ccaEnd + BigInt(TGE_COOLDOWN_SECONDS + FOUR_YEARS_IN_SECONDS),
    hre,
  });
  const interfoldTokenAddress = await interfoldToken.getAddress();
  console.log("InterfoldToken deployed to:", interfoldTokenAddress);

  // Fix up BondingRegistry's license token now that INTF exists.
  console.log("Setting license token in BondingRegistry...");
  await (await bondingRegistry.setLicenseToken(interfoldTokenAddress)).wait();

  if (interfoldTokenAddress.toLowerCase() === feeTokenAddress.toLowerCase()) {
    throw new Error(
      "MockUSDC and InterfoldToken resolved to the same address. " +
        "Start a fresh Anvil on http://127.0.0.1:8545 (e.g. `anvil --chain-id 31337`) " +
        "and rerun deploy so token nonces advance separately.",
    );
  }

  // Whitelist BondingRegistry so bonded transfers work pre-TGE.
  console.log("Whitelisting BondingRegistry in INTF...");
  await (
    await interfoldToken.setTransferWhitelisted(bondingRegistryAddress, true)
  ).wait();

  console.log("Deploying Interfold...");
  const { interfold } = await deployAndSaveInterfold({
    owner: ownerAddress,
    maxDuration: THIRTY_DAYS_IN_SECONDS.toString(),
    registry: ciphernodeRegistryAddress,
    bondingRegistry: bondingRegistryAddress,
    e3RefundManager: addressOne, // placeholder, will be updated
    feeToken: feeTokenAddress,
    timeoutConfig: DEFAULT_TIMEOUT_CONFIG,
    hre,
  });
  const interfoldAddress = await interfold.getAddress();
  console.log("Interfold deployed to:", interfoldAddress);

  console.log("Deploying E3RefundManager...");
  const { e3RefundManager } = await deployAndSaveE3RefundManager({
    owner: ownerAddress,
    interfold: interfoldAddress,
    treasury: ownerAddress, // Protocol treasury
    hre,
  });
  const e3RefundManagerAddress = await e3RefundManager.getAddress();
  console.log("E3RefundManager deployed to:", e3RefundManagerAddress);

  console.log("Setting E3RefundManager in Interfold...");
  await interfold.setE3RefundManager(e3RefundManagerAddress);

  ///////////////////////////////////////////
  // Configure cross-contract dependencies
  ///////////////////////////////////////////

  console.log("Configuring cross-contract dependencies...");

  console.log("Setting Interfold address in CiphernodeRegistry...");
  await ciphernodeRegistry.setInterfold(interfoldAddress);

  console.log("Setting BondingRegistry address in CiphernodeRegistry...");
  await ciphernodeRegistry.setBondingRegistry(bondingRegistryAddress);

  console.log("Setting Submission Window in CiphernodeRegistry...");
  console.log("SORTITION_SUBMISSION_WINDOW:", SORTITION_SUBMISSION_WINDOW);
  await ciphernodeRegistry.setSortitionSubmissionWindow(
    SORTITION_SUBMISSION_WINDOW,
  );

  console.log("Setting BondingRegistry address in InterfoldTicketToken...");
  await interfoldTicketToken.setRegistry(bondingRegistryAddress);

  console.log("Setting CiphernodeRegistry address in BondingRegistry...");
  await bondingRegistry.setRegistry(ciphernodeRegistryAddress);

  console.log("Setting Interfold address in SlashingManager...");
  await slashingManager.setInterfold(interfoldAddress);

  console.log("Setting BondingRegistry address in SlashingManager...");
  await slashingManager.setBondingRegistry(bondingRegistryAddress);

  console.log("Setting CiphernodeRegistry address in SlashingManager...");
  await slashingManager.setCiphernodeRegistry(ciphernodeRegistryAddress);

  console.log("Setting E3RefundManager address in SlashingManager...");
  await slashingManager.setE3RefundManager(e3RefundManagerAddress);

  console.log("Setting SlashingManager address in Interfold...");
  await interfold.setSlashingManager(slashingManagerAddress);

  console.log("Setting SlashingManager address in BondingRegistry...");
  await bondingRegistry.setSlashingManager(slashingManagerAddress);

  console.log("Setting SlashingManager address in CiphernodeRegistry...");
  await ciphernodeRegistry.setSlashingManager(slashingManagerAddress);

  if (shouldDeployMocks) {
    console.log("Configuring local SlashingManager slash policies...");
    await configureLocalSlashingPolicies(hre, slashingManager);
  }

  // H-24: SLASHER_ROLE must be granted explicitly. Without this, Lane B
  // (evidence-based) slash proposals are uncallable and there is no on-chain
  // path to penalise nodes for off-chain misbehaviour. Source the slasher
  // address from $SLASHER_ADDRESS, falling back to the deployer with a
  // visible warning so testnet deployments stay functional but production
  // operators are forced to set it intentionally.
  const slasherAddress = process.env.SLASHER_ADDRESS || ownerAddress;
  if (!process.env.SLASHER_ADDRESS) {
    console.warn(
      "[WARN] SLASHER_ADDRESS not set \u2014 granting SLASHER_ROLE to deployer.\n" +
        "       Set SLASHER_ADDRESS to the production slasher EOA / multisig\n" +
        "       and revoke from the deployer before going live.",
    );
  }
  console.log(`Granting SLASHER_ROLE to ${slasherAddress}...`);
  const addSlasherTx = await slashingManager.addSlasher(slasherAddress);
  await addSlasherTx.wait();
  const slasherRole = await slashingManager.SLASHER_ROLE();
  const slasherGranted = await slashingManager.hasRole(
    slasherRole,
    slasherAddress,
  );
  if (!slasherGranted) {
    throw new Error(
      `Failed to grant SLASHER_ROLE to ${slasherAddress} \u2014 aborting deployment`,
    );
  }
  console.log("SLASHER_ROLE granted.");

  console.log("Setting Interfold as reward distributor in BondingRegistry...");
  await bondingRegistry.setRewardDistributor(interfoldAddress);

  // E3RefundManager already has correct interfold from deployment

  // Initialize committee size thresholds [quorum, total] (H, N)
  console.log("Setting committee thresholds...");
  // Minimum: H=2, N=3 (T=1)
  await interfold.setCommitteeThresholds(0, [2, 3]);
  // Micro: H=5, N=9 (T=4)
  await interfold.setCommitteeThresholds(1, [5, 9]);
  // Small: H=10, N=19 (T=9)
  await interfold.setCommitteeThresholds(2, [10, 19]);
  console.log(
    "Committee thresholds set (Minimum=[2,3], Micro=[5,9], Small=[10,19])",
  );

  // Register BFV param sets
  console.log("Registering BFV param sets...");
  await interfold.setParamSet(0, encodedInsecure); // ParamSet.Insecure512
  await interfold.setParamSet(1, encodedSecure); // ParamSet.Secure8192
  console.log("ParamSet.Insecure512 registered");
  console.log("ParamSet.Secure8192 registered");

  const encryptionSchemeId = ethers.keccak256(ethers.toUtf8Bytes("fhe.rs:BFV"));

  // Set pricing config with protocol treasury
  const protocolTreasury = process.env.PROTOCOL_TREASURY || ownerAddress;
  console.log("Setting pricing config...");
  await interfold.setPricingConfig({
    keyGenFixedPerNode: 100000, // 0.10 USDC
    keyGenPerEncryptionProof: 50000, // 0.05 USDC
    coordinationPerPair: 10000, // 0.01 USDC
    availabilityPerNodePerSec: 50, // 0.00005 USDC
    decryptionPerNode: 300000, // 0.30 USDC
    publicationBase: 1000000, // 1.00 USDC
    verificationPerProof: 5000, // 0.005 USDC
    protocolTreasury: protocolTreasury,
    marginBps: 1500, // 15%
    protocolShareBps: 2000, // 20%
    dkgUtilizationBps: 2500, // 25%
    computeUtilizationBps: 5000, // 50%
    decryptUtilizationBps: 2500, // 25%
    minCommitteeSize: 0,
    minThreshold: 0,
  });
  console.log("Pricing config set (treasury:", protocolTreasury, ")");

  if (shouldDeployMocks) {
    const {
      decryptionVerifierAddress: mockDecryptionVerifierAddress,
      pkVerifierAddress: mockPkVerifierAddress,
      e3ProgramAddress,
    } = await deployMocks();

    console.log("encryptionSchemeId", encryptionSchemeId);

    if (!shouldHaveZKVerification && mockDecryptionVerifierAddress) {
      const deployedDecryptionVerifier =
        await interfold.decryptionVerifiers(encryptionSchemeId);
      if (deployedDecryptionVerifier === mockDecryptionVerifierAddress) {
        console.log(`DecryptionVerifier already set in Interfold contract`);
      } else {
        const tx = await interfold.setDecryptionVerifier(
          encryptionSchemeId,
          mockDecryptionVerifierAddress,
        );
        await tx.wait();
        console.log(
          `Successfully set MockDecryptionVerifier in Interfold contract`,
        );
      }
    }

    if (!shouldHaveZKVerification && mockPkVerifierAddress) {
      const deployedPkVerifier =
        await interfold.pkVerifiers(encryptionSchemeId);
      if (deployedPkVerifier === mockPkVerifierAddress) {
        console.log(`PkVerifier already set in Interfold contract`);
      } else {
        const tx = await interfold.setPkVerifier(
          encryptionSchemeId,
          mockPkVerifierAddress,
        );
        await tx.wait();
        console.log(`Successfully set MockPkVerifier in Interfold contract`);
      }
    }

    const tx = await interfold.enableE3Program(e3ProgramAddress);
    await tx.wait();
    console.log(`Successfully enabled E3 Program in Interfold contract`);
  }

  let verifierDeployments: Record<string, string> = {};
  if (shouldHaveZKVerification) {
    console.log("Deploying circuit verifiers...");
    verifierDeployments = await deployAndSaveAllVerifiers(hre);
    const requiredVerifierNames = [
      DKG_AGGREGATOR_VERIFIER,
      DECRYPTION_AGGREGATOR_VERIFIER,
    ] as const;
    for (const name of requiredVerifierNames) {
      const addr = verifierDeployments[name];
      if (!addr?.trim()) {
        throw new Error(
          `ZK verification enabled but "${name}" is missing from verifier deployments ` +
            `(got ${verifierDeployments[name] === undefined ? "undefined" : JSON.stringify(addr)}). ` +
            `Ensure deployAndSaveAllVerifiers discovers and deploys this circuit, or fix verifier artifacts.`,
        );
      }
    }
  } else {
    console.log("Skipping circuit verifiers (ENABLE_ZK_VERIFICATION not set)");
  }
  const verifierEntries = Object.entries(verifierDeployments);

  if (shouldHaveZKVerification) {
    console.log("Deploying BfvDecryptionVerifier and registering for prod...");
    const { bfvDecryptionVerifier } =
      await deployAndSaveBfvDecryptionVerifier(hre);
    const bfvDecryptionVerifierAddress =
      await bfvDecryptionVerifier.getAddress();
    const deployedDecryptionVerifier =
      await interfold.decryptionVerifiers(encryptionSchemeId);
    if (deployedDecryptionVerifier !== bfvDecryptionVerifierAddress) {
      const tx = await interfold.setDecryptionVerifier(
        encryptionSchemeId,
        bfvDecryptionVerifierAddress,
      );
      await tx.wait();
      console.log(
        "Successfully set BfvDecryptionVerifier in Interfold contract",
      );
    }
  }

  if (shouldHaveZKVerification) {
    console.log("Deploying BfvPkVerifier and registering for prod...");
    const { bfvPkVerifier } = await deployAndSaveBfvPkVerifier(hre);
    const bfvPkVerifierAddress = await bfvPkVerifier.getAddress();
    const deployedPkVerifier = await interfold.pkVerifiers(encryptionSchemeId);
    if (deployedPkVerifier !== bfvPkVerifierAddress) {
      const tx = await interfold.setPkVerifier(
        encryptionSchemeId,
        bfvPkVerifierAddress,
      );
      await tx.wait();
      console.log("Successfully set BfvPkVerifier in Interfold contract");
    }
  }

  let dkgFoldAttestationVerifierAddress: string | undefined;
  if (shouldHaveZKVerification) {
    console.log("Deploying DkgFoldAttestationVerifier...");
    const { dkgFoldAttestationVerifier } =
      await deployAndSaveDkgFoldAttestationVerifier(hre);
    dkgFoldAttestationVerifierAddress =
      await dkgFoldAttestationVerifier.getAddress();
    const currentVerifier =
      await ciphernodeRegistry.dkgFoldAttestationVerifier();
    if (currentVerifier !== dkgFoldAttestationVerifierAddress) {
      const tx = await ciphernodeRegistry.setInitialDkgFoldAttestationVerifier(
        dkgFoldAttestationVerifierAddress,
      );
      await tx.wait();
      console.log(
        "Successfully set DkgFoldAttestationVerifier on CiphernodeRegistry",
      );
    }
  }

  const verifierLines =
    verifierEntries.length > 0
      ? verifierEntries.map(([name, addr]) => `    ${name}: ${addr}`).join("\n")
      : "    (none)";

  const decryptionVerifierAddress =
    await interfold.decryptionVerifiers(encryptionSchemeId);
  const pkVerifierAddress = await interfold.pkVerifiers(encryptionSchemeId);

  console.log(`
    ============================================
    Deployment Complete!
    ============================================
    MockFeeToken: ${feeTokenAddress}
    InterfoldToken (INTF): ${interfoldTokenAddress}
    InterfoldTicketToken: ${interfoldTicketTokenAddress}
    SlashingManager: ${slashingManagerAddress}
    BondingRegistry: ${bondingRegistryAddress}
    CiphernodeRegistry: ${ciphernodeRegistryAddress}
    E3RefundManager: ${e3RefundManagerAddress}
    Interfold: ${interfoldAddress}
    DecryptionVerifier (BFV): ${decryptionVerifierAddress}
    PkVerifier (BFV): ${pkVerifierAddress}
    Circuit Verifiers:
${verifierLines}
    DkgFoldAttestationVerifier: ${dkgFoldAttestationVerifierAddress ?? "(not deployed)"}
    ============================================
  `);
};
