// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { ethers as ethersLib } from "ethers";
import fs from "fs";
import { network } from "hardhat";
import os from "os";
import path from "path";

import { deployProtocolContracts } from "../../scripts/protocol/deployContracts";
import {
  currentNodeRelease,
  requiresNodeReleasePolicyUpdate,
} from "../../scripts/protocol/nodeRelease";
import {
  assertValidatedVrfDeploymentMatchesPlan,
  assertVrfSubscription,
  assertVrfUpgradePlanMatchesDeployment,
  requireCiphernodeRestartAcknowledgement,
  requirePlannedRandomnessConfig,
} from "../../scripts/protocol/randomness";
import {
  aragonAdminSafeBatch,
  aragonAdminSafeTransactions,
  safeTx,
} from "../../scripts/protocol/safe";
import { buildSafeTransactions } from "../../scripts/protocol/transactions";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  VrfSortitionUpgradePlan,
} from "../../scripts/protocol/types";
import { loadConfig } from "../../scripts/protocol/values";
import { requiredActiveOperatorsForSecureCrisp } from "../../scripts/upgrade/resumeSecureCrisp";
import { BondingRegistry__factory as BondingRegistryFactory } from "../../types";

const { ethers } = await network.connect();

describe("Protocol deployment", function () {
  it("derives one release identity for the Rust and contract tooling", function () {
    const release = currentNodeRelease();
    expect(release.version).to.match(/^\d+\.\d+\.\d+/);
    expect(release.protocolVersion).to.be.greaterThan(0);
    expect(release.nodeGeneration).to.be.greaterThan(0);
    expect(release.releaseId).to.equal(
      ethersLib.id(`interfold.node.release:v1:${release.version}`),
    );
  });

  it("updates the node release policy only when the release advances", function () {
    const release = { protocolVersion: 3, nodeGeneration: 1 };

    expect(requiresNodeReleasePolicyUpdate(release, 2n, 1n)).to.equal(true);
    expect(requiresNodeReleasePolicyUpdate(release, 3n, 1n)).to.equal(false);
    expect(() => requiresNodeReleasePolicyUpdate(release, 4n, 1n)).to.throw(
      "cannot move backwards",
    );
  });

  it("allows a named Sepolia rehearsal without weakening production capacity", function () {
    const thresholds = [
      { size: "0", total: "3" },
      { size: "1", total: "9" },
      { size: "2", total: "19" },
    ];

    expect(requiredActiveOperatorsForSecureCrisp(thresholds, 1)).to.equal(19n);
    expect(
      requiredActiveOperatorsForSecureCrisp(thresholds, 11155111, "0"),
    ).to.equal(3n);
    expect(() =>
      requiredActiveOperatorsForSecureCrisp(thresholds, 1, "0"),
    ).to.throw("only for a Sepolia rehearsal");
  });

  it("requires a ciphernode restart acknowledgement before resume", function () {
    expect(() => requireCiphernodeRestartAcknowledgement(false)).to.throw(
      "Restart every ciphernode",
    );
    expect(() => requireCiphernodeRestartAcknowledgement(true)).not.to.throw();
  });

  it("wraps DAO wiring actions in one Aragon Admin Safe transaction", async function () {
    const [adminPlugin, proposerSafe, targetA, targetB] =
      await ethers.getSigners();
    const config = {
      name: "mainnet-protocol",
      chainId: 1,
      protocolOwner: "0x652a31c669f9AB37f6040f279139a75D04F2679e",
      governance: {
        adminPlugin: await adminPlugin.getAddress(),
        proposerSafe: await proposerSafe.getAddress(),
        proposalMetadata: "0x",
      },
    } as ProtocolConfigFile;
    const actions = [
      safeTx(await targetA.getAddress(), "0x12345678"),
      safeTx(await targetB.getAddress(), "0xabcdef01"),
    ];

    const batch = aragonAdminSafeBatch(config, actions);
    expect(batch.meta.createdFromSafeAddress).to.equal(
      await proposerSafe.getAddress(),
    );
    expect(batch.transactions).to.have.lengthOf(1);

    const [wrapper] = aragonAdminSafeTransactions(config, actions);
    expect(wrapper.to).to.equal(await adminPlugin.getAddress());

    const adminInterface = new ethersLib.Interface([
      "function executeProposal(bytes metadata,tuple(address to,uint256 value,bytes data)[] actions,uint256 allowFailureMap)",
    ]);
    const decoded = adminInterface.decodeFunctionData(
      "executeProposal",
      wrapper.data,
    );

    expect(decoded.metadata).to.equal("0x");
    expect(decoded.allowFailureMap).to.equal(0n);
    expect(decoded.actions).to.have.lengthOf(actions.length);
    for (const [index, action] of actions.entries()) {
      expect(decoded.actions[index].to).to.equal(action.to);
      expect(decoded.actions[index].value).to.equal(BigInt(action.value));
      expect(decoded.actions[index].data).to.equal(action.data);
    }
  });

  it("rejects non-call actions in Aragon Admin Safe wrappers", async function () {
    const [adminPlugin, proposerSafe, target] = await ethers.getSigners();
    const config = {
      name: "mainnet-protocol",
      chainId: 1,
      protocolOwner: "0x652a31c669f9AB37f6040f279139a75D04F2679e",
      governance: {
        adminPlugin: await adminPlugin.getAddress(),
        proposerSafe: await proposerSafe.getAddress(),
      },
    } as ProtocolConfigFile;
    const tx = safeTx(await target.getAddress(), "0x12345678");
    tx.operation = 1;

    expect(() => aragonAdminSafeTransactions(config, [tx])).to.throw(
      "Governance transaction 1 is not a CALL operation",
    );
  });

  it("rejects a zero protocol owner and accepts a missing-owner override", function () {
    const source = new URL(
      "../../deploy/protocol/example.protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-protocol-config-"),
    );
    const configFile = path.join(tempDir, "protocol.json");
    const previousOwner = process.env.PROTOCOL_OWNER;

    try {
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "protocolOwner must not be the zero address",
      );

      delete config.protocolOwner;
      fs.writeFileSync(configFile, JSON.stringify(config));
      process.env.PROTOCOL_OWNER = "0x0000000000000000000000000000000000000001";
      expect(loadConfig(configFile).protocolOwner).to.equal(
        "0x0000000000000000000000000000000000000001",
      );
    } finally {
      if (previousOwner === undefined) delete process.env.PROTOCOL_OWNER;
      else process.env.PROTOCOL_OWNER = previousOwner;
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects config names that cannot be used as deployment file names", function () {
    const source = new URL(
      "../../deploy/protocol/example.protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-protocol-config-name-"),
    );
    const configFile = path.join(tempDir, "protocol.json");

    try {
      config.name = "../mainnet-protocol";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "Config name may only contain letters, numbers, underscores and hyphens",
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects a stale VRF upgrade plan", function () {
    const config = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/mainnet-protocol.config.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as ProtocolConfigFile;
    const deployment = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/mainnet-protocol.deployment.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as ProtocolDeployment;
    const plan = {
      name: config.name,
      operator: ethersLib.ZeroAddress,
      protocolOwner: config.protocolOwner,
      registryProxy: deployment.ciphernodeRegistry,
      registryProxyAdmin: deployment.ciphernodeRegistryProxyAdmin,
      registryImplementation: ethersLib.ZeroAddress,
      sortitionLibrary: ethersLib.ZeroAddress,
      interfoldProxy: deployment.interfold,
      interfoldProxyAdmin: deployment.interfoldProxyAdmin,
      interfoldImplementation: ethersLib.ZeroAddress,
      lifecycleLibrary: ethersLib.ZeroAddress,
      pricingLibrary: ethersLib.ZeroAddress,
      bondingProxy: config.bondingRegistryProxy,
      bondingProxyAdmin: config.bondingRegistryProxyAdmin,
      bondingImplementation: ethersLib.ZeroAddress,
      bondingAssetLibrary: ethersLib.ZeroAddress,
      bondingEligibilityLibrary: ethersLib.ZeroAddress,
      bondingSlashingLibrary: ethersLib.ZeroAddress,
      bondingRegistrationLibrary: ethersLib.ZeroAddress,
      bondingOwnershipLibrary: ethersLib.ZeroAddress,
      nodeReleaseRegistry: ethersLib.ZeroAddress,
      nodeRelease: {
        ...currentNodeRelease(),
        releaseId: ethersLib.ZeroHash,
      },
      randomnessProvider: ethersLib.ZeroAddress,
      randomness: { ...config.randomness! },
      randomnessFlatFee: config.interfold.pricing.randomnessFlatFee,
      randomnessProviderOwnershipAcceptanceRequired: false,
      safeTransactions: "upgrade.json",
    } satisfies VrfSortitionUpgradePlan;

    expect(() =>
      assertVrfUpgradePlanMatchesDeployment(config, deployment, plan, 1n),
    ).not.to.throw();
    expect(() =>
      assertVrfUpgradePlanMatchesDeployment(
        config,
        deployment,
        { ...plan, registryProxy: ethersLib.ZeroAddress },
        1n,
      ),
    ).to.throw("registry proxy");
    expect(() =>
      assertVrfUpgradePlanMatchesDeployment(config, deployment, plan, 42161n),
    ).to.throw("connected chain");
  });

  it("binds validation and resume to the prepared VRF settings", function () {
    const config = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/mainnet-protocol.config.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as ProtocolConfigFile;
    const deployment = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/mainnet-protocol.deployment.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as ProtocolDeployment;
    const randomness = { ...config.randomness!, subscriptionId: "7" };
    const plan = {
      name: config.name,
      operator: ethersLib.ZeroAddress,
      protocolOwner: config.protocolOwner,
      registryProxy: deployment.ciphernodeRegistry,
      registryProxyAdmin: deployment.ciphernodeRegistryProxyAdmin,
      registryImplementation: "0x0000000000000000000000000000000000000011",
      sortitionLibrary: "0x0000000000000000000000000000000000000012",
      interfoldProxy: deployment.interfold,
      interfoldProxyAdmin: deployment.interfoldProxyAdmin,
      interfoldImplementation: "0x0000000000000000000000000000000000000013",
      lifecycleLibrary: "0x0000000000000000000000000000000000000014",
      pricingLibrary: "0x0000000000000000000000000000000000000015",
      bondingProxy: config.bondingRegistryProxy,
      bondingProxyAdmin: config.bondingRegistryProxyAdmin,
      bondingImplementation: "0x0000000000000000000000000000000000000017",
      bondingAssetLibrary: "0x0000000000000000000000000000000000000018",
      bondingEligibilityLibrary: "0x0000000000000000000000000000000000000019",
      bondingSlashingLibrary: "0x0000000000000000000000000000000000000020",
      bondingRegistrationLibrary: "0x0000000000000000000000000000000000000021",
      bondingOwnershipLibrary: "0x0000000000000000000000000000000000000022",
      nodeReleaseRegistry: "0x0000000000000000000000000000000000000023",
      nodeRelease: {
        ...currentNodeRelease(),
        releaseId: ethersLib.ZeroHash,
      },
      randomnessProvider: "0x0000000000000000000000000000000000000016",
      randomness,
      randomnessFlatFee: config.interfold.pricing.randomnessFlatFee,
      randomnessProviderOwnershipAcceptanceRequired: false,
      safeTransactions: "upgrade.json",
    } satisfies VrfSortitionUpgradePlan;

    expect(requirePlannedRandomnessConfig(config, plan)).to.deep.equal(
      randomness,
    );
    expect(() =>
      requirePlannedRandomnessConfig(
        {
          ...config,
          randomness: { ...config.randomness!, requestTimeout: "7200" },
        },
        plan,
      ),
    ).to.throw("config.randomness.requestTimeout");
    expect(() =>
      requirePlannedRandomnessConfig(
        {
          ...config,
          interfold: {
            ...config.interfold,
            pricing: {
              ...config.interfold.pricing,
              randomnessFlatFee: "1",
            },
          },
        },
        plan,
      ),
    ).to.throw("config.interfold.pricing.randomnessFlatFee");

    const validatedDeployment = {
      ...deployment,
      registrySortitionLib: plan.sortitionLibrary,
      ciphernodeRegistryImplementation: plan.registryImplementation,
      interfoldImplementation: plan.interfoldImplementation,
      interfoldLifecycle: plan.lifecycleLibrary,
      interfoldPricing: plan.pricingLibrary,
      randomnessProvider: plan.randomnessProvider,
      bondingRegistryImplementation: plan.bondingImplementation,
      bondingAssetLib: plan.bondingAssetLibrary,
      bondingEligibilityLib: plan.bondingEligibilityLibrary,
      bondingSlashingLib: plan.bondingSlashingLibrary,
      bondingRegistrationLib: plan.bondingRegistrationLibrary,
      bondingOwnershipLib: plan.bondingOwnershipLibrary,
      nodeReleaseRegistry: plan.nodeReleaseRegistry,
      randomness: { ...plan.randomness },
    };
    expect(() =>
      assertValidatedVrfDeploymentMatchesPlan(validatedDeployment, plan),
    ).not.to.throw();
    expect(() =>
      assertValidatedVrfDeploymentMatchesPlan(
        {
          ...validatedDeployment,
          interfoldImplementation: ethersLib.ZeroAddress,
        },
        plan,
      ),
    ).to.throw("deployment Interfold implementation");
  });

  it("rejects VRF timing that cannot satisfy protocol reservations", function () {
    const source = new URL(
      "../../deploy/protocol/mainnet-protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-protocol-vrf-timing-"),
    );
    const configFile = path.join(tempDir, "protocol.json");

    try {
      config.bonding.exitDelay = "4200";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "exitDelay 4200 must be greater than sortitionSubmissionWindow 600 + randomnessRequestTimeout 3600",
      );

      config.bonding.exitDelay = "2592000";
      config.randomness.requestTimeout = "900";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "randomness.requestTimeout must be at least 1668 seconds",
      );

      config.randomness.requestTimeout = "3600";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).not.to.throw();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects unsupported VRF parameters", async function () {
    const [owner] = await ethers.getSigners();
    if (!owner) throw new Error("owner signer missing");
    const coordinator = await ethers.deployContract(
      "ChainlinkVrfCoordinatorV2_5Mock",
      [0, 0, ethers.parseEther("1")],
    );
    await coordinator.waitForDeployment();
    await coordinator.createSubscription();
    const [subscriptionId] = await coordinator.getActiveSubscriptionIds(0, 1);
    if (!subscriptionId) throw new Error("subscription missing");
    await coordinator.fundSubscription(subscriptionId, 1n);

    const config = {
      chainId: 1,
      protocolOwner: await owner.getAddress(),
      randomness: {
        coordinator: await coordinator.getAddress(),
        subscriptionId: subscriptionId.toString(),
        keyHash: `0x${"11".repeat(32)}`,
        requestConfirmations: 1,
        callbackGasLimit: 2_500_000,
        nativePayment: false,
        minimumSubscriptionBalance: "1",
        requestTimeout: "3600",
      },
    } as ProtocolConfigFile;

    await assertVrfSubscription(ethers, config);
    await expect(
      assertVrfSubscription(ethers, {
        ...config,
        randomness: { ...config.randomness!, requestConfirmations: 0 },
      }),
    ).to.be.rejectedWith("below the coordinator minimum");
    await expect(
      assertVrfSubscription(ethers, {
        ...config,
        randomness: { ...config.randomness!, callbackGasLimit: 2_500_001 },
      }),
    ).to.be.rejectedWith("exceeds the coordinator maximum");
    await expect(
      assertVrfSubscription(ethers, {
        ...config,
        randomness: { ...config.randomness!, keyHash: ethersLib.ZeroHash },
      }),
    ).to.be.rejectedWith("keyHash is not registered");
    await expect(
      assertVrfSubscription(ethers, {
        ...config,
        randomness: {
          ...config.randomness!,
          minimumSubscriptionBalance: "2",
        },
      }),
    ).to.be.rejectedWith("balance 1 is below the configured minimum 2");

    const nativeConfig = {
      ...config,
      randomness: {
        ...config.randomness!,
        nativePayment: true,
      },
    };
    await expect(
      assertVrfSubscription(ethers, nativeConfig),
    ).to.be.rejectedWith("native balance 0 is below the configured minimum 1");
    await coordinator.fundSubscriptionWithNative(subscriptionId, {
      value: 1n,
    });
    await assertVrfSubscription(ethers, nativeConfig);
  });

  it("rejects Arbitrum VRF config", function () {
    const source = new URL(
      "../../deploy/protocol/mainnet-protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-protocol-chain-"),
    );
    const configFile = path.join(tempDir, "protocol.json");

    try {
      config.chainId = 42161;
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "VRF sortition supports Ethereum mainnet, Sepolia, and local development chains only",
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects an oversized VRF balance floor", function () {
    const source = new URL(
      "../../deploy/protocol/mainnet-protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-protocol-balance-"),
    );
    const configFile = path.join(tempDir, "protocol.json");

    try {
      config.randomness.minimumSubscriptionBalance = (1n << 96n).toString();
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "randomness.minimumSubscriptionBalance must be a positive uint96 value",
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("normalizes the optional escrow votes adapter", function () {
    const source = new URL(
      "../../deploy/protocol/example.protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-protocol-escrow-votes-"),
    );
    const configFile = path.join(tempDir, "protocol.json");
    const previousAdapter = process.env.ESCROW_VOTES_ADAPTER;
    const adapter = "0x0000000000000000000000000000000000000002";

    try {
      config.protocolOwner = "0x0000000000000000000000000000000000000001";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(loadConfig(configFile).escrowVotesAdapter).to.equal(undefined);

      process.env.ESCROW_VOTES_ADAPTER = adapter;
      expect(loadConfig(configFile).escrowVotesAdapter).to.equal(adapter);
    } finally {
      if (previousAdapter === undefined)
        delete process.env.ESCROW_VOTES_ADAPTER;
      else process.env.ESCROW_VOTES_ADAPTER = previousAdapter;
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects external wiring for the deployed MockE3Program", function () {
    const source = new URL(
      "../../deploy/protocol/example.protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-mock-program-config-"),
    );
    const configFile = path.join(tempDir, "protocol.json");

    try {
      config.protocolOwner = "0x0000000000000000000000000000000000000001";
      config.e3Programs = ["0x0000000000000000000000000000000000000002"];
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "e3Programs[0] must be the zero address when deployMockE3Program is true",
      );

      config.e3Programs = [ethersLib.ZeroAddress];
      config.bindInitialE3Program = true;
      config.ciphertextVerifier = "0x0000000000000000000000000000000000000002";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "bindInitialE3Program must be false when deployMockE3Program is true",
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects configuring and deploying a ciphertext verifier at the same time", function () {
    const source = new URL(
      "../../deploy/protocol/example.protocol.config.json",
      import.meta.url,
    );
    const config = JSON.parse(fs.readFileSync(source, "utf8"));
    const tempDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "interfold-mock-ciphertext-config-"),
    );
    const configFile = path.join(tempDir, "protocol.json");

    try {
      config.protocolOwner = "0x0000000000000000000000000000000000000001";
      config.deployMockCiphertextVerifier = true;
      config.ciphertextVerifier = "0x0000000000000000000000000000000000000002";
      fs.writeFileSync(configFile, JSON.stringify(config));
      expect(() => loadConfig(configFile)).to.throw(
        "ciphertextVerifier must be omitted when deployMockCiphertextVerifier is true",
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("uses separate fee and ticket collateral tokens", async function () {
    const [operator, safe, bondingProxyAdmin] = await ethers.getSigners();
    const bondingProxy = await ethers.deployContract("MockBondingRegistry");
    await bondingProxy.waitForDeployment();
    const tokenFactory = await ethers.getContractFactory(
      "MockFeeOnTransferToken",
    );
    // `deploy()` resolves once the transaction is sent, not once it is mined,
    // and `getAddress()` returns the computed address either way. The addresses
    // below are fed into further deployments, and Interfold rejects a program
    // address with no runtime code, so each deployment has to land first.
    const feeToken = await tokenFactory.deploy(0);
    await feeToken.waitForDeployment();
    const ticketUnderlyingToken = await tokenFactory.deploy(0);
    await ticketUnderlyingToken.waitForDeployment();
    // FOLD has to be a real votes token: the deployment builds `BondedVotes` against it, and that
    // constructor compares the token's ERC-6372 clock with the bonded history's.
    const foldFactory = await ethers.getContractFactory("MockVotesToken");
    const fold = await foldFactory.deploy();
    await fold.waitForDeployment();
    const decryptionVerifier = await ethers.deployContract(
      "MockDecryptionVerifier",
    );
    await decryptionVerifier.waitForDeployment();
    const pkVerifier = await ethers.deployContract("MockPkVerifier");
    await pkVerifier.waitForDeployment();
    const dkgFoldAttestationVerifier = await ethers.deployContract(
      "DkgFoldAttestationVerifier",
    );
    await dkgFoldAttestationVerifier.waitForDeployment();
    const coordinator: any = await ethers.deployContract(
      "ChainlinkVrfCoordinatorV2_5Mock",
      [0, 0, ethers.parseEther("1")],
    );
    await coordinator.waitForDeployment();
    await coordinator.connect(safe).createSubscription();
    const [subscriptionId] = await coordinator.getActiveSubscriptionIds(0, 1);
    if (!subscriptionId) throw new Error("subscription missing");
    await coordinator.fundSubscription(
      subscriptionId,
      ethers.parseEther("100"),
    );

    const config = JSON.parse(
      fs.readFileSync(
        new URL(
          "../../deploy/protocol/example.protocol.config.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as ProtocolConfigFile;
    config.protocolOwner = await safe.getAddress();
    config.safe = await safe.getAddress();
    config.fold = await fold.getAddress();
    config.bondingRegistryProxy = await bondingProxy.getAddress();
    config.bondingRegistryProxyAdmin = await bondingProxyAdmin.getAddress();
    config.feeToken = await feeToken.getAddress();
    config.ticketUnderlyingToken = await ticketUnderlyingToken.getAddress();
    config.protocolTreasury = await safe.getAddress();
    config.slashedFundsTreasury = await safe.getAddress();
    config.interfold.pricing.protocolTreasury = await safe.getAddress();
    config.verifiers = {
      deploy: false,
      decryptionVerifier: await decryptionVerifier.getAddress(),
      pkVerifier: await pkVerifier.getAddress(),
      dkgFoldAttestationVerifier: await dkgFoldAttestationVerifier.getAddress(),
    };
    config.deployMockCiphertextVerifier = true;
    config.randomness = {
      coordinator: await coordinator.getAddress(),
      subscriptionId: subscriptionId.toString(),
      keyHash: `0x${"11".repeat(32)}`,
      requestConfirmations: 3,
      callbackGasLimit: 500_000,
      nativePayment: false,
      minimumSubscriptionBalance: "1",
      requestTimeout: "3600",
    };

    const result = await deployProtocolContracts(ethers, operator, config);
    const ticket = await ethers.getContractAt(
      "InterfoldTicketToken",
      result.contracts.ticketToken,
    );
    const interfold = await ethers.getContractAt(
      "Interfold",
      result.contracts.interfold,
    );
    const program = await ethers.getContractAt(
      "MockE3Program",
      result.contracts.initialE3Program,
    );

    expect(await ticket.underlying()).to.equal(
      await ticketUnderlyingToken.getAddress(),
    );
    expect(await interfold.feeToken()).to.equal(await feeToken.getAddress());
    expect(
      await interfold.e3Programs(result.contracts.initialE3Program),
    ).to.equal(true);
    expect(await program.ENCRYPTION_SCHEME_ID()).to.equal(
      ethersLib.id("fhe.rs:BFV"),
    );
    expect(result.contracts.decryptionVerifier).to.equal(
      await decryptionVerifier.getAddress(),
    );
    expect(result.contracts.pkVerifier).to.equal(await pkVerifier.getAddress());
    expect(result.contracts.dkgFoldAttestationVerifier).to.equal(
      await dkgFoldAttestationVerifier.getAddress(),
    );
    expect(result.contracts.ciphertextVerifier).to.match(/^0x[0-9a-fA-F]{40}$/);
    expect(result.contracts.randomnessProvider).to.match(/^0x[0-9a-fA-F]{40}$/);
    for (const verifier of [
      result.contracts.decryptionVerifier,
      result.contracts.pkVerifier,
      result.contracts.dkgFoldAttestationVerifier,
      result.contracts.ciphertextVerifier,
    ]) {
      expect(verifier).to.match(/^0x[0-9a-fA-F]{40}$/);
      expect(await ethers.provider.getCode(verifier as string)).to.not.equal(
        "0x",
      );
    }

    // Bonded voting has to be deployed and wired by the deployment itself. Shipping the registry
    // without it leaves the feature silently disabled: the sync is a no-op while unconfigured, so
    // every operator would read as holding no bonded voting power.
    const checkpoints = await ethers.getContractAt(
      "BondedCheckpoints",
      result.contracts.bondedCheckpoints,
    );
    // Bound to the proxy, not the implementation: the proxy is what calls `sync`.
    expect(await checkpoints.registry()).to.equal(config.bondingRegistryProxy);

    // `BondedVotes` is deliberately absent here. Its constructor asks the registry which token it
    // bonds, and the registry is only initialized by the Safe batch this step writes — so it is
    // deployed by `--action activate-voting` afterwards.
    expect(result.contracts).to.not.have.property("bondedVotes");

    // The batch must carry the call that attaches the history, or none of the above is reachable.
    const txs = buildSafeTransactions(
      config,
      result.contracts,
      result.interfaces,
    );
    const selector = BondingRegistryFactory.createInterface().getFunction(
      "setBondedCheckpoints",
    ).selector;
    const attach = txs.filter(
      (tx) =>
        tx.to.toLowerCase() === config.bondingRegistryProxy.toLowerCase() &&
        tx.data.startsWith(selector),
    );
    expect(attach).to.have.lengthOf(1);
    expect(attach[0].data.toLowerCase()).to.contain(
      result.contracts.bondedCheckpoints.slice(2).toLowerCase(),
    );

    const ciphertextSelector = interfold.interface.getFunction(
      "setCiphertextVerifier",
    )!.selector;
    const ciphertextTx = txs.filter(
      (tx) =>
        tx.to.toLowerCase() === result.contracts.interfold.toLowerCase() &&
        tx.data.startsWith(ciphertextSelector),
    );
    expect(ciphertextTx).to.have.lengthOf(1);
    expect(ciphertextTx[0].data.toLowerCase()).to.contain(
      result.contracts.ciphertextVerifier!.slice(2).toLowerCase(),
    );

    const registry = await ethers.getContractAt(
      "CiphernodeRegistryOwnable",
      result.contracts.ciphernodeRegistry,
    );
    const randomnessProvider = await ethers.getContractAt(
      "ChainlinkVrfRandomnessProvider",
      result.contracts.randomnessProvider,
    );
    expect(await randomnessProvider.minimumSubscriptionBalance()).to.equal(1);
    const randomnessCalls = [
      [
        result.contracts.randomnessProvider,
        randomnessProvider.interface.getFunction("acceptOwnership")!.selector,
      ],
      [
        await coordinator.getAddress(),
        coordinator.interface.getFunction("addConsumer")!.selector,
      ],
      [
        result.contracts.ciphernodeRegistry,
        registry.interface.getFunction("setRandomnessRequestTimeout")!.selector,
      ],
      [
        result.contracts.ciphernodeRegistry,
        registry.interface.getFunction("setRandomnessProvider")!.selector,
      ],
    ] as const;
    for (const [target, selector] of randomnessCalls) {
      expect(
        txs.filter(
          (tx) =>
            tx.to.toLowerCase() === target.toLowerCase() &&
            tx.data.startsWith(selector),
        ),
      ).to.have.lengthOf(1);
    }
  });
});
