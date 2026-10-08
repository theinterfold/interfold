// SPDX-License-Identifier: LGPL-3.0-only
import { type Interface, ethers as ethersLib } from "ethers";
import path from "path";

import { pricingConfigFingerprint } from "./pricingConfig";
import { ADDRESS_ONE } from "./protocol/constants";
import { repoRoot } from "./protocol/files";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  ProtocolInterfaces,
} from "./protocol/types";
import { feeAssetConfig } from "./protocol/values";
import {
  isLocalDeploymentChain,
  storeDeploymentArgs,
  updateE3Config,
} from "./utils";

interface SyncOptions {
  chain: string;
  blockNumber?: number;
  syncIntegrationConfig?: boolean;
}

interface SaleInfraRecord {
  safe: string;
  saleDeployer: string;
  bondingRegistryProxy: string;
  bondingRegistryImplementation: string;
  bondingRegistryProxyAdmin: string;
  validationHook?: string;
  predicateRegistry?: string;
  predicatePolicyID?: string;
  predicateRequireSenderIsOwner?: boolean;
}

interface SaleDeploymentRecord {
  safe: string;
  saleDeployer: string;
  fold: string;
  auction: string;
  bondingRegistry: string;
  bondingRegistryProxyAdmin?: string;
  blockNumber?: number;
}

interface SalePlanRecord {
  fold: {
    initialOwner: string;
    ccaStart: string;
    ccaEnd: string;
    noMoreLocks: string;
    bondingRegistry: string;
  };
}

function maybeBlock(blockNumber?: number): number | null {
  return blockNumber ?? null;
}

function shouldSyncIntegration(opts: SyncOptions): boolean {
  return Boolean(
    opts.syncIntegrationConfig || isLocalDeploymentChain(opts.chain),
  );
}

function integrationConfigPath(): string {
  return path.join(repoRoot, "tests", "integration", "interfold.config.yaml");
}

export function syncProtocolDeploymentRecords(
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
  interfaces: ProtocolInterfaces,
  opts: SyncOptions,
): void {
  const blockNumber = maybeBlock(opts.blockNumber);

  storeDeploymentArgs(
    {
      address: deployment.ticketToken,
      blockNumber,
      constructorArgs: {
        baseToken: config.ticketUnderlyingToken,
        registry: ADDRESS_ONE,
        owner: config.protocolOwner,
      },
    },
    "InterfoldTicketToken",
    opts.chain,
  );

  storeDeploymentArgs(
    { address: deployment.slashingEvidenceLib, blockNumber },
    "SlashingEvidenceLib",
    opts.chain,
  );

  storeDeploymentArgs(
    {
      address: deployment.slashingManager,
      blockNumber,
      constructorArgs: {
        initialDelay: config.slashing.initialDelay,
        admin: config.protocolOwner,
      },
      libraries: {
        SlashingEvidenceLib: deployment.slashingEvidenceLib,
      },
    },
    "SlashingManager",
    opts.chain,
  );

  storeDeploymentArgs(
    { address: deployment.poseidonT3, blockNumber },
    "PoseidonT3",
    opts.chain,
  );
  storeDeploymentArgs(
    { address: deployment.registrySortitionLib, blockNumber },
    "RegistrySortitionLib",
    opts.chain,
  );
  if (config.randomness && deployment.randomnessProvider) {
    storeDeploymentArgs(
      {
        address: deployment.randomnessProvider,
        blockNumber,
        constructorArgs: {
          requesterAddress: deployment.ciphernodeRegistry,
          coordinator: config.randomness.coordinator,
          vrfSubscriptionId: config.randomness.subscriptionId,
          vrfKeyHash: config.randomness.keyHash,
          vrfRequestConfirmations: config.randomness.requestConfirmations,
          vrfCallbackGasLimit: config.randomness.callbackGasLimit,
          payInNativeToken: config.randomness.nativePayment,
          vrfMinimumSubscriptionBalance:
            config.randomness.minimumSubscriptionBalance,
          protocolOwner: config.protocolOwner,
        },
      },
      "ChainlinkVrfRandomnessProvider",
      opts.chain,
    );
  }
  storeDeploymentArgs(
    { address: config.feeToken, blockNumber },
    "MockUSDC",
    opts.chain,
  );
  if (config.deployMockE3Program) {
    storeDeploymentArgs(
      { address: deployment.initialE3Program, blockNumber },
      "MockE3Program",
      opts.chain,
    );
  } else if (config.e3Programs?.[0]) {
    storeDeploymentArgs(
      { address: deployment.initialE3Program, blockNumber },
      "MockE3Program",
      opts.chain,
    );
  }

  const registryInitData = interfaces.registry.encodeFunctionData(
    "initialize",
    [config.protocolOwner, BigInt(config.registry.sortitionSubmissionWindow)],
  );
  storeDeploymentArgs(
    {
      address: deployment.ciphernodeRegistry,
      blockNumber,
      constructorArgs: {
        owner: config.protocolOwner,
        submissionWindow: config.registry.sortitionSubmissionWindow,
      },
      proxyRecords: {
        initData: registryInitData,
        initialOwner: config.protocolOwner,
        proxyAddress: deployment.ciphernodeRegistry,
        proxyAdminAddress: deployment.ciphernodeRegistryProxyAdmin,
        implementationAddress: deployment.ciphernodeRegistryImplementation,
      },
      libraries: {
        PoseidonT3: deployment.poseidonT3,
        RegistrySortitionLib: deployment.registrySortitionLib,
      },
    },
    "CiphernodeRegistryOwnable",
    opts.chain,
  );

  storeDeploymentArgs(
    {
      address: deployment.interfoldPricing,
      blockNumber,
    },
    "InterfoldPricing",
    opts.chain,
  );

  storeDeploymentArgs(
    {
      address: deployment.interfoldLifecycle,
      blockNumber,
    },
    "InterfoldLifecycle",
    opts.chain,
  );

  storeDeploymentArgs(
    { address: deployment.bondingAssetLib, blockNumber },
    "BondingAssetLib",
    opts.chain,
  );
  storeDeploymentArgs(
    { address: deployment.bondingEligibilityLib, blockNumber },
    "BondingEligibilityLib",
    opts.chain,
  );
  storeDeploymentArgs(
    { address: deployment.bondingSlashingLib, blockNumber },
    "BondingSlashingLib",
    opts.chain,
  );
  storeDeploymentArgs(
    { address: deployment.bondingRegistrationLib, blockNumber },
    "BondingRegistrationLib",
    opts.chain,
  );
  storeDeploymentArgs(
    { address: deployment.bondingOwnershipLib, blockNumber },
    "BondingOwnershipLib",
    opts.chain,
  );
  storeDeploymentArgs(
    {
      address: deployment.bondedCheckpoints,
      blockNumber,
      constructorArgs: { registry: config.bondingRegistryProxy },
    },
    "BondedCheckpoints",
    opts.chain,
  );
  // Absent until `--action activate-voting`, which cannot run before the Safe batch configures the
  // registry the constructor validates against.
  if (deployment.bondedVotes) {
    storeDeploymentArgs(
      {
        address: deployment.bondedVotes,
        blockNumber,
        constructorArgs: {
          token: config.fold,
          votesSource: config.escrowVotesAdapter ?? config.fold,
          checkpoints: deployment.bondedCheckpoints,
          excludedAccounts: config.bondedVotesExcludedAccounts ?? [],
        },
      },
      "BondedVotes",
      opts.chain,
    );
  }

  const interfoldInitData = interfaces.interfold.encodeFunctionData(
    "initialize",
    [
      config.protocolOwner,
      deployment.ciphernodeRegistry,
      config.bondingRegistryProxy,
      ADDRESS_ONE,
      feeAssetConfig(config),
      BigInt(config.interfold.maxDuration),
      {
        dkgWindow: BigInt(config.interfold.timeoutConfig.dkgWindow),
        computeWindow: BigInt(config.interfold.timeoutConfig.computeWindow),
        decryptionWindow: BigInt(
          config.interfold.timeoutConfig.decryptionWindow,
        ),
      },
      deployment.initialE3Program,
    ],
  );
  storeDeploymentArgs(
    {
      address: deployment.interfold,
      blockNumber,
      constructorArgs: {
        owner: config.protocolOwner,
        registry: deployment.ciphernodeRegistry,
        bondingRegistry: config.bondingRegistryProxy,
        e3RefundManager: ADDRESS_ONE,
        feeToken: config.feeToken,
        feeTokenDecimals: config.feeTokenDecimals,
        randomnessFlatFee: config.interfold.pricing.randomnessFlatFee,
        maxDuration: config.interfold.maxDuration,
        timeoutConfig: JSON.stringify(config.interfold.timeoutConfig),
        pricingConfig: pricingConfigFingerprint(config.interfold.pricing),
        initialE3Program: deployment.initialE3Program,
      },
      libraries: {
        InterfoldLifecycle: deployment.interfoldLifecycle,
        InterfoldPricing: deployment.interfoldPricing,
      },
      proxyRecords: {
        initData: interfoldInitData,
        initialOwner: config.protocolOwner,
        proxyAddress: deployment.interfold,
        proxyAdminAddress: deployment.interfoldProxyAdmin,
        implementationAddress: deployment.interfoldImplementation,
      },
    },
    "Interfold",
    opts.chain,
  );

  const refundInitData = interfacesFor("E3RefundManager").encodeFunctionData(
    "initialize",
    [config.protocolOwner, deployment.interfold, config.protocolTreasury],
  );
  storeDeploymentArgs(
    {
      address: deployment.e3RefundManager,
      blockNumber,
      constructorArgs: {
        owner: config.protocolOwner,
        interfold: deployment.interfold,
        treasury: config.protocolTreasury,
      },
      proxyRecords: {
        initData: refundInitData,
        initialOwner: config.protocolOwner,
        proxyAddress: deployment.e3RefundManager,
        proxyAdminAddress: deployment.e3RefundManagerProxyAdmin,
        implementationAddress: deployment.e3RefundManagerImplementation,
      },
    },
    "E3RefundManager",
    opts.chain,
  );

  const bondingInitData = interfaces.bonding.encodeFunctionData("initialize", [
    config.protocolOwner,
    {
      ticketToken: deployment.ticketToken,
      ciphernodeBondToken: config.fold,
      ticketPrice: BigInt(config.bonding.ticketPrice),
      requiredCiphernodeBond: BigInt(config.bonding.requiredCiphernodeBond),
      expectedTicketDecimals: config.bonding.ticketTokenDecimals,
      expectedCiphernodeBondDecimals:
        config.bonding.ciphernodeBondTokenDecimals,
    },
    deployment.ciphernodeRegistry,
    config.slashedFundsTreasury,
    BigInt(config.bonding.minTicketBalance),
    BigInt(config.bonding.exitDelay),
  ]);
  storeDeploymentArgs(
    {
      address: config.bondingRegistryProxy,
      blockNumber,
      constructorArgs: {
        owner: config.protocolOwner,
        ticketToken: deployment.ticketToken,
        ciphernodeBondToken: config.fold,
        registry: deployment.ciphernodeRegistry,
        slashedFundsTreasury: config.slashedFundsTreasury,
        ticketPrice: config.bonding.ticketPrice,
        requiredCiphernodeBond: config.bonding.requiredCiphernodeBond,
        ticketTokenDecimals: config.bonding.ticketTokenDecimals,
        ciphernodeBondTokenDecimals: config.bonding.ciphernodeBondTokenDecimals,
        minTicketBalance: config.bonding.minTicketBalance,
        exitDelay: config.bonding.exitDelay,
      },
      libraries: {
        BondingAssetLib: deployment.bondingAssetLib,
        BondingEligibilityLib: deployment.bondingEligibilityLib,
        BondingSlashingLib: deployment.bondingSlashingLib,
        BondingRegistrationLib: deployment.bondingRegistrationLib,
        BondingOwnershipLib: deployment.bondingOwnershipLib,
      },
      proxyRecords: {
        initData: bondingInitData,
        initialOwner: config.protocolOwner,
        proxyAddress: config.bondingRegistryProxy,
        proxyAdminAddress: config.bondingRegistryProxyAdmin,
        implementationAddress: deployment.bondingRegistryImplementation,
      },
    },
    "BondingRegistry",
    opts.chain,
  );

  storeDeploymentArgs(
    {
      address: deployment.nodeReleaseRegistry,
      blockNumber,
      constructorArgs: {
        owner: config.protocolOwner,
        bondingRegistry: config.bondingRegistryProxy,
        ciphernodeRegistry: deployment.ciphernodeRegistry,
      },
    },
    "NodeReleaseRegistry",
    opts.chain,
  );

  if (shouldSyncIntegration(opts)) {
    updateE3Config(opts.chain, integrationConfigPath(), {
      Interfold: "interfold",
      CiphernodeRegistryOwnable: "ciphernode_registry",
      BondingRegistry: "bonding_registry",
      SlashingManager: "slashing_manager",
      MockUSDC: "fee_token",
    });
  }
}

export function syncSaleInfraRecords(
  infra: SaleInfraRecord,
  opts: SyncOptions,
): void {
  storeDeploymentArgs(
    {
      address: infra.saleDeployer,
      blockNumber: maybeBlock(opts.blockNumber),
      constructorArgs: { protocolAdmin: infra.safe },
    },
    "InterfoldTokenSaleDeployer",
    opts.chain,
  );
  storeDeploymentArgs(
    {
      address: infra.bondingRegistryProxy,
      blockNumber: maybeBlock(opts.blockNumber),
      skipVerification: true,
      verificationNote:
        "Phase-1 placeholder bonding proxy; verify after protocol deploy replaces it with the real BondingRegistry implementation.",
      proxyRecords: {
        initData: "0x",
        initialOwner: infra.safe,
        proxyAddress: infra.bondingRegistryProxy,
        proxyAdminAddress: infra.bondingRegistryProxyAdmin,
        implementationAddress: infra.bondingRegistryImplementation,
      },
    },
    "BondingRegistry",
    opts.chain,
  );
  if (infra.validationHook) {
    const hasHookConstructorArgs = Boolean(
      infra.predicateRegistry && infra.predicatePolicyID,
    );
    const hookRecord = {
      address: infra.validationHook,
      blockNumber: maybeBlock(opts.blockNumber),
      skipVerification: hasHookConstructorArgs ? undefined : true,
      verificationNote: hasHookConstructorArgs
        ? undefined
        : "Predicate hook was supplied as an existing address; constructor args are not recorded.",
      constructorArgs: hasHookConstructorArgs
        ? {
            owner: infra.safe,
            registry: infra.predicateRegistry,
            policyID: infra.predicatePolicyID,
            requireSenderIsOwner: infra.predicateRequireSenderIsOwner ?? true,
          }
        : undefined,
    };
    storeDeploymentArgs(hookRecord, "PredicateValidationHook", opts.chain);
  }
}

export function syncSaleDeploymentRecords(
  deployment: SaleDeploymentRecord,
  plan: SalePlanRecord,
  opts: SyncOptions,
): void {
  storeDeploymentArgs(
    {
      address: deployment.fold,
      blockNumber: maybeBlock(deployment.blockNumber ?? opts.blockNumber),
      constructorArgs: {
        owner: plan.fold.initialOwner,
        ccaStart: plan.fold.ccaStart,
        ccaEnd: plan.fold.ccaEnd,
        noMoreLocks: plan.fold.noMoreLocks,
        bondingRegistry: plan.fold.bondingRegistry,
      },
    },
    "InterfoldToken",
    opts.chain,
  );
}

function interfacesFor(name: "E3RefundManager"): Interface {
  // Keep this tiny helper here so deployment record generation stays independent
  // from a connected Hardhat runtime.
  if (name === "E3RefundManager") {
    return new ethersLib.Interface([
      "function initialize(address,address,address)",
    ]);
  }
  throw new Error(`Unknown interface ${name}`);
}
