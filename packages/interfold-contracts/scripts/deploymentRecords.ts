// SPDX-License-Identifier: LGPL-3.0-only
import path from "path";

import { ethers as ethersLib, type Interface } from "ethers";

import { ADDRESS_ONE } from "./protocol/constants";
import { repoRoot } from "./protocol/files";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  ProtocolInterfaces,
} from "./protocol/types";
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
  ccaFactory: string;
  mockCcaFactory?: string;
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
    claimSource: string;
    bondingRegistry: string;
  };
}

function maybeBlock(blockNumber?: number): number | null {
  return blockNumber ?? null;
}

function shouldSyncIntegration(opts: SyncOptions): boolean {
  return Boolean(opts.syncIntegrationConfig || isLocalDeploymentChain(opts.chain));
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
        baseToken: config.feeToken,
        registry: ADDRESS_ONE,
        owner: config.safe,
      },
    },
    "InterfoldTicketToken",
    opts.chain,
  );

  storeDeploymentArgs(
    {
      address: deployment.slashingManager,
      blockNumber,
      constructorArgs: {
        initialDelay: config.slashing.initialDelay,
        admin: config.safe,
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
    { address: config.feeToken, blockNumber },
    "MockUSDC",
    opts.chain,
  );
  if (config.e3Programs?.[0]) {
    storeDeploymentArgs(
      { address: config.e3Programs[0], blockNumber },
      "MockE3Program",
      opts.chain,
    );
  }

  const registryInitData = interfaces.registry.encodeFunctionData(
    "initialize",
    [config.safe, BigInt(config.registry.sortitionSubmissionWindow)],
  );
  storeDeploymentArgs(
    {
      address: deployment.ciphernodeRegistry,
      blockNumber,
      constructorArgs: {
        owner: config.safe,
        submissionWindow: config.registry.sortitionSubmissionWindow,
      },
      proxyRecords: {
        initData: registryInitData,
        initialOwner: config.safe,
        proxyAddress: deployment.ciphernodeRegistry,
        proxyAdminAddress: deployment.ciphernodeRegistryProxyAdmin,
        implementationAddress: deployment.ciphernodeRegistryImplementation,
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

  const interfoldInitData = interfaces.interfold.encodeFunctionData(
    "initialize",
    [
      config.safe,
      deployment.ciphernodeRegistry,
      config.bondingRegistryProxy,
      ADDRESS_ONE,
      config.feeToken,
      BigInt(config.interfold.maxDuration),
      {
        dkgWindow: BigInt(config.interfold.timeoutConfig.dkgWindow),
        computeWindow: BigInt(config.interfold.timeoutConfig.computeWindow),
        decryptionWindow: BigInt(
          config.interfold.timeoutConfig.decryptionWindow,
        ),
      },
    ],
  );
  storeDeploymentArgs(
    {
      address: deployment.interfold,
      blockNumber,
      constructorArgs: {
        owner: config.safe,
        registry: deployment.ciphernodeRegistry,
        bondingRegistry: config.bondingRegistryProxy,
        e3RefundManager: ADDRESS_ONE,
        feeToken: config.feeToken,
        maxDuration: config.interfold.maxDuration,
        timeoutConfig: JSON.stringify(config.interfold.timeoutConfig),
      },
      proxyRecords: {
        initData: interfoldInitData,
        initialOwner: config.safe,
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
    [config.safe, deployment.interfold, config.protocolTreasury],
  );
  storeDeploymentArgs(
    {
      address: deployment.e3RefundManager,
      blockNumber,
      constructorArgs: {
        owner: config.safe,
        interfold: deployment.interfold,
        treasury: config.protocolTreasury,
      },
      proxyRecords: {
        initData: refundInitData,
        initialOwner: config.safe,
        proxyAddress: deployment.e3RefundManager,
        proxyAdminAddress: deployment.e3RefundManagerProxyAdmin,
        implementationAddress: deployment.e3RefundManagerImplementation,
      },
    },
    "E3RefundManager",
    opts.chain,
  );

  const bondingInitData = interfaces.bonding.encodeFunctionData("initialize", [
    config.safe,
    deployment.ticketToken,
    config.fold,
    deployment.ciphernodeRegistry,
    config.slashedFundsTreasury,
    BigInt(config.bonding.ticketPrice),
    BigInt(config.bonding.licenseRequiredBond),
    BigInt(config.bonding.minTicketBalance),
    BigInt(config.bonding.exitDelay),
  ]);
  storeDeploymentArgs(
    {
      address: config.bondingRegistryProxy,
      blockNumber,
      constructorArgs: {
        owner: config.safe,
        ticketToken: deployment.ticketToken,
        licenseToken: config.fold,
        registry: deployment.ciphernodeRegistry,
        slashedFundsTreasury: config.slashedFundsTreasury,
        ticketPrice: config.bonding.ticketPrice,
        licenseRequiredBond: config.bonding.licenseRequiredBond,
        minTicketBalance: config.bonding.minTicketBalance,
        exitDelay: config.bonding.exitDelay,
      },
      proxyRecords: {
        initData: bondingInitData,
        initialOwner: config.safe,
        proxyAddress: config.bondingRegistryProxy,
        proxyAdminAddress: config.bondingRegistryProxyAdmin,
        implementationAddress: deployment.bondingRegistryImplementation,
      },
    },
    "BondingRegistry",
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
  if (infra.mockCcaFactory) {
    storeDeploymentArgs(
      { address: infra.mockCcaFactory, blockNumber: maybeBlock(opts.blockNumber) },
      "MockCCAFactory",
      opts.chain,
    );
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
        claimSource: plan.fold.claimSource,
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
    return new ethersLib.Interface(["function initialize(address,address,address)"]);
  }
  throw new Error(`Unknown interface ${name}`);
}
