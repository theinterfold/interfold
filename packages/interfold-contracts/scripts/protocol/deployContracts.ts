// SPDX-License-Identifier: LGPL-3.0-only
import { CiphernodeRegistryOwnable__factory as RegistryFactory } from "../../types";
import {
  ActiveBfvConfig,
  activeBfvConfigForChain,
  bfvConfigsForChain,
  getBfvDecryptionSubCircuitVkHashPaths,
  getBfvPkSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../utils";
import { ADDRESS_ONE } from "./constants";
import { deployNodeReleaseRegistry } from "./nodeRelease";
import { ensurePoseidonT3 } from "./poseidon";
import { deployProxy } from "./proxies";
import { deployRandomnessProvider } from "./randomness";
import type { ProtocolConfigFile, ProtocolDeployResult } from "./types";
import { deployedAddress, feeAssetConfig, timeoutConfig } from "./values";

export async function deployProtocolContracts(
  ethers: any,
  operator: any,
  config: ProtocolConfigFile,
): Promise<ProtocolDeployResult> {
  const poseidonT3 = await ensurePoseidonT3(ethers);

  let initialE3Program = config.e3Programs[0];
  if (config.deployMockE3Program) {
    const programFactory = await ethers.getContractFactory("MockE3Program");
    const program = await programFactory.deploy();
    await program.waitForDeployment();
    initialE3Program = await deployedAddress(program);
  }

  const ticketFactory = await ethers.getContractFactory("InterfoldTicketToken");
  const ticket = await ticketFactory.deploy(
    config.ticketUnderlyingToken,
    ADDRESS_ONE,
    config.protocolOwner,
  );
  await ticket.waitForDeployment();
  const ticketToken = await deployedAddress(ticket);

  const slashingEvidenceFactory = await ethers.getContractFactory(
    "SlashingEvidenceLib",
  );
  const slashingEvidence = await slashingEvidenceFactory.deploy();
  await slashingEvidence.waitForDeployment();
  const slashingEvidenceLib = await deployedAddress(slashingEvidence);
  const slashingFactory = await ethers.getContractFactory("SlashingManager", {
    libraries: { SlashingEvidenceLib: slashingEvidenceLib },
  });
  const slashing = await slashingFactory.deploy(
    BigInt(config.slashing.initialDelay),
    config.protocolOwner,
  );
  await slashing.waitForDeployment();
  const slashingManager = await deployedAddress(slashing);

  const registrySortitionFactory = await ethers.getContractFactory(
    "RegistrySortitionLib",
  );
  const registrySortition = await registrySortitionFactory.deploy();
  await registrySortition.waitForDeployment();
  const registrySortitionLib = await deployedAddress(registrySortition);

  const registryFactory = await ethers.getContractFactory(
    RegistryFactory.abi,
    RegistryFactory.linkBytecode({
      "npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3": poseidonT3,
      "project/contracts/lib/RegistrySortitionLib.sol:RegistrySortitionLib":
        registrySortitionLib,
    }),
    operator,
  );
  const registryImpl = await registryFactory.deploy();
  await registryImpl.waitForDeployment();
  const ciphernodeRegistryImplementation = await deployedAddress(registryImpl);
  const registryProxy = await deployProxy(
    ethers,
    ciphernodeRegistryImplementation,
    config.protocolOwner,
    registryFactory.interface.encodeFunctionData("initialize", [
      config.protocolOwner,
      BigInt(config.registry.sortitionSubmissionWindow),
    ]),
  );

  const randomness = await deployRandomnessProvider(
    ethers,
    operator,
    config,
    registryProxy.proxy,
  );

  const pricingLibFactory = await ethers.getContractFactory("InterfoldPricing");
  const pricingLib = await pricingLibFactory.deploy();
  await pricingLib.waitForDeployment();
  const interfoldPricing = await deployedAddress(pricingLib);

  const lifecycleLibFactory =
    await ethers.getContractFactory("InterfoldLifecycle");
  const lifecycleLib = await lifecycleLibFactory.deploy();
  await lifecycleLib.waitForDeployment();
  const interfoldLifecycle = await deployedAddress(lifecycleLib);

  const interfoldFactory = await ethers.getContractFactory("Interfold", {
    libraries: {
      InterfoldLifecycle: interfoldLifecycle,
      InterfoldPricing: interfoldPricing,
    },
  });
  const interfoldImpl = await interfoldFactory.deploy();
  await interfoldImpl.waitForDeployment();
  const interfoldImplementation = await deployedAddress(interfoldImpl);
  const interfoldProxy = await deployProxy(
    ethers,
    interfoldImplementation,
    config.protocolOwner,
    interfoldFactory.interface.encodeFunctionData("initialize", [
      config.protocolOwner,
      registryProxy.proxy,
      config.bondingRegistryProxy,
      ADDRESS_ONE,
      feeAssetConfig(config),
      BigInt(config.interfold.maxDuration),
      timeoutConfig(config.interfold.timeoutConfig),
      initialE3Program,
    ]),
  );

  const refundClaimFactory = await ethers.getContractFactory("RefundClaimLib");
  const refundClaimLib = await refundClaimFactory.deploy();
  await refundClaimLib.waitForDeployment();
  const refundFactory = await ethers.getContractFactory("E3RefundManager", {
    libraries: { RefundClaimLib: await deployedAddress(refundClaimLib) },
  });
  const refundImpl = await refundFactory.deploy();
  await refundImpl.waitForDeployment();
  const e3RefundManagerImplementation = await deployedAddress(refundImpl);
  const refundProxy = await deployProxy(
    ethers,
    e3RefundManagerImplementation,
    config.protocolOwner,
    refundFactory.interface.encodeFunctionData("initialize", [
      config.protocolOwner,
      interfoldProxy.proxy,
      config.protocolTreasury,
    ]),
  );

  const bondingAssetFactory =
    await ethers.getContractFactory("BondingAssetLib");
  const bondingAsset = await bondingAssetFactory.deploy();
  await bondingAsset.waitForDeployment();
  const bondingAssetLib = await deployedAddress(bondingAsset);

  const bondingEligibilityFactory = await ethers.getContractFactory(
    "BondingEligibilityLib",
  );
  const bondingEligibility = await bondingEligibilityFactory.deploy();
  await bondingEligibility.waitForDeployment();
  const bondingEligibilityLib = await deployedAddress(bondingEligibility);

  const bondingSlashingFactory =
    await ethers.getContractFactory("BondingSlashingLib");
  const bondingSlashing = await bondingSlashingFactory.deploy();
  await bondingSlashing.waitForDeployment();
  const bondingSlashingLib = await deployedAddress(bondingSlashing);

  const bondingRegistrationFactory = await ethers.getContractFactory(
    "BondingRegistrationLib",
  );
  const bondingRegistration = await bondingRegistrationFactory.deploy();
  await bondingRegistration.waitForDeployment();
  const bondingRegistrationLib = await deployedAddress(bondingRegistration);

  const bondingOwnershipFactory = await ethers.getContractFactory(
    "BondingOwnershipLib",
  );
  const bondingOwnership = await bondingOwnershipFactory.deploy();
  await bondingOwnership.waitForDeployment();
  const bondingOwnershipLib = await deployedAddress(bondingOwnership);

  const bondingFactory = await ethers.getContractFactory("BondingRegistry", {
    libraries: {
      BondingAssetLib: bondingAssetLib,
      BondingEligibilityLib: bondingEligibilityLib,
      BondingSlashingLib: bondingSlashingLib,
      BondingRegistrationLib: bondingRegistrationLib,
      BondingOwnershipLib: bondingOwnershipLib,
    },
  });
  const bondingImpl = await bondingFactory.deploy();
  await bondingImpl.waitForDeployment();

  const nodeRelease = await deployNodeReleaseRegistry(
    ethers,
    config.protocolOwner,
    config.bondingRegistryProxy,
    registryProxy.proxy,
  );
  const nodeReleaseRegistry = nodeRelease.address;

  // Bound to the proxy, not the implementation: the proxy is the address that calls `sync`, and
  // `BondedCheckpoints` accepts writes from exactly one address. The registry is pointed at this
  // contract by a `setBondedCheckpoints` transaction in the governance batch, after `initialize`.
  const checkpointsFactory =
    await ethers.getContractFactory("BondedCheckpoints");
  const checkpoints = await checkpointsFactory.deploy(
    config.bondingRegistryProxy,
  );
  await checkpoints.waitForDeployment();
  const bondedCheckpoints = await deployedAddress(checkpoints);

  const activeBfvConfig = activeBfvConfigForChain(config.chainId);
  const bfvConfigs = bfvConfigsForChain(config.chainId);
  const deployedVerifiers = config.verifiers?.deploy
    ? await deployBfvVerifiers(
        ethers,
        registryProxy.proxy,
        activeBfvConfig,
        bfvConfigs,
      )
    : {
        decryptionVerifier: config.verifiers?.decryptionVerifier,
        pkVerifier: config.verifiers?.pkVerifier,
        dkgFoldAttestationVerifier:
          config.verifiers?.dkgFoldAttestationVerifier,
      };

  const deployedCiphertextVerifier = config.deployMockCiphertextVerifier
    ? await deployMockCiphertextVerifier(ethers)
    : undefined;

  // `BondedVotes` is deliberately NOT deployed here. Its constructor asks the registry which token
  // it bonds and refuses to build unless that matches the token it will read votes from — and the
  // registry is only initialized later, by the governance batch this script writes. It is deployed by
  // `--action activate-voting`, once that batch has executed.

  return {
    contracts: {
      ticketToken,
      slashingManager,
      slashingEvidenceLib,
      poseidonT3,
      registrySortitionLib,
      ...randomness,
      ciphernodeRegistry: registryProxy.proxy,
      ciphernodeRegistryImplementation,
      ciphernodeRegistryProxyAdmin: registryProxy.proxyAdmin,
      interfold: interfoldProxy.proxy,
      interfoldImplementation,
      interfoldProxyAdmin: interfoldProxy.proxyAdmin,
      interfoldLifecycle,
      interfoldPricing,
      e3RefundManager: refundProxy.proxy,
      e3RefundManagerImplementation,
      e3RefundManagerProxyAdmin: refundProxy.proxyAdmin,
      bondingAssetLib,
      bondingEligibilityLib,
      bondingRegistryImplementation: await deployedAddress(bondingImpl),
      bondingSlashingLib,
      bondingRegistrationLib,
      bondingOwnershipLib,
      nodeReleaseRegistry,
      bondedCheckpoints,
      initialE3Program,
      ...deployedVerifiers,
      ...(deployedCiphertextVerifier
        ? { ciphertextVerifier: deployedCiphertextVerifier }
        : {}),
    },
    interfaces: {
      ticket: ticketFactory.interface,
      slashing: slashingFactory.interface,
      registry: registryFactory.interface,
      interfold: interfoldFactory.interface,
      bonding: bondingFactory.interface,
      nodeRelease: nodeRelease.interface,
    },
  };
}

async function deployMockCiphertextVerifier(ethers: any) {
  const factory = await ethers.getContractFactory(
    "DeployableMockCiphertextVerifier",
  );
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();
  return deployedAddress(verifier);
}

function bfvHonkSource(
  config: ActiveBfvConfig,
  contractName: "DkgAggregatorVerifier" | "DecryptionAggregatorVerifier",
): string {
  if (config.preset === "insecure-512" && config.committee === "minimum") {
    return `contracts/verifiers/bfv/honk/${contractName}.sol`;
  }
  return `contracts/verifiers/bfv/honk/${config.preset}/${config.committee}/${contractName}.sol`;
}

async function deployBfvVerifiers(
  ethers: any,
  registry: string,
  defaultConfig: ActiveBfvConfig,
  configs: readonly ActiveBfvConfig[],
) {
  const verifierRoutes = await deployBfvVerifierRoutes(
    ethers,
    registry,
    defaultConfig,
    configs,
  );

  const dkgFoldFactory = await ethers.getContractFactory(
    "DkgFoldAttestationVerifier",
  );
  const dkgFold = await dkgFoldFactory.deploy();
  await dkgFold.waitForDeployment();
  const dkgFoldAttestationVerifier = await deployedAddress(dkgFold);

  return {
    ...verifierRoutes,
    dkgFoldAttestationVerifier,
  };
}

export async function deployBfvVerifierRoutes(
  ethers: any,
  registry: string,
  defaultConfig: ActiveBfvConfig,
  configs: readonly ActiveBfvConfig[],
) {
  if (configs.length === 0) {
    throw new Error("At least one BFV verifier route is required");
  }

  const routes = [];
  for (const config of configs) {
    routes.push(await deployBfvVerifierRoute(ethers, registry, config));
  }

  let pkVerifier = routes[0].pkVerifier;
  let decryptionVerifier = routes[0].decryptionVerifier;
  if (routes.length > 1) {
    const pkRouterFactory = await ethers.getContractFactory(
      "BfvPkVerifierRouter",
    );
    const pkRouter = await pkRouterFactory.deploy(
      routes.map((route) => route.pkVerifier),
      defaultConfig.h,
    );
    await pkRouter.waitForDeployment();
    pkVerifier = await deployedAddress(pkRouter);

    const decryptionRouterFactory = await ethers.getContractFactory(
      "BfvDecryptionVerifierRouter",
    );
    const decryptionRouter = await decryptionRouterFactory.deploy(
      routes.map((route) => route.decryptionVerifier),
      defaultConfig.t,
    );
    await decryptionRouter.waitForDeployment();
    decryptionVerifier = await deployedAddress(decryptionRouter);
  }

  return {
    decryptionVerifier,
    pkVerifier,
    dkgAggregatorVerifier: routes[0].dkgAggregatorVerifier,
    decryptionAggregatorVerifier: routes[0].decryptionAggregatorVerifier,
    verifierZkTranscriptLib: routes[0].verifierZkTranscriptLib,
    dkgVerifierRelationsLib: routes[0].dkgVerifierRelationsLib,
    decryptionVerifierRelationsLib: routes[0].decryptionVerifierRelationsLib,
    bfvVerifierRoutes: routes,
  };
}

async function deployBfvVerifierRoute(
  ethers: any,
  registry: string,
  config: ActiveBfvConfig,
) {
  const dkgSource = bfvHonkSource(config, "DkgAggregatorVerifier");
  const decryptionSource = bfvHonkSource(
    config,
    "DecryptionAggregatorVerifier",
  );

  const zkTranscriptFactory = await ethers.getContractFactory(
    `${dkgSource}:ZKTranscriptLib`,
  );
  const zkTranscript = await zkTranscriptFactory.deploy();
  await zkTranscript.waitForDeployment();
  const verifierZkTranscriptLib = await deployedAddress(zkTranscript);

  const dkgRelationsFactory = await ethers.getContractFactory(
    `${dkgSource}:RelationsLib`,
  );
  const dkgRelations = await dkgRelationsFactory.deploy();
  await dkgRelations.waitForDeployment();
  const dkgVerifierRelationsLib = await deployedAddress(dkgRelations);

  const decryptionRelationsFactory = await ethers.getContractFactory(
    `${decryptionSource}:RelationsLib`,
  );
  const decryptionRelations = await decryptionRelationsFactory.deploy();
  await decryptionRelations.waitForDeployment();
  const decryptionVerifierRelationsLib =
    await deployedAddress(decryptionRelations);

  const dkgAggregatorFactory = await ethers.getContractFactory(
    `${dkgSource}:DkgAggregatorVerifier`,
    {
      libraries: {
        [`project/${dkgSource}:ZKTranscriptLib`]: verifierZkTranscriptLib,
        [`project/${dkgSource}:RelationsLib`]: dkgVerifierRelationsLib,
      },
    },
  );
  const dkgAggregator = await dkgAggregatorFactory.deploy();
  await dkgAggregator.waitForDeployment();
  const dkgAggregatorVerifier = await deployedAddress(dkgAggregator);

  const decryptionAggregatorFactory = await ethers.getContractFactory(
    `${decryptionSource}:DecryptionAggregatorVerifier`,
    {
      libraries: {
        [`project/${decryptionSource}:ZKTranscriptLib`]:
          verifierZkTranscriptLib,
        [`project/${decryptionSource}:RelationsLib`]:
          decryptionVerifierRelationsLib,
      },
    },
  );
  const decryptionAggregator = await decryptionAggregatorFactory.deploy();
  await decryptionAggregator.waitForDeployment();
  const decryptionAggregatorVerifier =
    await deployedAddress(decryptionAggregator);

  const pkPaths = getBfvPkSubCircuitVkHashPaths(config);
  const pkFactory = await ethers.getContractFactory("BfvPkVerifier");
  const pk = await pkFactory.deploy(
    dkgAggregatorVerifier,
    readVkRecursiveHash(pkPaths.nodesFold, config),
    readVkRecursiveHash(pkPaths.c5, config),
    config.h,
  );
  await pk.waitForDeployment();
  const pkVerifier = await deployedAddress(pk);

  const decryptionPaths = getBfvDecryptionSubCircuitVkHashPaths(config);
  const decryptionFactory = await ethers.getContractFactory(
    "BfvDecryptionVerifier",
  );
  const decryption = await decryptionFactory.deploy(
    decryptionAggregatorVerifier,
    registry,
    readVkRecursiveHash(decryptionPaths.c6Fold, config),
    readVkRecursiveHash(decryptionPaths.c7, config),
    config.t,
  );
  await decryption.waitForDeployment();
  const decryptionVerifier = await deployedAddress(decryption);

  return {
    preset: config.preset,
    committee: config.committee,
    paramSet: config.paramSet,
    committeeSize: config.committeeSize,
    decryptionVerifier,
    pkVerifier,
    dkgAggregatorVerifier,
    decryptionAggregatorVerifier,
    verifierZkTranscriptLib,
    dkgVerifierRelationsLib,
    decryptionVerifierRelationsLib,
  };
}
