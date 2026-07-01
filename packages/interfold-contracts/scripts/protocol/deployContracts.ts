// SPDX-License-Identifier: LGPL-3.0-only
import { CiphernodeRegistryOwnable__factory as RegistryFactory } from "../../types";
import { ADDRESS_ONE } from "./constants";
import { ensurePoseidonT3 } from "./poseidon";
import { deployProxy } from "./proxies";
import type { ProtocolConfigFile, ProtocolDeployResult } from "./types";
import { deployedAddress, timeoutConfig } from "./values";

export async function deployProtocolContracts(
  ethers: any,
  operator: any,
  config: ProtocolConfigFile,
): Promise<ProtocolDeployResult> {
  const poseidonT3 = await ensurePoseidonT3(ethers);

  const ticketFactory = await ethers.getContractFactory("InterfoldTicketToken");
  const ticket = await ticketFactory.deploy(
    config.feeToken,
    ADDRESS_ONE,
    config.safe,
  );
  await ticket.waitForDeployment();
  const ticketToken = await deployedAddress(ticket);

  const slashingFactory = await ethers.getContractFactory("SlashingManager");
  const slashing = await slashingFactory.deploy(
    BigInt(config.slashing.initialDelay),
    config.safe,
  );
  await slashing.waitForDeployment();
  const slashingManager = await deployedAddress(slashing);

  const registryFactory = await ethers.getContractFactory(
    RegistryFactory.abi,
    RegistryFactory.linkBytecode({
      "npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3": poseidonT3,
    }),
    operator,
  );
  const registryImpl = await registryFactory.deploy();
  await registryImpl.waitForDeployment();
  const ciphernodeRegistryImplementation = await deployedAddress(registryImpl);
  const registryProxy = await deployProxy(
    ethers,
    ciphernodeRegistryImplementation,
    config.safe,
    registryFactory.interface.encodeFunctionData("initialize", [
      config.safe,
      BigInt(config.registry.sortitionSubmissionWindow),
    ]),
  );

  const pricingLibFactory = await ethers.getContractFactory("InterfoldPricing");
  const pricingLib = await pricingLibFactory.deploy();
  await pricingLib.waitForDeployment();
  const interfoldPricing = await deployedAddress(pricingLib);

  const interfoldFactory = await ethers.getContractFactory("Interfold", {
    libraries: { InterfoldPricing: interfoldPricing },
  });
  const interfoldImpl = await interfoldFactory.deploy();
  await interfoldImpl.waitForDeployment();
  const interfoldImplementation = await deployedAddress(interfoldImpl);
  const interfoldProxy = await deployProxy(
    ethers,
    interfoldImplementation,
    config.safe,
    interfoldFactory.interface.encodeFunctionData("initialize", [
      config.safe,
      registryProxy.proxy,
      config.bondingRegistryProxy,
      ADDRESS_ONE,
      config.feeToken,
      BigInt(config.interfold.maxDuration),
      timeoutConfig(config.interfold.timeoutConfig),
    ]),
  );

  const refundFactory = await ethers.getContractFactory("E3RefundManager");
  const refundImpl = await refundFactory.deploy();
  await refundImpl.waitForDeployment();
  const e3RefundManagerImplementation = await deployedAddress(refundImpl);
  const refundProxy = await deployProxy(
    ethers,
    e3RefundManagerImplementation,
    config.safe,
    refundFactory.interface.encodeFunctionData("initialize", [
      config.safe,
      interfoldProxy.proxy,
      config.protocolTreasury,
    ]),
  );

  const bondingFactory = await ethers.getContractFactory("BondingRegistry");
  const bondingImpl = await bondingFactory.deploy();
  await bondingImpl.waitForDeployment();

  return {
    contracts: {
      ticketToken,
      slashingManager,
      poseidonT3,
      ciphernodeRegistry: registryProxy.proxy,
      ciphernodeRegistryImplementation,
      ciphernodeRegistryProxyAdmin: registryProxy.proxyAdmin,
      interfold: interfoldProxy.proxy,
      interfoldImplementation,
      interfoldProxyAdmin: interfoldProxy.proxyAdmin,
      interfoldPricing,
      e3RefundManager: refundProxy.proxy,
      e3RefundManagerImplementation,
      e3RefundManagerProxyAdmin: refundProxy.proxyAdmin,
      bondingRegistryImplementation: await deployedAddress(bondingImpl),
    },
    interfaces: {
      ticket: ticketFactory.interface,
      slashing: slashingFactory.interface,
      registry: registryFactory.interface,
      interfold: interfoldFactory.interface,
      bonding: bondingFactory.interface,
    },
  };
}
