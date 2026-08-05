// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("Interfold", (m) => {
  const owner = m.getParameter("owner");
  const maxDuration = m.getParameter("maxDuration");
  const registry = m.getParameter("registry");
  const bondingRegistry = m.getParameter("bondingRegistry");
  const e3RefundManager = m.getParameter("e3RefundManager");
  const feeToken = m.getParameter("feeToken");
  const initialE3Program = m.getParameter("initialE3Program");
  const timeoutConfig = m.getParameter("timeoutConfig", {
    dkgWindow: 7200,
    computeWindow: 86400,
    decryptionWindow: 3600,
  });
  const pricingConfig = m.getParameter("pricingConfig", {
    keyGenFixedPerNode: 100000,
    keyGenPerEncryptionProof: 50000,
    coordinationPerPair: 10000,
    availabilityPerNodePerSec: 50,
    decryptionPerNode: 300000,
    publicationBase: 1000000,
    verificationPerProof: 5000,
    protocolTreasury: "0x0000000000000000000000000000000000000000",
    marginBps: 1000,
    protocolShareBps: 0,
    dkgUtilizationBps: 2500,
    computeUtilizationBps: 5000,
    decryptUtilizationBps: 2500,
    minCommitteeSize: 0,
    minThreshold: 0,
  });

  // External libraries keep pricing and lifecycle helpers out of the
  // size-constrained Interfold runtime.
  const interfoldLifecycle = m.library("InterfoldLifecycle");
  const interfoldPricing = m.library("InterfoldPricing");
  const interfoldImpl = m.contract("Interfold", [], {
    libraries: {
      InterfoldLifecycle: interfoldLifecycle,
      InterfoldPricing: interfoldPricing,
    },
  });

  const initData = m.encodeFunctionCall(interfoldImpl, "initialize", [
    owner,
    registry,
    bondingRegistry,
    e3RefundManager,
    feeToken,
    maxDuration,
    timeoutConfig,
    pricingConfig,
    initialE3Program,
  ]);

  const interfold = m.contract("TransparentUpgradeableProxy", [
    interfoldImpl,
    owner,
    initData,
  ]);

  return { interfold, interfoldLifecycle, interfoldPricing };
}) as any;
