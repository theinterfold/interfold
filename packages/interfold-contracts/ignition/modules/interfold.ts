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
  const feeTokenDecimals = m.getParameter("feeTokenDecimals", 6);
  const initialE3Program = m.getParameter("initialE3Program");
  const timeoutConfig = m.getParameter("timeoutConfig", {
    dkgWindow: 21600,
    computeWindow: 86400,
    decryptionWindow: 3600,
  });
  const pricingConfig = m.getParameter("pricingConfig");

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
    {
      token: feeToken,
      expectedDecimals: feeTokenDecimals,
      pricing: pricingConfig,
    },
    maxDuration,
    timeoutConfig,
    initialE3Program,
  ]);

  const interfold = m.contract("TransparentUpgradeableProxy", [
    interfoldImpl,
    owner,
    initData,
  ]);

  return { interfold, interfoldLifecycle, interfoldPricing };
}) as any;
