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
  const timeoutConfig = m.getParameter("timeoutConfig", {
    dkgWindow: 7200,
    computeWindow: 86400,
    decryptionWindow: 3600,
  });

  // Pure pricing math is delegated to the InterfoldPricing external library
  // (DELEGATECALL link) so the deployed Interfold runtime stays under the
  // EIP-170 24,576-byte cap.
  const interfoldPricing = m.library("InterfoldPricing");
  const interfoldImpl = m.contract("Interfold", [], {
    libraries: { InterfoldPricing: interfoldPricing },
  });

  const initData = m.encodeFunctionCall(interfoldImpl, "initialize", [
    owner,
    registry,
    bondingRegistry,
    e3RefundManager,
    feeToken,
    maxDuration,
    timeoutConfig,
  ]);

  const interfold = m.contract("TransparentUpgradeableProxy", [
    interfoldImpl,
    owner,
    initData,
  ]);

  return { interfold };
}) as any;
