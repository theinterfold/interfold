// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("E3RefundManager", (m) => {
  const owner = m.getParameter("owner");
  const interfold = m.getParameter("interfold");
  const treasury = m.getParameter("treasury");

  // External library keeps the honest-node claim checks out of the
  // size-constrained E3RefundManager runtime.
  const refundClaimLib = m.library("RefundClaimLib");
  const e3RefundManagerImpl = m.contract("E3RefundManager", [], {
    libraries: { RefundClaimLib: refundClaimLib },
  });

  const initData = m.encodeFunctionCall(e3RefundManagerImpl, "initialize", [
    owner,
    interfold,
    treasury,
  ]);

  const e3RefundManager = m.contract("TransparentUpgradeableProxy", [
    e3RefundManagerImpl,
    owner,
    initData,
  ]);

  return { e3RefundManager };
}) as any;
