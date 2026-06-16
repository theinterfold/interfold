// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("BondingRegistry", (m) => {
  const ticketToken = m.getParameter("ticketToken");
  const licenseToken = m.getParameter("licenseToken");
  const registry = m.getParameter("registry");
  const slashedFundsTreasury = m.getParameter("slashedFundsTreasury");
  const ticketPrice = m.getParameter("ticketPrice");
  const licenseRequiredBond = m.getParameter("licenseRequiredBond");
  const minTicketBalance = m.getParameter("minTicketBalance");
  const exitDelay = m.getParameter("exitDelay");
  const owner = m.getParameter("owner");

  const bondingRegistryImpl = m.contract("BondingRegistry", []);

  const initData = m.encodeFunctionCall(bondingRegistryImpl, "initialize", [
    owner,
    ticketToken,
    licenseToken,
    registry,
    slashedFundsTreasury,
    ticketPrice,
    licenseRequiredBond,
    minTicketBalance,
    exitDelay,
  ]);

  const bondingRegistry = m.contract("TransparentUpgradeableProxy", [
    bondingRegistryImpl,
    owner,
    initData,
  ]);

  return { bondingRegistry };
}) as any;
