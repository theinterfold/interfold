// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("InterfoldToken", (m) => {
  const owner = m.getParameter("owner");
  const ccaStart = m.getParameter("ccaStart");
  const ccaEnd = m.getParameter("ccaEnd");
  const claimSource = m.getParameter("claimSource");
  const bondingRegistry = m.getParameter("bondingRegistry");
  const noMoreLocks = m.getParameter("noMoreLocks");

  const interfoldToken = m.contract("InterfoldToken", [
    owner,
    ccaStart,
    ccaEnd,
    noMoreLocks,
    claimSource,
    bondingRegistry,
  ]);

  return { interfoldToken };
}) as any;
