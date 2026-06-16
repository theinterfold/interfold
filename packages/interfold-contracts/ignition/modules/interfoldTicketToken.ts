// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("InterfoldTicketToken", (m) => {
  const baseToken = m.getParameter("baseToken");
  const registry = m.getParameter("registry");
  const owner = m.getParameter("owner");

  const interfoldTicketToken = m.contract("InterfoldTicketToken", [
    baseToken,
    registry,
    owner,
  ]);

  return { interfoldTicketToken };
}) as any;
