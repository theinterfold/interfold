// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

// Default 2-day delay for the DEFAULT_ADMIN_ROLE two-step handover (M-17).
const DEFAULT_ADMIN_DELAY = 60 * 60 * 24 * 2;

export default buildModule("SlashingManager", (m) => {
  const admin = m.getParameter("admin");
  // WARNING: overriding initialDelay to 0 collapses the two-step DEFAULT_ADMIN
  // handover into a single transaction, removing the timelock protection (M-17).
  // Always use a non-zero value in production deployments.
  const initialDelay = m.getParameter("initialDelay", DEFAULT_ADMIN_DELAY);

  const slashingManager = m.contract("SlashingManager", [initialDelay, admin]);

  return { slashingManager };
}) as any;
