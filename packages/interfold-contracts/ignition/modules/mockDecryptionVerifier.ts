// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("MockDecryptionVerifier", (m) => {
  const mockDecryptionVerifier = m.contract("MockDecryptionVerifier");

  return { mockDecryptionVerifier };
}) as any;
