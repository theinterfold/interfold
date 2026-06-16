// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("DecryptionAggregatorVerifier", (m) => {
  const decryptionAggregatorVerifier = m.contract(
    "DecryptionAggregatorVerifier",
  );

  return { decryptionAggregatorVerifier };
}) as any;
