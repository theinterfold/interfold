// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import { BFV_THRESHOLD_T, getBfvVkCommitments } from "../../scripts/utils";
import decryptionAggregatorVerifierModule from "./decryptionAggregatorVerifier";

export default buildModule("BfvDecryptionVerifier", (m) => {
  const registry = m.getParameter("registry");
  const { decryptionAggregatorVerifier } = m.useModule(
    decryptionAggregatorVerifierModule,
  );

  const { c6Fold: c6FoldKeyHash, c7: c7KeyHash } = getBfvVkCommitments();

  const bfvDecryptionVerifier = m.contract("BfvDecryptionVerifier", [
    decryptionAggregatorVerifier,
    registry,
    c6FoldKeyHash,
    c7KeyHash,
    BFV_THRESHOLD_T,
  ]);

  return { bfvDecryptionVerifier };
}) as any;
