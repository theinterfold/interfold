// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import { BFV_DKG_H, getBfvVkCommitments } from "../../scripts/utils";
import dkgAggregatorVerifierModule from "./dkgAggregatorVerifier";

export default buildModule("BfvPkVerifier", (m) => {
  const { dkgAggregatorVerifier } = m.useModule(dkgAggregatorVerifierModule);

  const { nodesFold: nodesFoldKeyHash, c5: c5KeyHash } = getBfvVkCommitments();

  // `BfvPkVerifier` serves the trBFV path, which always pins the nodes-fold tree and C5.
  const bfvPkVerifier = m.contract("BfvPkVerifier", [
    dkgAggregatorVerifier,
    nodesFoldKeyHash!,
    c5KeyHash!,
    BFV_DKG_H,
  ]);

  return { bfvPkVerifier };
}) as any;
