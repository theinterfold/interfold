// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import {
  BFV_DKG_H,
  BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS,
  readVkRecursiveHash,
} from "../../scripts/utils";
import dkgAggregatorVerifierModule from "./dkgAggregatorVerifier";

export default buildModule("BfvPkVerifier", (m) => {
  const { dkgAggregatorVerifier } = m.useModule(dkgAggregatorVerifierModule);

  const nodesFoldKeyHash = readVkRecursiveHash(
    BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS.nodesFold,
  );
  const c5KeyHash = readVkRecursiveHash(BFV_PK_SUB_CIRCUIT_VK_HASH_PATHS.c5);

  const bfvPkVerifier = m.contract("BfvPkVerifier", [
    dkgAggregatorVerifier,
    nodesFoldKeyHash,
    c5KeyHash,
    BFV_DKG_H,
  ]);

  return { bfvPkVerifier };
}) as any;
