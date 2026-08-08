// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import {
  BFV_DKG_H,
  getBfvPkSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../../scripts/utils";
import dkgAggregatorVerifierModule from "./dkgAggregatorVerifier";

export default buildModule("BfvPkVerifier", (m) => {
  const { dkgAggregatorVerifier } = m.useModule(dkgAggregatorVerifierModule);

  const nodesFoldKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().nodesFold,
  );
  const c5KeyHash = readVkRecursiveHash(getBfvPkSubCircuitVkHashPaths().c5);
  const skC2ChunkKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().skC2Chunk,
  );
  const esmC2ChunkKeyHash = readVkRecursiveHash(
    getBfvPkSubCircuitVkHashPaths().esmC2Chunk,
  );

  const bfvPkVerifier = m.contract("BfvPkVerifier", [
    dkgAggregatorVerifier,
    nodesFoldKeyHash,
    c5KeyHash,
    skC2ChunkKeyHash,
    esmC2ChunkKeyHash,
    BFV_DKG_H,
  ]);

  return { bfvPkVerifier };
}) as any;
