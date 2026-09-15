// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import {
  getBfvPkSubCircuitVkHashPaths,
  getBfvPkVkBindingHashPaths,
  getBfvV2SubCircuitVkHashPaths,
  getBfvV2VkBindingHashPaths,
  readVkRecursiveHash,
} from "../../scripts/utils";
import dkgAggregatorV2VerifierModule from "./dkgAggregatorV2Verifier";

export default buildModule("BfvPkVerifierV2", (m) => {
  const registry = m.getParameter("registry");
  const { dkgAggregatorV2Verifier } = m.useModule(
    dkgAggregatorV2VerifierModule,
  );
  const pkPaths = getBfvPkSubCircuitVkHashPaths();

  const bfvPkVerifierV2 = m.contract("BfvPkVerifierV2", [
    dkgAggregatorV2Verifier,
    registry,
    readVkRecursiveHash(getBfvV2SubCircuitVkHashPaths().nodesFold),
    readVkRecursiveHash(pkPaths.c5),
    readVkRecursiveHash(pkPaths.skC2Chunk),
    readVkRecursiveHash(pkPaths.esmC2Chunk),
    getBfvPkVkBindingHashPaths().map((filePath) =>
      readVkRecursiveHash(filePath),
    ),
    getBfvV2VkBindingHashPaths().map((filePath) =>
      readVkRecursiveHash(filePath),
    ),
  ]);

  return { bfvPkVerifierV2 };
}) as any;
