// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import {
  ACTIVE_BFV_PARAM_SET,
  BFV_THRESHOLD_T,
  bfvMessageCoeffsCount,
  getBfvDecryptionSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../../scripts/utils";
import decryptionAggregatorVerifierModule from "./decryptionAggregatorVerifier";

export default buildModule("BfvDecryptionVerifier", (m) => {
  const registry = m.getParameter("registry");
  const { decryptionAggregatorVerifier } = m.useModule(
    decryptionAggregatorVerifierModule,
  );

  const c6FoldKeyHash = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths().c6Fold,
  );
  const c7KeyHash = readVkRecursiveHash(
    getBfvDecryptionSubCircuitVkHashPaths().c7,
  );

  const bfvDecryptionVerifier = m.contract("BfvDecryptionVerifier", [
    decryptionAggregatorVerifier,
    registry,
    c6FoldKeyHash,
    c7KeyHash,
    BFV_THRESHOLD_T,
    bfvMessageCoeffsCount(ACTIVE_BFV_PARAM_SET),
  ]);

  return { bfvDecryptionVerifier };
}) as any;
