// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import {
  BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS,
  BFV_THRESHOLD_T,
  readVkRecursiveHash,
} from "../../scripts/utils";
import decryptionAggregatorVerifierModule from "./decryptionAggregatorVerifier";

export default buildModule("BfvDecryptionVerifier", (m) => {
  const { decryptionAggregatorVerifier } = m.useModule(
    decryptionAggregatorVerifierModule,
  );

  const c6FoldKeyHash = readVkRecursiveHash(
    BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS.c6Fold,
  );
  const c7KeyHash = readVkRecursiveHash(
    BFV_DECRYPTION_SUB_CIRCUIT_VK_HASH_PATHS.c7,
  );

  const bfvDecryptionVerifier = m.contract("BfvDecryptionVerifier", [
    decryptionAggregatorVerifier,
    c6FoldKeyHash,
    c7KeyHash,
    BFV_THRESHOLD_T,
  ]);

  return { bfvDecryptionVerifier };
}) as any;
