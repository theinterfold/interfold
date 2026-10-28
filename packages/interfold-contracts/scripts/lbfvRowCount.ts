// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import {
  INSECURE_LBFV_PARAM_SET,
  INSECURE_SIMD_PARAM_SET,
  SECURE_16384_SIMD_D6_PARAM_SET,
  SECURE_16384_SIMD_PARAM_SET,
} from "./utils";

/** On-chain index of the secure-16384 parameters (l-BFV path). */
const SECURE_16384_PARAM_SET = 3;

/** Row counts compiled into the supported l-BFV parameter sets. */
export const INSECURE_LBFV_ROWS = 3;
export const SECURE_16384_LBFV_ROWS = 5;
export const SECURE_16384_SIMD_D6_LBFV_ROWS = 8;

/** Every l-BFV row count some supported parameter set compiles. */
export const SUPPORTED_LBFV_ROW_COUNTS = [
  INSECURE_LBFV_ROWS,
  SECURE_16384_LBFV_ROWS,
  SECURE_16384_SIMD_D6_LBFV_ROWS,
] as const;

/**
 * Number of l-BFV rows compiled for `paramSet`: the single script-side owner, mirroring
 * `LbfvRowCount.rowCount` in `contracts/lib/LbfvRowCount.sol` and `lbfv_row_count` in
 * `crates/fhe-params/src/lbfv.rs`. Returns 0 for parameter sets that are not on the l-BFV path
 * (the trBFV sets), exactly like the contract.
 */
export function lbfvRowCount(paramSet: number): number {
  switch (paramSet) {
    case SECURE_16384_SIMD_D6_PARAM_SET:
      return SECURE_16384_SIMD_D6_LBFV_ROWS;
    case SECURE_16384_PARAM_SET:
    case SECURE_16384_SIMD_PARAM_SET:
      return SECURE_16384_LBFV_ROWS;
    case INSECURE_LBFV_PARAM_SET:
    case INSECURE_SIMD_PARAM_SET:
      return INSECURE_LBFV_ROWS;
    default:
      return 0;
  }
}
