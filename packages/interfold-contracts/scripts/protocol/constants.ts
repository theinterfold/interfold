// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { BFV_PRESETS } from "../../bfv.js";

export const ZERO = ethersLib.ZeroAddress;
export const ADDRESS_ONE = "0x0000000000000000000000000000000000000001";

export const abi = ethersLib.AbiCoder.defaultAbiCoder();

export const proxyAdminInterface = new ethersLib.Interface([
  "function owner() view returns (address)",
  "function upgradeAndCall(address proxy,address implementation,bytes data) payable",
]);

export const BFV_PARAMS = {
  // Parameter set 4: insecure trBFV at degree 64.
  insecure64: BFV_PRESETS["insecure-64"].threshold,
  // Parameter set 6: insecure l-BFV at degree 128.
  insecureLbfv: BFV_PRESETS["insecure-lbfv"].threshold,
  secure8192: BFV_PRESETS["secure-8192"].threshold,
  secure16384: BFV_PRESETS["secure-16384"].threshold,
} as const;
