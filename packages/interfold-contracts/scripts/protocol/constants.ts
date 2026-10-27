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
  insecure64: BFV_PRESETS["insecure-64"].threshold,
  secure8192: BFV_PRESETS["secure-8192"].threshold,
} as const;
