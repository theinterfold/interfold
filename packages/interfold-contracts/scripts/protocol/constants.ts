// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

export const ZERO = ethersLib.ZeroAddress;
export const ADDRESS_ONE = "0x0000000000000000000000000000000000000001";

export const abi = ethersLib.AbiCoder.defaultAbiCoder();

export const proxyAdminInterface = new ethersLib.Interface([
  "function owner() view returns (address)",
  "function upgradeAndCall(address proxy,address implementation,bytes data) payable",
]);

export const BFV_PARAMS = {
  insecure64: {
    degree: 64n,
    plaintextModulus: 17000000n,
    moduli: [0x0000000007fffd81n, 0x0000000007fff801n, 0x0000000007fff781n],
    error1Variance: "12617929386",
  },
  secure8192: {
    degree: 8192n,
    plaintextModulus: 17000000n,
    moduli: [0x0800000000db4001n, 0x0800000000d54001n, 0x0800000000cbc001n],
    error1Variance: "17723039943798878305460955570711717478400",
  },
} as const;
