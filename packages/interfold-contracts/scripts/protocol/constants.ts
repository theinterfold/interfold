// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

export const ZERO = ethersLib.ZeroAddress;
export const ADDRESS_ONE = "0x0000000000000000000000000000000000000001";
export const LEGACY_MAINNET_SECURE_PARAM_SET_HASH =
  "0xd7068fdcc1910f5e49c8b05530cf74f876cadee2a1caf797a40b1ae53ae143ec";

export const abi = ethersLib.AbiCoder.defaultAbiCoder();

export const proxyAdminInterface = new ethersLib.Interface([
  "function owner() view returns (address)",
  "function upgradeAndCall(address proxy,address implementation,bytes data) payable",
]);

export const BFV_PARAMS = {
  insecure512: {
    degree: 512n,
    plaintextModulus: 100n,
    moduli: [0xffffee001n, 0xffffc4001n],
    error1Variance: "3",
  },
  secure8192: {
    degree: 8192n,
    plaintextModulus: 1000000n,
    moduli: [0x0400000000c00001n, 0x0400000000a40001n, 0x0400000000990001n],
    error1Variance: "17723039943798878305460955570711717478400",
  },
} as const;
