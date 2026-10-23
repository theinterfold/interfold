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
  // The insecure degree-128 parameters of the l-BFV path: on-chain parameter set 4.
  insecure: {
    degree: 128n,
    plaintextModulus: 100n,
    moduli: [0x00ffffffffffc601n, 0x00ffffffffffc301n, 0x00ffffffffffa501n],
    error1Variance: "50471587840",
  },
  // The insecure ciphertext moduli with a SIMD plaintext modulus (prime, 1 mod 2N): on-chain
  // parameter set 5.
  insecureSimd: {
    degree: 128n,
    plaintextModulus: 257n,
    moduli: [0x00ffffffffffc601n, 0x00ffffffffffc301n, 0x00ffffffffffa501n],
    error1Variance: "50471587840",
  },
  secure8192: {
    degree: 8192n,
    plaintextModulus: 17000000n,
    moduli: [0x0800000000db4001n, 0x0800000000d54001n, 0x0800000000cbc001n],
    error1Variance: "17723039943798878305460955570711717478400",
  },
  secure16384: {
    degree: 16384n,
    plaintextModulus: 1000n,
    moduli: [
      0x00040000009f0001n,
      0x00040000008a0001n,
      0x0004000000800001n,
      0x00040000007e0001n,
      0x0004000000750001n,
    ],
    error1Variance: "264093875047547791978479834453333",
  },
} as const;

/**
 * The BFV parameters registered under an on-chain parameter set. Set 0 is insecure-64 (trBFV) and
 * set 4 is the insecure degree-128 set of the l-BFV path.
 */
export function bfvParamsForParamSet(
  paramSet: number,
): (typeof BFV_PARAMS)[keyof typeof BFV_PARAMS] {
  switch (paramSet) {
    case 0:
      return BFV_PARAMS.insecure64;
    case 4:
      return BFV_PARAMS.insecure;
    case 2:
      return BFV_PARAMS.secure8192;
    case 3:
      return BFV_PARAMS.secure16384;
    case 5:
      return BFV_PARAMS.insecureSimd;
    default:
      throw new Error(`Unsupported BFV parameter set: ${paramSet}`);
  }
}
