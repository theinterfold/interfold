// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Shared test constants. Importable by every spec file.
import { BFV_PARAMS } from "../../scripts/protocol/constants";
import { ethers } from "./connection";

// ── Addresses ────────────────────────────────────────────────────────────────
export const ADDRESS_ONE = "0x0000000000000000000000000000000000000001";
export const ADDRESS_TWO = "0x0000000000000000000000000000000000000002";

// ── Time ─────────────────────────────────────────────────────────────────────
export const ONE_HOUR = 60 * 60;
export const ONE_DAY = 24 * ONE_HOUR;
export const THREE_DAYS = 3 * ONE_DAY;
export const SEVEN_DAYS = 7 * ONE_DAY;
export const THIRTY_DAYS = 30 * ONE_DAY;

// ── Sortition ────────────────────────────────────────────────────────────────
export const SORTITION_SUBMISSION_WINDOW = 60;

// ── Encryption scheme ───────────────────────────────────────────────────────
// Derived from the same string the BFV verifier wrappers and
// `MockE3Program` use (`keccak256("fhe.rs:BFV")`) so the test constant
// stays aligned with the contracts if either side ever changes.
export const ENCRYPTION_SCHEME_ID = ethers.id("fhe.rs:BFV");

// ── Fake ciphertext / proof payloads used across spec files ──────────────────
export const DATA = "0xda7a";
export const PROOF = "0x1337";

// ── Active BFV parameter set ────────────────────────────────────────────────
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

function encodeBfvParams(params: {
  degree: bigint;
  plaintextModulus: bigint;
  moduli: readonly bigint[];
  error1Variance: string;
}): string {
  return abiCoder.encode(
    [
      "tuple(uint256 degree,uint256 plaintext_modulus,uint256[] moduli,string error1_variance)",
    ],
    [
      [
        params.degree,
        params.plaintextModulus,
        [...params.moduli],
        params.error1Variance,
      ],
    ],
  );
}

/** The insecure-512 parameter set compiled into the active test circuits. */
export const BFV_PARAMS_DEFAULT = encodeBfvParams(BFV_PARAMS.insecure512);

/** The secure-8192 parameter set that Sepolia/local deployments can also register. */
export const BFV_PARAMS_SECURE = encodeBfvParams(BFV_PARAMS.secure8192);

/** Circuit, BFV parameters, and verifier generation used by this build. */
export const ACTIVE_CRYPTO_CONFIG_ID = ethers.keccak256(
  abiCoder.encode(
    ["bytes32", "bytes32", "bytes32"],
    [
      ENCRYPTION_SCHEME_ID,
      ethers.keccak256(BFV_PARAMS_DEFAULT),
      ethers.id("interfold-bfv-v1"),
    ],
  ),
);

/** Production default circuit configuration exposed by `activeCryptoConfigId()`. */
export const PRODUCTION_CRYPTO_CONFIG_ID = ethers.keccak256(
  abiCoder.encode(
    ["bytes32", "bytes32", "bytes32"],
    [
      ENCRYPTION_SCHEME_ID,
      ethers.keccak256(BFV_PARAMS_SECURE),
      ethers.id("interfold-bfv-v1"),
    ],
  ),
);

// ── Timeout configs ──────────────────────────────────────────────────────────
/** 1h / 1h / 1h — used by short-lifecycle tests. */
export const DEFAULT_TIMEOUT_CONFIG = {
  dkgWindow: ONE_HOUR,
  computeWindow: ONE_HOUR,
  decryptionWindow: ONE_HOUR,
};

/** 1d / 3d / 1d — used by long-lifecycle integration tests. */
export const LARGE_TIMEOUT_CONFIG = {
  dkgWindow: ONE_DAY,
  computeWindow: THREE_DAYS,
  decryptionWindow: ONE_DAY,
};

// ── Committee sizes (matches `IInterfold.CommitteeSize`) ─────────────────────
/** N=3, T=1 — default CI / dev committee. */
export const COMMITTEE_SIZE_MINIMUM = 0;
/** N=9, T=4. */
export const COMMITTEE_SIZE_MICRO = 1;
/** N=19, T=9, H=14. */
export const COMMITTEE_SIZE_SMALL = 2;

/**
 * Canonical on-chain thresholds: `[H, N]` (required honest roster and committee
 * size). Pricing resolves the matching circuit threshold `T` from the same
 * committee-size enum.
 */
export const COMMITTEE_THRESHOLDS_DEFAULT: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [[COMMITTEE_SIZE_MINIMUM, [2, 3]]];

/**
 * Production `setCommitteeThresholds` values from `scripts/deployInterfold.ts`:
 * `[H, N]` (minimum honest roster, committee size). On-chain `threshold[0]`
 * is the registry viability threshold H (`activeCount >= H`).
 *
 * Pass via `deployInterfoldSystem({ committeeThresholds: [...] })` when a
 * spec exercises post-expulsion viability with production semantics.
 */
export const COMMITTEE_THRESHOLDS_ONCHAIN: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [
  [COMMITTEE_SIZE_MINIMUM, [2, 3]],
  [COMMITTEE_SIZE_MICRO, [5, 9]],
  [COMMITTEE_SIZE_SMALL, [14, 19]],
];

/** Single-size fixture used by sortition / pricing smoke tests. */
export const COMMITTEE_THRESHOLDS_MINIMUM_ONLY: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [[COMMITTEE_SIZE_MINIMUM, [2, 3]]];

// ── Bonding defaults (passed to BondingRegistry constructor) ─────────────────
/** 10 USDC ticket price (6-decimal stable). */
export const TICKET_PRICE = ethers.parseUnits("10", 6);
/** 1000 ciphernode bond tokens (18-decimal) per active operator. */
export const REQUIRED_CIPHERNODE_BOND = ethers.parseEther("1000");
/** Minimum ticket balance (in ticket units, not USDC). */
export const MIN_TICKET_BALANCE = 5;
