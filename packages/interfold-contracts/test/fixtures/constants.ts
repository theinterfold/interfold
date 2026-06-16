// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Shared test constants. Importable by every spec file.
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
export const SORTITION_SUBMISSION_WINDOW = 10;

// ── Encryption scheme ───────────────────────────────────────────────────────
// Derived from the same string the BFV verifier wrappers and
// `MockE3Program` use (`keccak256("fhe.rs:BFV")`) so the test constant
// stays aligned with the contracts if either side ever changes.
export const ENCRYPTION_SCHEME_ID = ethers.id("fhe.rs:BFV");

// ── Fake ciphertext / proof payloads used across spec files ──────────────────
export const DATA = "0xda7a";
export const PROOF = "0x1337";

// ── BFV parameter sets (abi.encode(uint256 degree, uint256 modulus, uint256[] moduli)) ──
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

/** Small BFV params (degree 512). Used by `Interfold.spec` & `Pricing.spec`. */
export const BFV_PARAMS_DEFAULT = abiCoder.encode(
  ["uint256", "uint256", "uint256[]"],
  [
    ethers.toBigInt(512),
    ethers.toBigInt(10),
    [ethers.toBigInt("0xffffee001"), ethers.toBigInt("0xffffc4001")],
  ],
);

/** Production-sized BFV params (degree 2048). Used by `E3Integration.spec`. */
export const BFV_PARAMS_LARGE = abiCoder.encode(
  ["uint256", "uint256", "uint256[]"],
  [
    ethers.toBigInt(2048),
    ethers.toBigInt(1032193),
    [ethers.toBigInt("18014398492704769")],
  ],
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
/** N=19, T=9. */
export const COMMITTEE_SIZE_SMALL = 2;

/**
 * Default thresholds for {@link deployInterfoldSystem} when `committeeThresholds`
 * is not overridden: `[T, N]` (Shamir reconstruction threshold, committee size).
 *
 * Matches what {@link InterfoldPricing.quote} uses as `m` / `n` and what most
 * pricing / sortition / lifecycle specs assert against. **Not** the same as
 * {@link COMMITTEE_THRESHOLDS_ONCHAIN} (production deploy uses `[H, N]`).
 */
export const COMMITTEE_THRESHOLDS_DEFAULT: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [
  [COMMITTEE_SIZE_MINIMUM, [1, 3]],
  [COMMITTEE_SIZE_MICRO, [4, 9]],
  [COMMITTEE_SIZE_SMALL, [9, 19]],
];

/**
 * Production `setCommitteeThresholds` values from `scripts/deployInterfold.ts`:
 * `[H, N]` (minimum honest roster, committee size). On-chain `threshold[0]`
 * is registry viability **M** (`activeCount >= M`); production sets M = H.
 *
 * Pass via `deployInterfoldSystem({ committeeThresholds: [...] })` when a
 * spec exercises post-expulsion viability with production semantics.
 */
export const COMMITTEE_THRESHOLDS_ONCHAIN: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [
  [COMMITTEE_SIZE_MINIMUM, [2, 3]],
  [COMMITTEE_SIZE_MICRO, [5, 9]],
  [COMMITTEE_SIZE_SMALL, [10, 19]],
];

/**
 * Slashing expulsion harness: low M with small N so specs can reach / breach
 * viability without a full Micro/Small committee. Micro uses N=4 (not 9).
 * CommitteeSize `3` and above stay unconfigured for negative-path tests.
 */
export const COMMITTEE_THRESHOLDS_FAULT_TOLERANCE: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [
  [COMMITTEE_SIZE_MINIMUM, [2, 3]],
  [COMMITTEE_SIZE_MICRO, [2, 4]],
  [COMMITTEE_SIZE_SMALL, [9, 19]],
];

/** Single-size fixture used by sortition / pricing smoke tests. */
export const COMMITTEE_THRESHOLDS_MINIMUM_ONLY: ReadonlyArray<
  readonly [number, readonly [number, number]]
> = [[COMMITTEE_SIZE_MINIMUM, [1, 3]]];

// ── Bonding defaults (passed to BondingRegistry constructor) ─────────────────
/** 10 USDC ticket price (6-decimal stable). */
export const TICKET_PRICE = ethers.parseUnits("10", 6);
/** 1000 license tokens (18-decimal) per active operator. */
export const LICENSE_REQUIRED_BOND = ethers.parseEther("1000");
/** Minimum ticket balance (in ticket units, not USDC). */
export const MIN_TICKET_BALANCE = 5;
