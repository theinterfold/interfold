// SPDX-License-Identifier: LGPL-3.0-only

/** Official Avail bridge and VectorX verifier addresses accepted by this release. */
export const AVAIL_VECTORX = {
  mainnet: {
    chainId: 1,
    bridge: "0x054fd961708d8e2b9c10a63f6157c74458889f0a",
    vectorx: "0x02993cdC11213985b9B13224f3aF289F03bf298d",
  },
  sepolia: {
    chainId: 11155111,
    bridge: "0x967F7DdC4ec508462231849AE81eeaa68Ad01389",
    vectorx: "0xe542db219a7e2b29c7aeaeace242c9a2cd528f96",
  },
} as const;

/** Time reserved between the last accepted input proof and the Ethereum input deadline. */
export const AVAIL_FINALIZATION_WINDOW_SECONDS = 10_800;

/** Voting time CRISP must leave after the worst-case committee setup. */
export const CRISP_MIN_VOTING_DURATION_SECONDS = 3_600;

export function availVectorXForChain(chainId: number) {
  const entry = Object.values(AVAIL_VECTORX).find(
    (candidate) => candidate.chainId === chainId,
  );
  if (!entry) {
    throw new Error(
      `Avail/VectorX data availability is not configured for chain ${chainId}`,
    );
  }
  return entry;
}
