// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Pure helpers (no deploys). Compose with `deployInterfoldSystem`.
import type { ContractTransactionResponse, Signer } from "ethers";

import type { IInterfold, Interfold } from "../../types/contracts/Interfold";
import type { MockUSDC } from "../../types/contracts/test/MockStableToken.sol/MockUSDC";
import { ethers, networkHelpers } from "./connection";
import {
  COMMITTEE_SIZE_MINIMUM,
  SORTITION_SUBMISSION_WINDOW,
} from "./constants";

const { time } = networkHelpers;
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

/**
 * Build ABI-encoded fake DKG proof bytes accepted by `MockPkVerifier`.
 * The last public input must equal `pkCommitment`.
 */
export const encodeMockDkgProof = (pkCommitment: string): string =>
  abiCoder.encode(["bytes", "bytes32[]"], ["0x", [pkCommitment]]);

/**
 * Run the full committee submission → finalisation → publication flow for an
 * E3. Operators each submit one ticket, time advances past the submission
 * window, the committee is finalised, then the public key is published.
 *
 * @param registry        CiphernodeRegistryOwnable instance.
 * @param e3Id            Target E3 id.
 * @param nodes           Pre-resolved node addresses (sorted as caller wants).
 * @param publicKey       Bytes published as the committee public key.
 * @param operators       Signers who submit tickets (typically === nodes).
 * @param committeeProof  Bytes passed to `publishCommittee` (default "0x").
 */
export const setupAndPublishCommittee = async (
  registry: any,
  e3Id: number,
  publicKey: string,
  operators: Signer[],
  committeeProof: string = "0x",
  dkgAttestationBundle: string = "0x",
): Promise<void> => {
  for (const operator of operators) {
    await registry.connect(operator).submitTicket(e3Id, 1);
  }
  await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
  await registry.finalizeCommittee(e3Id);
  const pkCommitment = ethers.keccak256(publicKey);
  await registry.publishCommittee(
    e3Id,
    publicKey,
    pkCommitment,
    committeeProof,
    dkgAttestationBundle,
  );
};

/**
 * Approve USDC for the quoted fee and submit an E3 request.
 *
 * @param interfold       Interfold instance.
 * @param usdcToken     MockUSDC instance funding the request.
 * @param requestParams Struct passed to `interfold.request`.
 * @param signer        Optional non-default signer; defaults to the contracts'
 *                      currently-bound runner.
 */
export const makeRequest = async (
  interfold: Interfold,
  usdcToken: MockUSDC,
  requestParams: IInterfold.E3RequestParamsStruct,
  signer?: Signer,
): Promise<ContractTransactionResponse> => {
  const fee = await interfold.getE3Quote(requestParams);
  const tokenContract = signer ? usdcToken.connect(signer) : usdcToken;
  const interfoldContract = signer ? interfold.connect(signer) : interfold;

  await tokenContract.approve(await interfold.getAddress(), fee);
  return interfoldContract.request(requestParams);
};

/** Options for {@link buildRequestParams}. */
export interface BuildRequestParamsOptions {
  /** `CommitteeSize` enum value. Defaults to {@link COMMITTEE_SIZE_MINIMUM}. */
  committeeSize?: number;
  /** Seconds added to `time.latest()` for `inputWindow[0]`. Defaults to `10`. */
  startOffset?: number;
  /** `inputWindow[1] - time.latest()`. Defaults to `300` (5 minutes). */
  windowDuration?: number;
  /** Defaults to `false`. */
  proofAggregationEnabled?: boolean;
  /** Override custom params bytes. Defaults to an ABI-encoded throwaway address. */
  customParams?: string;
  /** Param-set id registered on the Interfold. Defaults to `0`. */
  paramSet?: number;
}

/**
 * Build a fresh `Interfold.request(...)` struct anchored at the current block
 * timestamp. Useful when a test needs a second request after `time.increase`.
 */
export const buildRequestParams = async (
  e3Program: { getAddress: () => Promise<string> } | string,
  decryptionVerifier: { getAddress: () => Promise<string> } | string,
  opts: BuildRequestParamsOptions = {},
): Promise<IInterfold.E3RequestParamsStruct> => {
  const now = await time.latest();
  const startOffset = opts.startOffset ?? 10;
  const windowDuration = opts.windowDuration ?? 300;
  const e3ProgramAddr =
    typeof e3Program === "string" ? e3Program : await e3Program.getAddress();
  const decryptionVerifierAddr =
    typeof decryptionVerifier === "string"
      ? decryptionVerifier
      : await decryptionVerifier.getAddress();
  return {
    committeeSize: opts.committeeSize ?? COMMITTEE_SIZE_MINIMUM,
    inputWindow: [now + startOffset, now + windowDuration] as [number, number],
    e3Program: e3ProgramAddr,
    paramSet: opts.paramSet ?? 0,
    computeProviderParams: abiCoder.encode(
      ["address"],
      [decryptionVerifierAddr],
    ),
    customParams:
      opts.customParams ??
      abiCoder.encode(
        ["address"],
        ["0x1234567890123456789012345678901234567890"],
      ),
    proofAggregationEnabled: opts.proofAggregationEnabled ?? false,
  };
};
