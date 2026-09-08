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
import { ACTIVE_CRYPTO_CONFIG_ID, COMMITTEE_SIZE_MINIMUM } from "./constants";
import { buildMockDkgAttestationFixtureData } from "./dkgAttestation";

const { time } = networkHelpers;
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

export type E3RequestInput = Omit<
  IInterfold.E3RequestParamsStruct,
  "expectedFeeToken" | "expectedCryptoConfigId" | "maxFee"
>;

/** Deploy a SlashingManager with its external evidence verifier linked. */
export const deploySlashingManager = async (
  initialDelay: number | bigint,
  admin: string,
) => {
  const evidenceLib = await ethers.deployContract("SlashingEvidenceLib");
  await evidenceLib.waitForDeployment();
  const factory = await ethers.getContractFactory("SlashingManager", {
    libraries: { SlashingEvidenceLib: await evidenceLib.getAddress() },
  });
  const manager = await factory.deploy(initialDelay, admin);
  await manager.waitForDeployment();
  return manager;
};

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
  e3Id: number | bigint,
  publicKey: string,
  operators: Signer[],
  committeeProof: string = "0x",
  dkgAttestationBundle: string = "0x",
): Promise<void> => {
  await time.increase(1);
  for (const operator of operators) {
    await registry.connect(operator).submitTicket(e3Id, 1);
  }
  const deadline = await registry.getCommitteeDeadline(e3Id);
  await time.setNextBlockTimestamp(deadline + 1n);
  await registry.finalizeCommittee(e3Id);
  const pkCommitment = ethers.keccak256(publicKey);
  if (committeeProof === "0x" && dkgAttestationBundle === "0x") {
    let verifierAddress = await registry.dkgFoldAttestationVerifier();
    if (verifierAddress === ethers.ZeroAddress) {
      const verifier = await ethers.deployContract(
        "DkgFoldAttestationVerifier",
      );
      await verifier.waitForDeployment();
      verifierAddress = await verifier.getAddress();
      await registry.setInitialDkgFoldAttestationVerifier(verifierAddress);
    }
    const fixture = await buildMockDkgAttestationFixtureData(
      operators,
      e3Id,
      pkCommitment,
      verifierAddress,
      await registry.getAddress(),
    );
    committeeProof = fixture.proof;
    dkgAttestationBundle = fixture.bundle;
  }
  await registry.publishCommittee(
    e3Id,
    pkCommitment,
    committeeProof,
    dkgAttestationBundle,
  );
  const publicKeyBytes = ethers.getBytes(publicKey);
  await registry
    .connect(operators[0])
    .publishCommitteePublicKey(
      e3Id,
      ethers.keccak256(publicKey),
      0,
      1,
      publicKeyBytes.length,
      publicKeyBytes,
    );
};

/** Build the reference payload accepted by the protocol's DA-only output path. */
export const ciphertextOutputReference = (
  ciphertextOutput: string,
  ciphertextCommitment: string,
  computeProof: string,
) => ({
  contentHash: ethers.keccak256(ciphertextOutput),
  ciphertextCommitment,
  computeProof,
  // MockE3ProgramHarness treats the raw object as its deterministic local receipt.
  availabilityProof: ciphertextOutput,
});

/** Publish a test ciphertext through the deterministic local DA verifier. */
export const publishAvailableCiphertextOutput = (
  interfold: Interfold,
  e3Id: number | bigint,
  ciphertextOutput: string,
  ciphertextCommitment: string,
  computeProof: string,
) =>
  interfold.publishCiphertextOutput(
    e3Id,
    abiCoder.encode(
      [
        "tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes computeProof,bytes availabilityProof)",
      ],
      [
        ciphertextOutputReference(
          ciphertextOutput,
          ciphertextCommitment,
          computeProof,
        ),
      ],
    ),
  );

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
  requestParams: E3RequestInput,
  signer?: Signer,
): Promise<ContractTransactionResponse> => {
  const tokenContract = signer ? usdcToken.connect(signer) : usdcToken;
  const interfoldContract = signer ? interfold.connect(signer) : interfold;
  const quoteParams = {
    ...requestParams,
    expectedFeeToken: await usdcToken.getAddress(),
    expectedCryptoConfigId: ACTIVE_CRYPTO_CONFIG_ID,
    maxFee: 0,
  };
  const fee = await interfold.getE3Quote(quoteParams);

  await tokenContract.approve(await interfold.getAddress(), fee);
  return interfoldContract.request({ ...quoteParams, maxFee: fee });
};

/** Options for {@link buildRequestParams}. */
export interface BuildRequestParamsOptions {
  /** `CommitteeSize` enum value. Defaults to {@link COMMITTEE_SIZE_MINIMUM}. */
  committeeSize?: number;
  /** Seconds added to `time.latest()` for `inputWindow[0]`. Defaults to `10`. */
  startOffset?: number;
  /** `inputWindow[1] - time.latest()`. Defaults to `300` (5 minutes). */
  windowDuration?: number;
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
): Promise<E3RequestInput> => {
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
  };
};
