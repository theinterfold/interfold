// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Shared attestation helpers for committee-based slashing tests.
import type { Signer, TypedDataDomain } from "ethers";

import { ethers } from "./connection";

const abiCoder = ethers.AbiCoder.defaultAbiCoder();

// EIP-712 type string for AccusationVote. Mirrors VOTE_TYPEHASH constant in
// SlashingManager.sol. The struct intentionally omits `chainId` and
// `verifyingContract` — those are bound via the EIP-712 domain separator (H-10).
// `agrees` was dropped (sig-L): every signature now implicitly asserts agreement
// and the contract enforces witness equality across all voters via `dataHash`.
export const VOTE_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "AccusationVote(uint256 e3Id,bytes32 accusationId,address voter,bytes32 dataHash,uint256 issuedAt,uint256 deadline)",
  ),
);

/**
 * Helper to create signed committee attestation evidence for Lane A.
 *
 * Returns `abi.encode(uint256 proofType, uint256 proofInstance, address[] voters, bytes32[] dataHashes,
 *                     bytes evidence, uint256 issuedAt, uint256 deadline,
 *                     bytes[] signatures)` with
 * voters sorted ascending by address.
 *
 * Each voter signs the EIP-712 `AccusationVote` struct against the
 * `InterfoldSlashing/1` domain anchored at `verifyingContract`. This binds the
 * attestation to a specific SlashingManager deployment on a specific chain,
 * eliminating the cross-chain / cross-contract replay class (H-10, M-24).
 *
 * @param voterSigners - Committee members signing the accusation.
 * @param e3Id         - The E3 the accusation targets.
 * @param operator     - The accused operator address.
 * @param verifyingContract - Address of the SlashingManager (EIP-712 domain).
 * @param proofType    - Numeric proof type, mapped to a slash reason on-chain.
 * @param chainId      - Chain ID for the EIP-712 domain. Defaults to 31337 (hardhat).
 * @param evidence     - Evidence preimage bytes. All voters sign
 *                       `keccak256(evidence)` as `dataHash`.
 * @param deadline     - Optional unix expiry. Defaults to 30 minutes after issue.
 * @param dataHashOverride - Optional negative-test override for signed `dataHash`.
 * @param issuedAt     - Optional signature issue time. Defaults to the latest block.
 */
export async function signAndEncodeAttestation(
  voterSigners: Signer[],
  e3Id: number | bigint,
  operator: string,
  verifyingContract: string,
  proofType: number = 0,
  chainId: number = 31337,
  evidence: string = ethers.hexlify(ethers.toUtf8Bytes("lane-a-attestation")),
  deadline?: bigint,
  dataHashOverride?: string,
  issuedAt?: bigint,
  proofInstance: number = 0,
): Promise<string> {
  const latestBlock = await ethers.provider.getBlock("latest");
  const effectiveIssuedAt =
    issuedAt ?? BigInt(latestBlock?.timestamp ?? Math.floor(Date.now() / 1000));
  const effectiveDeadline = deadline ?? effectiveIssuedAt + 30n * 60n;
  const accusationId = ethers.keccak256(
    proofInstance === 0
      ? ethers.solidityPacked(
          ["uint256", "uint256", "address", "uint256"],
          [chainId, e3Id, operator, proofType],
        )
      : ethers.solidityPacked(
          ["uint256", "uint256", "address", "uint256", "uint256"],
          [chainId, e3Id, operator, proofType, proofInstance],
        ),
  );

  const domain: TypedDataDomain = {
    name: "InterfoldSlashing",
    version: "1",
    chainId,
    verifyingContract,
  };

  const types = {
    AccusationVote: [
      { name: "e3Id", type: "uint256" },
      { name: "accusationId", type: "bytes32" },
      { name: "voter", type: "address" },
      { name: "dataHash", type: "bytes32" },
      { name: "issuedAt", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  } as const;

  const signersWithAddrs = await Promise.all(
    voterSigners.map(async (s) => ({
      signer: s,
      address: await s.getAddress(),
    })),
  );
  signersWithAddrs.sort((a, b) =>
    a.address.toLowerCase() < b.address.toLowerCase()
      ? -1
      : a.address.toLowerCase() > b.address.toLowerCase()
        ? 1
        : 0,
  );

  const voters: string[] = [];
  const dataHashes: string[] = [];
  const signatures: string[] = [];
  const dataHash = dataHashOverride ?? ethers.keccak256(evidence);

  for (const { signer, address: voterAddress } of signersWithAddrs) {
    voters.push(voterAddress);
    dataHashes.push(dataHash);

    const value = {
      e3Id,
      accusationId,
      voter: voterAddress,
      dataHash,
      issuedAt: effectiveIssuedAt,
      deadline: effectiveDeadline,
    };

    const signature = await (
      signer as Signer & {
        signTypedData: (
          d: TypedDataDomain,
          t: typeof types,
          v: typeof value,
        ) => Promise<string>;
      }
    ).signTypedData(domain, types, value);
    signatures.push(signature);
  }

  // Silence unused-import lint when abiCoder is the only escape hatch consumers
  // may want for non-EIP-712 negative tests. (Kept for future negative cases.)
  void abiCoder;

  return ethers.AbiCoder.defaultAbiCoder().encode(
    [
      "uint256",
      "uint256",
      "address[]",
      "bytes32[]",
      "bytes",
      "uint256",
      "uint256",
      "bytes[]",
    ],
    [
      proofType,
      proofInstance,
      voters,
      dataHashes,
      evidence,
      effectiveIssuedAt,
      effectiveDeadline,
      signatures,
    ],
  );
}
