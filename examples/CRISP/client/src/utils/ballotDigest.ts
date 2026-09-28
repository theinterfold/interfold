// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { parseAbi } from 'viem'
import type { Address, PublicClient } from 'viem'

const INTERFOLD_ABI = parseAbi([
  'function getE3(uint256 e3Id) view returns ((uint256 seed, uint8 committeeSize, uint256 requestBlock, uint256[2] inputWindow, bytes32 encryptionSchemeId, address e3Program, uint8 paramSet, bytes customParams, address decryptionVerifier, address pkVerifier, bytes32 committeePublicKey, bytes32 ciphertextOutput, bytes plaintextOutput, address requester, bytes32 ciphertextCommitment))',
])

const CRISP_PROGRAM_ABI = parseAbi([
  'function ballotAuthorization(uint256 e3Id, address slot, bytes32 ciphertextCommitment) view returns (bool safe, bytes32 digest, bytes32 ownersCommitment)',
])

/**
 * Resolve the CRISP program a round was requested against.
 *
 * Read from the round rather than configured, so it cannot disagree with the program the round
 * actually points at. The client already knows the Interfold address from the round state, and a
 * round names its own program, so no extra configuration reaches the browser.
 *
 * @param client The public client.
 * @param interfoldAddress The Interfold contract for this round.
 * @param e3Id The round.
 * @returns The CRISP program address.
 */
export const getCrispRoundConfig = async (
  client: PublicClient,
  interfoldAddress: Address,
  e3Id: bigint,
): Promise<{ crispProgram: Address; paramSet: number }> => {
  const e3 = await client.readContract({
    address: interfoldAddress,
    abi: INTERFOLD_ABI,
    functionName: 'getE3',
    args: [e3Id],
  })

  return { crispProgram: e3.e3Program, paramSet: e3.paramSet }
}

/** Resolve only the CRISP program for callers that do not generate a proof. */
export const getCrispProgramAddress = async (client: PublicClient, interfoldAddress: Address, e3Id: bigint): Promise<Address> =>
  (await getCrispRoundConfig(client, interfoldAddress, e3Id)).crispProgram

/**
 * Read what one ballot is proved against: the digest to sign and the owner commitment.
 *
 * Read from the contract rather than rebuilt here. `CRISPProgram.publishInput` recomputes both
 * values and the circuit proves against them, so a locally built EIP-712 struct that drifted from
 * the contract would produce ballots that every node rejects. For a wallet, `digest` is the
 * `Ballot` typed data that `ballotTypedData` describes. For a Safe slot of an ONCHAIN round, it is
 * the Safe's `SafeMessage` hash, and the owners sign it together.
 *
 * @param client The public client.
 * @param crispProgram The CRISP program address.
 * @param e3Id The round the ballot belongs to.
 * @param slot The slot address the ballot is written to.
 * @param ciphertextCommitment The commitment from `prepareBallot`.
 * @returns Whether the slot is a Safe, the digest, and the owner commitment (zero in a census round).
 */
export const getBallotAuthorization = async (
  client: PublicClient,
  crispProgram: Address,
  e3Id: bigint,
  slot: Address,
  ciphertextCommitment: `0x${string}`,
): Promise<{ safe: boolean; digest: `0x${string}`; ownersCommitment: `0x${string}` }> => {
  const [safe, digest, ownersCommitment] = await client.readContract({
    address: crispProgram,
    abi: CRISP_PROGRAM_ABI,
    functionName: 'ballotAuthorization',
    args: [e3Id, slot, ciphertextCommitment],
  })
  return { safe, digest, ownersCommitment }
}

/**
 * The EIP-712 domain and type a ballot signature covers.
 *
 * Must match `CRISPProgram`'s `EIP712("CRISP", "1")` and `BALLOT_TYPEHASH`. A wallet signs this
 * through `signTypedData`, which produces a signature over the same digest `ballotDigest`
 * returns — `signMessage` would add the EIP-191 prefix and sign something else.
 *
 * @param chainId The chain the program is deployed on.
 * @param crispProgram The CRISP program address.
 * @returns The domain and types for `signTypedData`.
 */
export const ballotTypedData = (chainId: number, crispProgram: Address) =>
  ({
    domain: { name: 'CRISP', version: '1', chainId, verifyingContract: crispProgram },
    types: {
      Ballot: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'slot', type: 'address' },
        { name: 'ciphertextCommitment', type: 'bytes32' },
      ],
    },
    primaryType: 'Ballot',
  }) as const
