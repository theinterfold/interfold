// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { hashMessage } from 'viem'

export const CRISP_SERVER_TOKEN_TREE_ENDPOINT = 'state/token-holders'
export const CRISP_SERVER_STATE_LITE_ENDPOINT = 'state/lite'
export const CRISP_SERVER_PREVIOUS_CIPHERTEXT_ENDPOINT = 'state/previous-ciphertext'
export const CRISP_SERVER_STATE_RESULT_ENDPOINT = 'state/result'
export const CRISP_SERVER_STATE_ALL_ENDPOINT = 'state/all'
export const CRISP_SERVER_ELIGIBLE_ADDRESSES_ENDPOINT = 'state/eligible-addresses'
export const CRISP_SERVER_VOTING_BROADCAST_ENDPOINT = 'voting/broadcast'
export const CRISP_SERVER_VOTING_AVAILABILITY_ENDPOINT = 'voting/availability'
export const CRISP_SERVER_VOTING_STATUS_ENDPOINT = 'voting/status'
export const CRISP_SERVER_ROUNDS_CURRENT_ENDPOINT = 'rounds/current'
export const CRISP_SERVER_ROUNDS_PUBLIC_KEY_ENDPOINT = 'rounds/public-key'
export const CRISP_SERVER_ROUNDS_CIPHERTEXT_ENDPOINT = 'rounds/ciphertext'
export const CRISP_SERVER_ROUNDS_REQUEST_ENDPOINT = 'rounds/request'

// Chain access. These let a client read the contracts CRISP already watches without holding a
// hosted-provider key of its own — see the `/chain/*` routes on the server.
export const CRISP_SERVER_CHAIN_RPC_ENDPOINT = 'chain/rpc'
export const CRISP_SERVER_CHAIN_HEAD_ENDPOINT = 'chain/head'
export const CRISP_SERVER_CHAIN_READ_ENDPOINT = 'chain/read'
export const CRISP_SERVER_CHAIN_LOGS_ENDPOINT = 'chain/logs'
export const CRISP_SERVER_CHAIN_BLOCK_AT_TIMESTAMP_ENDPOINT = 'chain/block-at-timestamp'

export const MERKLE_TREE_MAX_DEPTH = 20 // static, hardcoded in the circuit.

// @note Must stay aligned with CRISP circuits / threshold message layout (Rust & Noir MAX_MSG_NON_ZERO_COEFFS).
// Vote payload uses only the first MAX_MSG_NON_ZERO_COEFFS polynomial coeffs, split evenly across options
// (e.g. 2 options → 50 binary coeffs each within those 100).
export const MAX_MSG_NON_ZERO_COEFFS = 100
// Hard limit on the maximum number of vote options supported.
export const MAX_VOTE_OPTIONS = 10

/**
 * Message used by users to prove ownership of their Ethereum account
 * This message is signed by the user's private key to authenticate their identity
 * @notice Apps ideally want to use a different message to avoid signature reuse across different applications
 */
export const SIGNATURE_MESSAGE = 'CRISP: Sign this message to prove ownership of your Ethereum account'
export const SIGNATURE_MESSAGE_HASH = hashMessage(SIGNATURE_MESSAGE)

// Placeholder signature for masking votes.
export const MASK_SIGNATURE =
  '0x8e7d77112641d59e9409ec3052041703bb9d9e6ed39bfcf75aefbcafe829ac6b21dd7648116ad5db0466fcb4bd468dcb28f6c069def8bc47cd9d859c85a016e31b'
