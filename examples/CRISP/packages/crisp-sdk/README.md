# CRISP SDK

TypeScript SDK for interacting with CRISP (Coercion-Resistant Impartial Selection Protocol) and the
CRISP server.

## Installation

```bash
npm install @crisp-e3/sdk
```

## Features

- **Round Management**: Fetch round details, token requirements, and voting parameters
- **Token Operations**: Query token balances and total supply at specific blocks
- **Merkle Tree Utilities**: Generate proofs for voter inclusion in the eligibility tree
- **Vote Proof Generation**: Create zero-knowledge proofs for votes and mask votes
- **Proof Verification**: Verify generated proofs using Noir circuits
- **Selectable Parameters**: preset bundles are separate entry points and can be loaded on demand

## Choosing a preset

Proving needs the BFV-shaped circuits, and those exist once per parameter set. They are not part of
the main entry point: the `secure-8192` set is far larger than `insecure-512`. Each preset has its
own subpath, so your bundler can pull only the one the round needs.

```ts
import { setCircuits } from '@crisp-e3/sdk'
import { loadCircuits } from '@crisp-e3/sdk/insecure-512' // or '@crisp-e3/sdk/secure-8192'

setCircuits(await loadCircuits())
```

Register once at start-up, before the first `prepareBallot`/`generateProof`. There is deliberately
no default: a ballot proved against the wrong parameters is rejected on chain rather than locally,
so `generateProof` throws a directed error instead of guessing.

In a browser, load it through a dynamic `import()` so the circuits become their own chunk and the
app boots without them:

```ts
const { loadCircuits } = await import('@crisp-e3/sdk/secure-8192')
setCircuits(await loadCircuits())
```

`verifyProof`, `encodeVote`, `decodeTally` and the round/token helpers need no preset. The
aggregation circuits they use are proof-shaped rather than polynomial-shaped, so a single artifact
covers every preset and ships in the main entry point.

## Usage

### CrispSDK Class (Recommended)

The `CrispSDK` class provides a convenient interface that automatically handles server communication
for fetching previous ciphertexts and checking slot status.

```typescript
import { CrispSDK } from '@crisp-e3/sdk'

const sdk = new CrispSDK(serverUrl)

// Generate a vote proof (automatically fetches previous ciphertext if needed)
const voteProof = await sdk.generateVoteProof({
  e3Id: 1n,
  vote: [100, 0], // one weight per option
  publicKey: publicKeyBytes,
  signature: '0x...',
  messageHash: '0x...',
  balance: 1000n,
  slotAddress: '0x...',
  merkleLeaves: [...],
})

// Generate a mask vote proof (automatically fetches previous ciphertext if needed)
const maskProof = await sdk.generateMaskVoteProof({
  e3Id: 1n,
  balance: 1000n,
  slotAddress: '0x...',
  publicKey: publicKeyBytes,
  merkleLeaves: [...],
})
```

### Standalone Functions

#### Get Round Details

```typescript
import { getRoundDetails, getRoundTokenDetails } from '@crisp-e3/sdk'

const roundDetails = await getRoundDetails(serverUrl, e3Id)
const tokenDetails = await getRoundTokenDetails(serverUrl, e3Id)
```

#### Get Token Balance and Supply

```typescript
import { getBalanceAt, getTotalSupplyAt, getTreeData } from '@crisp-e3/sdk'

const balance = await getBalanceAt(voterAddress, tokenAddress, snapshotBlock, chainId)
const totalSupply = await getTotalSupplyAt(tokenAddress, snapshotBlock, chainId)
const merkleLeaves = await getTreeData(serverUrl, e3Id)
```

#### Generate Vote Proof (Low-level)

```typescript
import { generateVoteProof } from '@crisp-e3/sdk'

const proof = await generateVoteProof({
  vote: [100, 0], // one weight per option
  publicKey: publicKeyBytes,
  signature: '0x...',
  messageHash: '0x...',
  balance: 1000n,
  slotAddress: '0x...',
  merkleLeaves: [...],
  previousCiphertext: previousCiphertextBytes, // optional
})
```

#### Generate Mask Vote Proof (Low-level)

```typescript
import { generateMaskVoteProof } from '@crisp-e3/sdk'

const maskProof = await generateMaskVoteProof({
  balance: 1000n,
  slotAddress: '0x...',
  publicKey: publicKeyBytes,
  merkleLeaves: [...],
  previousCiphertext: previousCiphertextBytes, // optional
})
```

#### Verify Proof

```typescript
import { verifyProof } from '@crisp-e3/sdk'

const isValid = await verifyProof(proof)
```

#### Ballot Encoding and Decode Tally

Coefficient `o` of the message polynomial is the weight on option `o`. Every other coefficient up to
the BFV degree is zero. BFV adds ballots coefficient by coefficient, so the decrypted tally holds
one total per option. A weight is a non-negative integer below the BFV plaintext modulus `t`, and a
round has 2 to `MAX_VOTE_OPTIONS` options. `CRISPProgram` keeps every option total below `t`.

```typescript
import { encodeVote, decodeTally } from '@crisp-e3/sdk'

const coefficients = encodeVote([3, 0, 7]) // coefficient 0 = 3, coefficient 2 = 7, the rest 0

const tally = decodeTally(tallyBytes, numOptions)
// Returns: bigint[] — the first numOptions coefficients, one total per option
```

#### Cryptographic Utilities

```typescript
import { generatePublicKey, encryptVote, encodeSolidityProof } from '@crisp-e3/sdk'

const publicKey = generatePublicKey()
const encryptedVote = encryptVote(vote, publicKey)
const encodedProof = encodeSolidityProof(proof)
```

#### Merkle Tree Utilities

```typescript
import {
  generateMerkleProof,
  generateMerkleTree,
  hashLeaf,
  getAddressFromSignature,
} from '@crisp-e3/sdk'

const leaf = hashLeaf(address, balance)
const tree = generateMerkleTree(leaves)
const proof = generateMerkleProof(balance, address, merkleLeaves)
const address = await getAddressFromSignature(signature, messageHash)
```

#### State Utilities

```typescript
import { getPreviousCiphertext } from '@crisp-e3/sdk'

const head = await getPreviousCiphertext(serverUrl, e3Id, slotAddress)
// { ciphertext, index }, or undefined when the slot holds nothing usable (404).
// `index` is the entry a new input names as its parent. It is the end of the slot's chain of
// usable entries, not simply the newest one published: an entry whose bytes do not reproduce its
// commitment is never selected by the Secure Process, and never a valid parent.
```

#### Submission Status

A committed ballot counts only when the Secure Process selects it for its slot and its ciphertext is
published. An earlier ballot or mask that names the same parent takes the slot first.

```typescript
import {
  decodeInputIdentity,
  getInputSelection,
  getSubmissionStage,
  getVoteAvailability,
} from '@crisp-e3/sdk'

const identity = decodeInputIdentity(encodedProof)
const job = await getVoteAvailability(serverUrl, jobId)
const selection = await getInputSelection(serverUrl, e3Id, identity)
// undefined when the server has no record of the round (404).
const { stage, retryOffered } = getSubmissionStage({
  availability: job.status,
  selection: selection ?? null,
  now: Math.floor(Date.now() / 1000),
  commitmentDeadline,
})
// stage: awaiting_commitment | selection_pending | availability_pending | counted | excluded | failed
// retryOffered: true only for `excluded` before the commitment deadline.
```

## API

### CrispSDK Class

- `constructor(serverUrl: string)` - Create a new SDK instance
- `generateVoteProof(voteProofRequest: VoteProofRequest): Promise<ProofData>` - Generate a vote
  proof (automatically handles previous ciphertext)
- `generateMaskVoteProof(maskVoteProofRequest: MaskVoteProofRequest): Promise<ProofData>` - Generate
  a mask vote proof (automatically handles previous ciphertext)

### State Functions

- `getRoundDetails(serverUrl: string, e3Id: bigint): Promise<RoundDetails>` - Get round details
- `getRoundTokenDetails(serverUrl: string, e3Id: bigint): Promise<TokenDetails>` - Get token details
  for a round
- `getPreviousCiphertext(serverUrl: string, e3Id: bigint, address: string): Promise<SlotHead | undefined>` -
  Get the end of a slot's chain of usable entries, as `{ ciphertext, index }`. `index` is what a new
  input names as its parent. Undefined when the slot holds nothing usable.

### Token Functions

- `getBalanceAt(voterAddress: string, tokenAddress: string, snapshotBlock: number, chainId: number): Promise<bigint>` -
  Get token balance at a specific block
- `getTotalSupplyAt(tokenAddress: string, snapshotBlock: number, chainId: number): Promise<bigint>` -
  Get total supply at a specific block
- `getTreeData(serverUrl: string, e3Id: bigint): Promise<bigint[]>` - Get merkle tree leaves from
  server

### Vote Functions

- `generateVoteProof(voteProofInputs: VoteProofInputs): Promise<ProofData>` - Generate a vote proof
  (low-level)
- `generateMaskVoteProof(maskVoteProofInputs: MaskVoteProofInputs): Promise<ProofData>` - Generate a
  mask vote proof (low-level)
- `verifyProof(proof: ProofData): Promise<boolean>` - Verify a proof locally
- `encodeVote(vote: Vote): number[]` - Encode one weight per option into message coefficients,
  padded to the BFV degree
- `decodeTally(tallyBytes: string | number[] | bigint[], numChoices: number): TallyResult` - Decode
  the first `numChoices` coefficients of a tally into one total per option
- `validateVote(vote: Vote, balance: bigint): void` - Check the weights against the plaintext
  modulus and the voting-power rules; throws on an invalid vote
- `generatePublicKey(): Uint8Array` - Generate a random public key
- `encryptVote(vote: Vote, publicKey: Uint8Array): Uint8Array` - Encrypt a vote
- `encodeSolidityProof(proof: ProofData): Hex` - Encode proof for Solidity contract
- `decodeInputIdentity(encodedProof: Hex): InputIdentity` - Read the slot address, ciphertext
  commitment, ciphertext hash, and parent index plus one from an `encodeSolidityProof` envelope

### Submission Functions

- `getInputSelection(serverUrl: string, e3Id: bigint, identity: InputIdentity): Promise<InputSelectionResponse | undefined>` -
  Get the Secure Process selection state of an input. Undefined when the server has no record of the
  round.
- `getSubmissionStage(inputs: SubmissionStageInputs): SubmissionStatus` - Combine the availability
  job status and the selection state into the stage of one ballot, and tell whether a retry is
  offered

### Utility Functions

- `generateMerkleProof(balance: bigint, address: string, leaves: bigint[] | string[]): MerkleProof` -
  Generate merkle proof
- `generateMerkleTree(leaves: bigint[]): LeanIMT` - Generate merkle tree
- `hashLeaf(address: string, balance: bigint): bigint` - Hash a leaf node
- `getAddressFromSignature(signature: \`0x${string}\`, messageHash?: \`0x${string}\`):
  Promise<string>` - Extract address from signature

### Constants

- `MERKLE_TREE_MAX_DEPTH` - Maximum depth of the merkle tree
- `SIGNATURE_MESSAGE` - Message used for signature verification
- `MAX_VOTE_OPTIONS` - Maximum number of options in a round
- `MAX_MSG_NON_ZERO_COEFFS` - Number of plaintext coefficients published as the tally
- `SIGNATURE_MESSAGE_HASH` - Hash of the signature message

### Types

- `RoundDetails` - Round details type
- `RoundDetailsResponse` - Server response type for round details
- `TokenDetails` - Token details type
- `Vote` - One non-negative integer weight per option, indexed by option
- `MaskVoteProofInputs` - Inputs for mask vote proof generation
- `VoteProofInputs` - Inputs for vote proof generation
