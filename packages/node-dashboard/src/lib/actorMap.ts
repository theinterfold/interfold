// SPDX-License-Identifier: LGPL-3.0-only

export type ActorId = 'chain' | 'sortition' | 'node' | 'aggregator' | 'zk' | 'compute' | 'net'

export interface ActorMeta {
  id: ActorId
  label: string
  desc: string
}

export const ACTORS: ActorMeta[] = [
  { id: 'chain', label: 'Chain', desc: 'On-chain contract events (EVM reader)' },
  { id: 'sortition', label: 'Sortition', desc: 'Committee selection & lottery' },
  { id: 'node', label: 'Node', desc: 'Keyshare & threshold operations' },
  { id: 'aggregator', label: 'Aggregator', desc: 'Public key & plaintext aggregation' },
  { id: 'zk', label: 'ZK', desc: 'Zero-knowledge proof generation' },
  { id: 'compute', label: 'Compute', desc: 'FHE program execution' },
  { id: 'net', label: 'Network', desc: 'P2P messaging & sync' },
]

export interface EventMeta {
  actor: ActorId
  /** Human-readable description of what this event means */
  label: string
  /** Fields to surface in the flow card (skip binary blobs).
   *  Empty array = use auto-scalar extraction. */
  fields?: string[]
}

// NOTE: keys must match the exact Rust enum variant name as serialised by serde
export const EVT_META: Record<string, EventMeta> = {
  // ── Chain / EVM events ────────────────────────────────────────────────────
  E3Requested: { actor: 'chain', label: 'E3 compute request submitted on-chain', fields: ['threshold_m', 'threshold_n'] },
  CiphernodeSelected: { actor: 'chain', label: 'This node selected for committee', fields: ['party_id', 'threshold_m', 'threshold_n'] },
  E3StageChanged: { actor: 'chain', label: 'E3 on-chain stage transition', fields: ['previous_stage', 'new_stage'] },
  CommitteePublished: { actor: 'chain', label: 'Committee published on-chain', fields: [] },
  CommitteeFinalized: { actor: 'chain', label: 'Committee finalized on-chain', fields: [] },
  CiphertextOutputPublished: { actor: 'chain', label: 'Encrypted input published on-chain', fields: [] },
  PlaintextOutputPublished: { actor: 'chain', label: 'Decrypted output published on-chain', fields: [] },
  E3RequestComplete: { actor: 'chain', label: 'E3 request complete ✓', fields: [] },
  E3Failed: { actor: 'chain', label: 'E3 request failed ✗', fields: ['failed_at_stage', 'reason'] },
  CiphernodeAdded: { actor: 'chain', label: 'Ciphernode registered on-chain', fields: ['address'] },
  CiphernodeRemoved: { actor: 'chain', label: 'Ciphernode removed from registry', fields: ['address'] },
  TicketBalanceUpdated: { actor: 'chain', label: 'Ticket/stake balance updated', fields: ['balance'] },
  ConfigurationUpdated: { actor: 'chain', label: 'Node configuration updated on-chain', fields: [] },
  OperatorActivationChanged: { actor: 'chain', label: 'Operator activation status changed', fields: ['is_active'] },
  SlashExecuted: { actor: 'chain', label: 'Slash executed on-chain', fields: [] },
  CommitteeMemberExpelled: { actor: 'chain', label: 'Committee member expelled', fields: ['party_id'] },
  TicketSubmitted: { actor: 'chain', label: 'Lottery ticket submitted on-chain', fields: ['ticket_id'] },

  // ── Sortition ──────────────────────────────────────────────────────────────
  CommitteeRequested: { actor: 'sortition', label: 'Committee DKG initiated', fields: [] },
  CommitteeFinalizeRequested: { actor: 'sortition', label: 'Committee finalize requested', fields: [] },
  TicketGenerated: { actor: 'sortition', label: 'Lottery ticket generated locally', fields: ['ticket_id'] },

  // ── Node / Keyshare ────────────────────────────────────────────────────────
  KeyshareCreated: { actor: 'node', label: 'BFV keyshare generated (broadcast to peers)', fields: ['party_id', 'node'] },
  EncryptionKeyPending: { actor: 'node', label: 'Collecting encryption keys from committee', fields: [] },
  EncryptionKeyReceived: { actor: 'node', label: 'Encryption key received from peer', fields: ['party_id'] },
  EncryptionKeyCreated: { actor: 'node', label: 'All committee encryption keys collected ✓', fields: [] },
  EncryptionKeyCollectionFailed: { actor: 'node', label: 'Encryption key collection failed ✗', fields: ['reason'] },
  ThresholdSharePending: { actor: 'node', label: 'Collecting threshold decryption shares', fields: [] },
  ThresholdShareCreated: { actor: 'node', label: 'Threshold decryption share generated', fields: ['party_id'] },
  ThresholdShareCollectionFailed: { actor: 'node', label: 'Threshold share collection failed ✗', fields: ['reason'] },
  DecryptionKeyShared: { actor: 'node', label: 'Decryption key share broadcast to peers', fields: ['party_id', 'node'] },
  DecryptionshareCreated: { actor: 'node', label: 'Decryption share created locally', fields: ['party_id'] },
  AggregatorChanged: { actor: 'node', label: 'Aggregator role assignment', fields: ['is_aggregator'] },
  AccusationVote: { actor: 'node', label: 'Accusation vote submitted', fields: ['accused'] },
  AccusationQuorumReached: { actor: 'node', label: 'Accusation quorum reached', fields: ['accused'] },
  ProofFailureAccusation: { actor: 'node', label: 'Proof failure accusation raised', fields: ['party_id'] },
  CommitmentConsistencyCheckRequested: { actor: 'node', label: 'Commitment consistency check requested', fields: [] },
  CommitmentConsistencyCheckComplete: { actor: 'node', label: 'Commitment consistency check complete', fields: ['passed'] },
  CommitmentConsistencyViolation: { actor: 'node', label: 'Commitment consistency VIOLATION ✗', fields: ['party_id'] },
  EnclaveError: { actor: 'node', label: 'Enclave error', fields: ['msg'] },

  // ── Aggregator ─────────────────────────────────────────────────────────────
  PlaintextAggregated: { actor: 'aggregator', label: 'Plaintext aggregated from decryption shares', fields: [] },
  // NOTE: Rust variant is PublicKeyAggregated (capital K), not PublickeyAggregated
  PublicKeyAggregated: { actor: 'aggregator', label: 'Public key aggregated from committee keyshares', fields: ['nodes'] },

  // ── ZK Proofs ──────────────────────────────────────────────────────────────
  // NOTE: Rust variant is DKGInnerProofReady (all-caps DKG)
  DKGInnerProofReady: { actor: 'zk', label: 'DKG inner ZK proof computed', fields: ['party_id'] },
  DKGRecursiveAggregationComplete: { actor: 'zk', label: 'DKG recursive aggregation complete', fields: [] },
  PkGenerationProofSigned: { actor: 'zk', label: 'PK generation proof signed', fields: ['party_id'] },
  PkAggregationProofPending: { actor: 'zk', label: 'Waiting for PK aggregation ZK proof', fields: [] },
  PkAggregationProofSigned: { actor: 'zk', label: 'PK aggregation ZK proof signed', fields: [] },
  DkgProofSigned: { actor: 'zk', label: 'DKG proof signed', fields: ['party_id'] },
  DecryptionShareProofSigned: { actor: 'zk', label: 'Decryption share ZK proof signed', fields: ['party_id'] },
  ShareDecryptionProofPending: { actor: 'zk', label: 'Waiting for share decryption ZK proof', fields: [] },
  AggregationProofPending: { actor: 'zk', label: 'Waiting for aggregation ZK proof', fields: [] },
  AggregationProofSigned: { actor: 'zk', label: 'Aggregation ZK proof signed ✓', fields: [] },
  ShareComputationProofSigned: { actor: 'zk', label: 'Share computation ZK proof signed', fields: ['party_id'] },
  ShareVerificationDispatched: { actor: 'zk', label: 'Share verification dispatched', fields: [] },
  ShareVerificationComplete: { actor: 'zk', label: 'Share verification complete', fields: ['valid'] },
  ProofVerificationFailed: { actor: 'zk', label: 'ZK proof verification failed ✗', fields: ['party_id'] },
  ProofVerificationPassed: { actor: 'zk', label: 'ZK proof verification passed ✓', fields: ['party_id'] },
  SignedProofFailed: { actor: 'zk', label: 'Signed proof validation failed ✗', fields: [] },
  DecryptionShareProofsPending: { actor: 'zk', label: 'Waiting for decryption share ZK proofs', fields: [] },

  // ── Compute ────────────────────────────────────────────────────────────────
  ComputeRequest: { actor: 'compute', label: 'FHE computation requested', fields: ['program'] },
  ComputeResponse: { actor: 'compute', label: 'FHE computation response received', fields: [] },
  ComputeRequestError: { actor: 'compute', label: 'FHE computation failed ✗', fields: ['error'] },

  // ── Network / Sync ─────────────────────────────────────────────────────────
  NetReady: { actor: 'net', label: 'P2P network layer ready', fields: [] },
  OutgoingSyncRequested: { actor: 'net', label: 'Event sync broadcast to peers', fields: [] },
  DocumentReceived: { actor: 'net', label: 'Document received from peer', fields: [] },
  PublishDocumentRequested: { actor: 'net', label: 'Publishing document to network', fields: [] },
  HistoricalEvmSyncStart: { actor: 'net', label: 'Historical EVM chain sync started', fields: [] },
  HistoricalNetSyncStart: { actor: 'net', label: 'Historical P2P network sync started', fields: [] },
  HistoricalNetSyncEventsReceived: { actor: 'net', label: 'Historical network events received', fields: ['count'] },
  SyncEffect: { actor: 'net', label: 'Sync effect applied', fields: [] },
  SyncEnded: { actor: 'net', label: 'Sync phase complete', fields: [] },
  EffectsEnabled: { actor: 'net', label: 'Live effects enabled (post-sync)', fields: [] },
}

/** Return a short human-readable badge colour class for an actor */
export function actorClass(actor: ActorId): string {
  return `actor-${actor}`
}
