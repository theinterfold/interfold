// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{AggregateId, E3id};

pub struct StoreKeys;

impl StoreKeys {
    pub fn keyshare(e3_id: &E3id) -> String {
        format!("//keyshare/{e3_id}")
    }

    pub fn threshold_keyshare(e3_id: &E3id) -> String {
        format!("{}{e3_id}", Self::THRESHOLD_KEYSHARE_PREFIX)
    }

    pub fn threshold_keyshare_recovery(e3_id: &E3id) -> String {
        format!("{}{e3_id}", Self::THRESHOLD_KEYSHARE_RECOVERY_PREFIX)
    }

    pub fn threshold_keyshare_recovery_payloads(e3_id: &E3id) -> String {
        format!(
            "{}{e3_id}",
            Self::THRESHOLD_KEYSHARE_RECOVERY_PAYLOADS_PREFIX
        )
    }

    pub fn threshold_keyshare_bfv_key(e3_id: &E3id) -> String {
        format!("{}{e3_id}", Self::THRESHOLD_KEYSHARE_BFV_KEY_PREFIX)
    }

    /// Key prefix of the key-share state of one E3. The E3 ID follows it.
    pub const THRESHOLD_KEYSHARE_PREFIX: &'static str = "//threshold_keyshare/";

    /// Key prefix of this node's BFV encryption keypair for one E3. The E3 ID follows it.
    pub const THRESHOLD_KEYSHARE_BFV_KEY_PREFIX: &'static str = "//threshold_keyshare_bfv_key/v1/";

    /// Key prefix of the key-share recovery state of one E3. The E3 ID follows it.
    pub const THRESHOLD_KEYSHARE_RECOVERY_PREFIX: &'static str =
        "//threshold_keyshare_recovery/v1/";

    /// Key prefix of the key-share recovery payloads of one E3. The E3 ID follows it.
    pub const THRESHOLD_KEYSHARE_RECOVERY_PAYLOADS_PREFIX: &'static str =
        "//threshold_keyshare_recovery_payloads/v1/";

    /// Key prefix of the slash writer state of one chain. The chain ID follows it.
    pub const SLASHING_WRITER_PREFIX: &'static str = "//evm_writers/slashing/";

    pub fn plaintext(e3_id: &E3id) -> String {
        format!("//plaintext/{e3_id}")
    }

    pub fn plaintext_recovery(e3_id: &E3id) -> String {
        format!("//plaintext_recovery/v1/{e3_id}")
    }

    pub fn publickey(e3_id: &E3id) -> String {
        format!("//publickey/{e3_id}")
    }

    pub fn publickey_recovery(e3_id: &E3id) -> String {
        format!("//publickey_recovery/v1/{e3_id}")
    }

    pub fn fhe(e3_id: &E3id) -> String {
        format!("//fhe/{e3_id}")
    }

    pub fn meta(e3_id: &E3id) -> String {
        format!("//meta/{e3_id}")
    }

    pub fn dkg_fold_attestation_context(e3_id: &E3id) -> String {
        format!("//dkg_fold_attestation_context/{e3_id}")
    }

    pub fn node_dkg_fold_recovery() -> String {
        String::from("//node_dkg_fold/recovery/v1")
    }

    pub fn node_dkg_inner_proof(e3_id: &E3id, seq: usize) -> String {
        format!("//node_dkg_fold/proofs/{e3_id}/{seq}")
    }

    pub fn node_dkg_fold_meta(e3_id: &E3id) -> String {
        format!("//node_dkg_fold/meta/{e3_id}")
    }

    pub fn context(e3_id: &E3id) -> String {
        format!("//context/{e3_id}")
    }

    /// Durable state for the per-E3 commitment-consistency checker.
    pub fn commitment_consistency(e3_id: &E3id) -> String {
        format!("//commitment_consistency/v1/{e3_id}")
    }

    pub fn router() -> String {
        String::from("//router")
    }

    pub fn request_router_checkpoint() -> String {
        String::from("//router/recovery_checkpoint")
    }

    pub fn e3_lifecycle() -> String {
        String::from("//e3_lifecycle")
    }

    pub fn sortition() -> String {
        String::from("//sortition")
    }

    pub fn sortition_recovery() -> String {
        String::from("//sortition/runtime_recovery/v1")
    }

    pub fn restart_input_cursors() -> String {
        String::from("//sync/restart_input_cursors/v1")
    }

    pub fn sortition_bond_owners() -> String {
        String::from("//sortition/bond_owners/v2")
    }

    pub fn sortition_admission() -> String {
        String::from("//sortition/admission/v2")
    }

    pub fn committee_finalizer_recovery() -> String {
        String::from("//committee_finalizer/recovery/v1")
    }

    pub fn slashing_writer_recovery(chain_id: u64) -> String {
        format!("{}{chain_id}/recovery/v1", Self::SLASHING_WRITER_PREFIX)
    }

    pub fn data_availability_recovery(chain_id: u64) -> String {
        format!("//data_availability/{chain_id}/recovery/v1")
    }

    pub fn eth_private_key() -> String {
        String::from("//eth_private_key")
    }

    pub fn libp2p_keypair() -> String {
        String::from("//libp2p/keypair")
    }

    pub fn node_state() -> String {
        String::from("//node_state")
    }

    /// Global on-disk schema version marker. Written once on first boot and
    /// checked on every subsequent boot to reject incompatible upgrades and
    /// downgrades loudly instead of silently loading garbage (H19/H20).
    pub fn schema_version() -> String {
        String::from("//schema_version")
    }

    /// Role of the node that owns this data directory (full or bootstrap). Written on first boot;
    /// a node refuses to start on a directory that another role wrote.
    pub fn node_role() -> String {
        String::from("//node_role")
    }

    pub fn finalized_committees() -> String {
        String::from("//finalized_committees")
    }

    pub fn ciphernode_selector() -> String {
        String::from("//ciphernode_selector/v2")
    }

    pub fn aggregator_failover() -> String {
        String::from("//aggregator_failover")
    }

    pub fn aggregate_seq(aggregate_id: AggregateId) -> String {
        format!("//aggregate_seq/{}", aggregate_id)
    }

    pub fn aggregate_block(aggregate_id: AggregateId) -> String {
        format!("//aggregate_block/{}", aggregate_id)
    }

    pub fn aggregate_ts(aggregate_id: AggregateId) -> String {
        format!("//aggregate_ts/{}", aggregate_id)
    }
}
