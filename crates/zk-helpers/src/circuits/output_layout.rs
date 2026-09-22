// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Describes the public output (return value) layout of each ZK circuit.
//!
//! In Noir, circuits declare `pub` input parameters and `-> pub` return values.
//! Both end up in the proof's `public_signals` byte array, with return values
//! placed **after** all public inputs. This module provides the metadata needed
//! to extract named return fields from a proof's public signals without
//! hard-coding byte offsets.

use serde::{Deserialize, Serialize};
use std::ops::Range;

/// Size of a single Noir `Field` element in bytes (BN254 scalar).
pub const FIELD_BYTE_LEN: usize = 32;

/// A named output field of a circuit proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputField {
    /// Human-readable name (e.g. `"pk_commitment"`).
    pub name: &'static str,
}

/// Describes the public return values of a circuit.
///
/// `fields` lists them in the order they appear in `public_signals`,
/// which is the same order as the Noir `-> pub (A, B, C)` tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CircuitOutputLayout {
    /// Fixed number of `Field`-sized outputs, names known at compile time.
    Fixed { fields: &'static [OutputField] },
    /// The circuit returns no public values (void).
    None,
}

impl CircuitOutputLayout {
    /// Number of fixed output fields, or `None` for void layouts.
    pub fn field_count(&self) -> Option<usize> {
        match self {
            CircuitOutputLayout::Fixed { fields } => Some(fields.len()),
            CircuitOutputLayout::None => Some(0),
        }
    }

    /// Look up a field index by name.
    pub fn field_index(&self, name: &str) -> Option<usize> {
        match self {
            CircuitOutputLayout::Fixed { fields } => fields.iter().position(|f| f.name == name),
            _ => None,
        }
    }

    /// Extract a named output field from raw `public_signals` bytes.
    ///
    /// Return values sit at the **end** of `public_signals`, after any
    /// `pub` input parameters. This method indexes from the tail.
    pub fn extract_field<'a>(&self, public_signals: &'a [u8], name: &str) -> Option<&'a [u8]> {
        let fields = match self {
            CircuitOutputLayout::Fixed { fields } => fields,
            _ => return None,
        };
        let idx = fields.iter().position(|f| f.name == name)?;
        let total_output_bytes = fields.len() * FIELD_BYTE_LEN;
        if public_signals.len() < total_output_bytes {
            return None;
        }
        let output_start = public_signals.len() - total_output_bytes;
        let offset = output_start + idx * FIELD_BYTE_LEN;
        Some(&public_signals[offset..offset + FIELD_BYTE_LEN])
    }

    /// Extract all output fields from raw `public_signals` bytes.
    ///
    /// Returns a vec of `(name, &[u8])` pairs in field order.
    pub fn extract_all<'a>(
        &self,
        public_signals: &'a [u8],
    ) -> Option<Vec<(&'static str, &'a [u8])>> {
        let fields = match self {
            CircuitOutputLayout::Fixed { fields } => fields,
            CircuitOutputLayout::None => return Some(Vec::new()),
        };
        let total_output_bytes = fields.len() * FIELD_BYTE_LEN;
        if public_signals.len() < total_output_bytes {
            return None;
        }
        let output_start = public_signals.len() - total_output_bytes;
        Some(
            fields
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let offset = output_start + i * FIELD_BYTE_LEN;
                    (f.name, &public_signals[offset..offset + FIELD_BYTE_LEN])
                })
                .collect(),
        )
    }
}

/// C6 — Threshold share decryption public inputs.
pub const THRESHOLD_SHARE_DECRYPTION_INPUTS: &[OutputField] = &[
    f("expected_sk_commitment"),
    f("expected_e_sm_commitment"),
    f("ct_commitment"),
    f("domain_hi"),
    f("domain_lo"),
];

/// C3 — Share encryption public return (`-> pub Field`).
pub const SHARE_ENCRYPTION_OUTPUTS: &[OutputField] = &[f("ct_commitment")];

// ── Per-circuit output field constants ──────────────────────────────────────

const fn f(name: &'static str) -> OutputField {
    OutputField { name }
}

/// C0 — BFV public key proof.
pub const PK_BFV_OUTPUTS: &[OutputField] = &[f("pk_commitment")];

/// C1 — Threshold public key generation.
pub const PK_GENERATION_OUTPUTS: &[OutputField] =
    &[f("sk_commitment"), f("pk_commitment"), f("e_sm_commitment")];

/// l-BFV public-key generation for one gadget row.
pub const LBFV_PK_GENERATION_OUTPUTS: &[OutputField] =
    &[f("sk_commitment"), f("pk_commitment"), f("limb_vk_hash")];

/// l-BFV public-key generation for one row and one CRT limb.
pub const LBFV_PK_GENERATION_LIMB_OUTPUTS: &[OutputField] = &[
    f("sk_commitment"),
    f("eek_commitment"),
    f("pk_limb_commitment"),
];

/// Threshold l-BFV public-key aggregation for one gadget row.
pub const LBFV_PK_AGGREGATION_OUTPUTS: &[OutputField] = &[f("pk_agg_commitment")];

/// l-BFV relinearization-key generation for one row.
pub const RLK_GENERATION_OUTPUTS: &[OutputField] = &[
    f("sk_commitment"),
    f("r_commitment"),
    f("d0_commitment"),
    f("d2_commitment"),
    f("limb_vk_hash"),
];

/// l-BFV relinearization-key generation for one row and one CRT limb.
pub const RLK_GENERATION_LIMB_OUTPUTS: &[OutputField] = &[
    f("sk_commitment"),
    f("r_commitment"),
    f("e0_commitment"),
    f("e2_commitment"),
    f("d0_limb_commitment"),
    f("d2_limb_commitment"),
];

/// l-BFV relinearization-key aggregation for one gadget row.
pub const RLK_AGGREGATION_OUTPUTS: &[OutputField] =
    &[f("d0_agg_commitment"), f("d2_agg_commitment")];

/// C4 — DKG share decryption.
pub const DKG_SHARE_DECRYPTION_OUTPUTS: &[OutputField] = &[f("commitment")];

/// C5 — Public key aggregation.
pub const PK_AGGREGATION_OUTPUTS: &[OutputField] = &[f("commitment")];

/// C6 — Threshold share decryption (prefix commitment to `d`, per CRT limb).
pub const THRESHOLD_SHARE_DECRYPTION_OUTPUTS: &[OutputField] = &[f("d_commitment")];

/// Number of legacy recursive verification-key bindings in `dkg_aggregator_v2`.
pub const DKG_AGGREGATOR_V2_LEGACY_VK_BINDING_LEN: usize = 16;

/// Number of V2 recursive verification-key bindings in `dkg_aggregator_v2`.
pub const DKG_AGGREGATOR_V2_VK_BINDING_LEN: usize = 13;

/// Exact public-signal positions for `dkg_aggregator_v2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgAggregatorV2PublicLayout {
    pub nodes_fold_key_hash: usize,
    pub c5_key_hash: usize,
    pub party_ids: Range<usize>,
    pub committee_hash_hi: usize,
    pub committee_hash_lo: usize,
    pub legacy_vk_binding: Range<usize>,
    pub legacy_key_hash: usize,
    pub c2a_chunk_hash: usize,
    pub c2b_chunk_hash: usize,
    pub sk_agg_commitments: Range<usize>,
    pub esm_agg_commitments: Range<usize>,
    pub key_envelope_commitment: usize,
    pub v2_key_hash: usize,
    pub session_id_hi: usize,
    pub session_id_lo: usize,
    pub aggregator_party_id: usize,
    pub accepted_party_set_hash_hi: usize,
    pub accepted_party_set_hash_lo: usize,
    pub aggregate_pk_commitments: Range<usize>,
    pub aggregate_d0_commitments: Range<usize>,
    pub aggregate_d2_commitments: Range<usize>,
    pub v2_vk_binding: Range<usize>,
    pub field_count: usize,
}

impl DkgAggregatorV2PublicLayout {
    /// Build the layout for one compiled committee and l-BFV row count.
    pub fn new(committee_h: usize, lbfv_row_count: usize) -> Self {
        let party_ids = 2..2 + committee_h;
        let committee_hash_hi = party_ids.end;
        let committee_hash_lo = committee_hash_hi + 1;
        let legacy_vk_binding =
            committee_hash_lo + 1..committee_hash_lo + 1 + DKG_AGGREGATOR_V2_LEGACY_VK_BINDING_LEN;

        let legacy_key_hash = legacy_vk_binding.end;
        let c2a_chunk_hash = legacy_key_hash + 1;
        let c2b_chunk_hash = c2a_chunk_hash + 1;
        let sk_agg_commitments = c2b_chunk_hash + 1..c2b_chunk_hash + 1 + committee_h;
        let esm_agg_commitments = sk_agg_commitments.end..sk_agg_commitments.end + committee_h;
        let key_envelope_commitment = esm_agg_commitments.end;
        let v2_key_hash = key_envelope_commitment + 1;
        let session_id_hi = v2_key_hash + 1;
        let session_id_lo = session_id_hi + 1;
        let aggregator_party_id = session_id_lo + 1;
        let accepted_party_set_hash_hi = aggregator_party_id + 1;
        let accepted_party_set_hash_lo = accepted_party_set_hash_hi + 1;
        let aggregate_pk_commitments =
            accepted_party_set_hash_lo + 1..accepted_party_set_hash_lo + 1 + lbfv_row_count;
        let aggregate_d0_commitments =
            aggregate_pk_commitments.end..aggregate_pk_commitments.end + lbfv_row_count;
        let aggregate_d2_commitments =
            aggregate_d0_commitments.end..aggregate_d0_commitments.end + lbfv_row_count;
        let v2_vk_binding = aggregate_d2_commitments.end
            ..aggregate_d2_commitments.end + DKG_AGGREGATOR_V2_VK_BINDING_LEN;

        Self {
            nodes_fold_key_hash: 0,
            c5_key_hash: 1,
            party_ids,
            committee_hash_hi,
            committee_hash_lo,
            legacy_vk_binding,
            legacy_key_hash,
            c2a_chunk_hash,
            c2b_chunk_hash,
            sk_agg_commitments,
            esm_agg_commitments,
            key_envelope_commitment,
            v2_key_hash,
            session_id_hi,
            session_id_lo,
            aggregator_party_id,
            accepted_party_set_hash_hi,
            accepted_party_set_hash_lo,
            aggregate_pk_commitments,
            aggregate_d0_commitments,
            aggregate_d2_commitments,
            field_count: v2_vk_binding.end,
            v2_vk_binding,
        }
    }

    /// Extract the key-envelope commitment from an exact-shape public statement.
    pub fn extract_key_envelope_commitment<'a>(
        &self,
        public_signals: &'a [u8],
    ) -> Option<&'a [u8]> {
        if public_signals.len() != self.field_count.checked_mul(FIELD_BYTE_LEN)? {
            return None;
        }
        let start = self.key_envelope_commitment.checked_mul(FIELD_BYTE_LEN)?;
        public_signals.get(start..start + FIELD_BYTE_LEN)
    }
}

// ── Per-circuit input field constants ───────────────────────────────────────

/// C3 — Share encryption public inputs (at HEAD of `public_signals`).
pub const SHARE_ENCRYPTION_INPUTS: &[OutputField] = &[
    f("expected_pk_commitment"),
    f("expected_message_commitment"),
    f("party_idx"),
    f("mod_idx"),
];

/// Public l-BFV relinearization-key generation domain and row identity.
pub const RLK_GENERATION_INPUTS: &[OutputField] = &[
    f("session_id_hi"),
    f("session_id_lo"),
    f("party_id"),
    f("row_index"),
];

/// Public generation domain, row, and CRT-limb identity for an RLK leaf proof.
pub const RLK_GENERATION_LIMB_INPUTS: &[OutputField] = &[
    f("session_id_hi"),
    f("session_id_lo"),
    f("party_id"),
    f("row_index"),
    f("limb_index"),
];

/// Public l-BFV public-key generation domain and row identity.
pub const LBFV_PK_GENERATION_INPUTS: &[OutputField] = &[
    f("session_id_hi"),
    f("session_id_lo"),
    f("party_id"),
    f("row_index"),
];

/// Public generation domain, row, and CRT-limb identity for a public-key leaf proof.
pub const LBFV_PK_GENERATION_LIMB_INPUTS: &[OutputField] = &[
    f("session_id_hi"),
    f("session_id_lo"),
    f("party_id"),
    f("row_index"),
    f("limb_index"),
];

/// Public domain, accepted party-set hash, and row for public-key aggregation.
pub const LBFV_PK_AGGREGATION_INPUTS: &[OutputField] = &[
    f("session_id_hi"),
    f("session_id_lo"),
    f("aggregator_party_id"),
    f("accepted_party_set_hash_hi"),
    f("accepted_party_set_hash_lo"),
    f("row_index"),
];

/// Public domain, accepted party-set hash, and row for RLK aggregation.
pub const RLK_AGGREGATION_INPUTS: &[OutputField] = &[
    f("session_id_hi"),
    f("session_id_lo"),
    f("aggregator_party_id"),
    f("accepted_party_set_hash_hi"),
    f("accepted_party_set_hash_lo"),
    f("row_index"),
];

/// Exact field positions for one l-BFV public-key aggregation statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LbfvPkAggregationPublicLayout {
    pub session_id_hi: usize,
    pub session_id_lo: usize,
    pub aggregator_party_id: usize,
    pub accepted_party_set_hash_hi: usize,
    pub accepted_party_set_hash_lo: usize,
    pub row_index: usize,
    pub expected_pk_generation_commitments: Range<usize>,
    pub pk_agg_commitment: usize,
    pub field_count: usize,
}

impl LbfvPkAggregationPublicLayout {
    pub fn new(committee_h: usize) -> Self {
        let expected_pk_generation_commitments = 6..6 + committee_h;
        let pk_agg_commitment = expected_pk_generation_commitments.end;
        Self {
            session_id_hi: 0,
            session_id_lo: 1,
            aggregator_party_id: 2,
            accepted_party_set_hash_hi: 3,
            accepted_party_set_hash_lo: 4,
            row_index: 5,
            expected_pk_generation_commitments,
            pk_agg_commitment,
            field_count: pk_agg_commitment + 1,
        }
    }
}

/// Exact field positions for one RLK aggregation statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlkAggregationPublicLayout {
    pub session_id_hi: usize,
    pub session_id_lo: usize,
    pub aggregator_party_id: usize,
    pub accepted_party_set_hash_hi: usize,
    pub accepted_party_set_hash_lo: usize,
    pub row_index: usize,
    pub expected_d0_commitments: Range<usize>,
    pub expected_d2_commitments: Range<usize>,
    pub d0_agg_commitment: usize,
    pub d2_agg_commitment: usize,
    pub field_count: usize,
}

impl RlkAggregationPublicLayout {
    pub fn new(committee_h: usize) -> Self {
        let expected_d0_commitments = 6..6 + committee_h;
        let expected_d2_commitments =
            expected_d0_commitments.end..expected_d0_commitments.end + committee_h;
        let d0_agg_commitment = expected_d2_commitments.end;
        let d2_agg_commitment = d0_agg_commitment + 1;
        Self {
            session_id_hi: 0,
            session_id_lo: 1,
            aggregator_party_id: 2,
            accepted_party_set_hash_hi: 3,
            accepted_party_set_hash_lo: 4,
            row_index: 5,
            expected_d0_commitments,
            expected_d2_commitments,
            d0_agg_commitment,
            d2_agg_commitment,
            field_count: d2_agg_commitment + 1,
        }
    }
}

/// Describes the public input layout of a circuit.
///
/// Unlike [`CircuitOutputLayout`] which indexes from the TAIL of
/// `public_signals`, input fields sit at the HEAD.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CircuitInputLayout {
    /// Fixed number of `Field`-sized inputs, names known at compile time.
    Fixed { fields: &'static [OutputField] },
    /// The circuit has no named public inputs (or they are not tracked).
    None,
}

impl CircuitInputLayout {
    /// Number of fixed input fields, or `None` for void layouts.
    pub fn field_count(&self) -> Option<usize> {
        match self {
            CircuitInputLayout::Fixed { fields } => Some(fields.len()),
            CircuitInputLayout::None => Some(0),
        }
    }

    /// Look up a field index by name.
    pub fn field_index(&self, name: &str) -> Option<usize> {
        match self {
            CircuitInputLayout::Fixed { fields } => fields.iter().position(|f| f.name == name),
            _ => None,
        }
    }

    /// Extract a named input field from raw `public_signals` bytes.
    ///
    /// Input fields sit at the **beginning** of `public_signals`.
    /// This method indexes from the head (offset = idx * FIELD_BYTE_LEN).
    pub fn extract_field<'a>(&self, public_signals: &'a [u8], name: &str) -> Option<&'a [u8]> {
        let fields = match self {
            CircuitInputLayout::Fixed { fields } => fields,
            _ => return None,
        };
        let idx = fields.iter().position(|f| f.name == name)?;
        let offset = idx * FIELD_BYTE_LEN;
        if public_signals.len() < offset + FIELD_BYTE_LEN {
            return None;
        }
        Some(&public_signals[offset..offset + FIELD_BYTE_LEN])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_single_output_field() {
        let layout = CircuitOutputLayout::Fixed {
            fields: PK_BFV_OUTPUTS,
        };
        // 32 bytes pub input + 32 bytes output
        let mut signals = vec![0xAAu8; 64];
        signals[32..].copy_from_slice(&[0xBB; 32]);
        let commitment = layout.extract_field(&signals, "pk_commitment").unwrap();
        assert_eq!(commitment, &[0xBB; 32]);
    }

    #[test]
    fn extract_c1_pk_commitment_from_middle() {
        let layout = CircuitOutputLayout::Fixed {
            fields: PK_GENERATION_OUTPUTS,
        };
        // C1 has no pub inputs, only 3 outputs = 96 bytes total.
        let mut signals = vec![0u8; 96];
        signals[0..32].copy_from_slice(&[0x11; 32]); // sk_commitment
        signals[32..64].copy_from_slice(&[0x22; 32]); // pk_commitment
        signals[64..96].copy_from_slice(&[0x33; 32]); // e_sm_commitment

        assert_eq!(
            layout.extract_field(&signals, "sk_commitment").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            layout.extract_field(&signals, "pk_commitment").unwrap(),
            &[0x22; 32]
        );
        assert_eq!(
            layout.extract_field(&signals, "e_sm_commitment").unwrap(),
            &[0x33; 32]
        );
    }

    #[test]
    fn extract_c5_output_after_pub_inputs() {
        let layout = CircuitOutputLayout::Fixed {
            fields: PK_AGGREGATION_OUTPUTS,
        };
        // C5 has H pub input fields + 1 output. Simulate H=3 → 128 bytes total.
        let mut signals = vec![0xAA; 128]; // 3 * 32 pub inputs
        signals[96..128].copy_from_slice(&[0xFF; 32]); // 1 output at the end
        let commitment = layout.extract_field(&signals, "commitment").unwrap();
        assert_eq!(commitment, &[0xFF; 32]);
    }

    #[test]
    fn extract_nonexistent_field_returns_none() {
        let layout = CircuitOutputLayout::Fixed {
            fields: PK_BFV_OUTPUTS,
        };
        let signals = vec![0u8; 32];
        assert!(layout.extract_field(&signals, "nonexistent").is_none());
    }

    #[test]
    fn extract_from_void_circuit_returns_none() {
        let layout = CircuitOutputLayout::None;
        let signals = vec![0u8; 64];
        assert!(layout.extract_field(&signals, "anything").is_none());
    }

    #[test]
    fn signals_too_short_returns_none() {
        let layout = CircuitOutputLayout::Fixed {
            fields: PK_GENERATION_OUTPUTS,
        };
        // Need 96 bytes for 3 outputs, only 64 available
        let signals = vec![0u8; 64];
        assert!(layout.extract_field(&signals, "pk_commitment").is_none());
    }

    #[test]
    fn extract_all_c1_outputs() {
        let layout = CircuitOutputLayout::Fixed {
            fields: PK_GENERATION_OUTPUTS,
        };
        let mut signals = vec![0u8; 96];
        signals[0..32].copy_from_slice(&[0x11; 32]);
        signals[32..64].copy_from_slice(&[0x22; 32]);
        signals[64..96].copy_from_slice(&[0x33; 32]);

        let all = layout.extract_all(&signals).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, "sk_commitment");
        assert_eq!(all[1].0, "pk_commitment");
        assert_eq!(all[2].0, "e_sm_commitment");
        assert_eq!(all[1].1, &[0x22; 32]);
    }

    #[test]
    fn field_count() {
        assert_eq!(
            CircuitOutputLayout::Fixed {
                fields: PK_GENERATION_OUTPUTS
            }
            .field_count(),
            Some(3)
        );
        assert_eq!(CircuitOutputLayout::None.field_count(), Some(0));
    }

    #[test]
    fn extract_c6_d_commitment_after_pub_inputs() {
        let layout = CircuitOutputLayout::Fixed {
            fields: THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
        };
        // C6: 5 public inputs + 1 output = 192 bytes
        let mut signals = vec![0u8; 192];
        signals[0..32].copy_from_slice(&[0x11; 32]);
        signals[32..64].copy_from_slice(&[0x22; 32]);
        signals[64..96].copy_from_slice(&[0x33; 32]);
        signals[96..128].copy_from_slice(&[0x44; 32]);
        signals[128..160].copy_from_slice(&[0x55; 32]);
        signals[160..192].copy_from_slice(&[0x77; 32]);

        assert_eq!(
            layout.extract_field(&signals, "d_commitment").unwrap(),
            &[0x77; 32]
        );
    }

    // ── CircuitInputLayout tests ────────────────────────────────────────

    #[test]
    fn extract_input_field_from_head() {
        let layout = CircuitInputLayout::Fixed {
            fields: SHARE_ENCRYPTION_INPUTS,
        };
        let mut signals = vec![0u8; 128];
        signals[0..32].copy_from_slice(&[0xAA; 32]);
        signals[32..64].copy_from_slice(&[0xBB; 32]);

        assert_eq!(
            layout
                .extract_field(&signals, "expected_pk_commitment")
                .unwrap(),
            &[0xAA; 32]
        );
        assert_eq!(
            layout
                .extract_field(&signals, "expected_message_commitment")
                .unwrap(),
            &[0xBB; 32]
        );
    }

    #[test]
    fn extract_c6_public_inputs_via_input_layout() {
        let layout = CircuitInputLayout::Fixed {
            fields: THRESHOLD_SHARE_DECRYPTION_INPUTS,
        };
        let mut signals = vec![0u8; 160];
        signals[0..32].copy_from_slice(&[0x11; 32]);
        signals[32..64].copy_from_slice(&[0x22; 32]);
        signals[64..96].copy_from_slice(&[0x33; 32]);
        signals[96..128].copy_from_slice(&[0x44; 32]);
        signals[128..160].copy_from_slice(&[0x55; 32]);

        assert_eq!(
            layout
                .extract_field(&signals, "expected_sk_commitment")
                .unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            layout
                .extract_field(&signals, "expected_e_sm_commitment")
                .unwrap(),
            &[0x22; 32]
        );
        assert_eq!(
            layout.extract_field(&signals, "ct_commitment").unwrap(),
            &[0x33; 32]
        );
        assert_eq!(
            layout.extract_field(&signals, "domain_hi").unwrap(),
            &[0x44; 32]
        );
        assert_eq!(
            layout.extract_field(&signals, "domain_lo").unwrap(),
            &[0x55; 32]
        );
    }

    #[test]
    fn extract_c6_input_signals_too_short_returns_none() {
        let layout = CircuitInputLayout::Fixed {
            fields: THRESHOLD_SHARE_DECRYPTION_INPUTS,
        };
        assert!(layout.extract_field(&[0u8; 64], "ct_commitment").is_none());
    }

    #[test]
    fn input_layout_nonexistent_field_returns_none() {
        let layout = CircuitInputLayout::Fixed {
            fields: SHARE_ENCRYPTION_INPUTS,
        };
        let signals = vec![0u8; 64];
        assert!(layout.extract_field(&signals, "nonexistent").is_none());
    }

    #[test]
    fn input_layout_none_returns_none() {
        let layout = CircuitInputLayout::None;
        let signals = vec![0u8; 64];
        assert!(layout.extract_field(&signals, "anything").is_none());
    }

    #[test]
    fn input_signals_too_short_returns_none() {
        let layout = CircuitInputLayout::Fixed {
            fields: SHARE_ENCRYPTION_INPUTS,
        };
        let signals = vec![0u8; 32];
        assert!(layout
            .extract_field(&signals, "expected_message_commitment")
            .is_none());
    }

    #[test]
    fn input_field_count() {
        assert_eq!(
            CircuitInputLayout::Fixed {
                fields: SHARE_ENCRYPTION_INPUTS
            }
            .field_count(),
            Some(4)
        );
        assert_eq!(CircuitInputLayout::None.field_count(), Some(0));
    }

    #[test]
    fn lbfv_aggregation_layouts_name_exact_dynamic_ranges() {
        let pk = LbfvPkAggregationPublicLayout::new(2);
        assert_eq!(pk.expected_pk_generation_commitments, 6..8);
        assert_eq!(pk.pk_agg_commitment, 8);
        assert_eq!(pk.field_count, 9);

        let rlk = RlkAggregationPublicLayout::new(2);
        assert_eq!(rlk.expected_d0_commitments, 6..8);
        assert_eq!(rlk.expected_d2_commitments, 8..10);
        assert_eq!(rlk.d0_agg_commitment, 10);
        assert_eq!(rlk.d2_agg_commitment, 11);
        assert_eq!(rlk.field_count, 12);
    }

    #[test]
    fn dkg_aggregator_v2_layout_tracks_dynamic_commitment_position() {
        let secure_minimum = DkgAggregatorV2PublicLayout::new(2, 5);
        assert_eq!(secure_minimum.party_ids, 2..4);
        assert_eq!(secure_minimum.sk_agg_commitments, 25..27);
        assert_eq!(secure_minimum.esm_agg_commitments, 27..29);
        assert_eq!(secure_minimum.key_envelope_commitment, 29);
        assert_eq!(secure_minimum.aggregate_pk_commitments, 36..41);
        assert_eq!(secure_minimum.v2_vk_binding, 51..64);
        assert_eq!(secure_minimum.field_count, 64);

        let insecure_micro = DkgAggregatorV2PublicLayout::new(5, 3);
        assert_eq!(insecure_micro.key_envelope_commitment, 38);
        assert_eq!(insecure_micro.field_count, 67);
    }

    /// C7 (`DecryptedSharesAggregation`) has no `-> pub` return values; metadata uses `None`.
    #[test]
    fn c7_void_output_extract_field_returns_none() {
        let layout = CircuitOutputLayout::None;
        let signals = vec![0u8; 256];
        assert!(layout.extract_field(&signals, "d_commitment").is_none());
    }

    /// C7: `extract_all` yields no named outputs when the layout is void.
    #[test]
    fn c7_void_output_extract_all_returns_empty() {
        let layout = CircuitOutputLayout::None;
        let signals = vec![0u8; 256];
        let all = layout.extract_all(&signals).unwrap();
        assert!(all.is_empty());
    }
}
