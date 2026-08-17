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
    /// Number of fixed output fields. Void layouts report `Some(0)`, because no arm
    /// returns `None`.
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
            CircuitOutputLayout::None => None,
        }
    }

    /// Extract a named output field from raw `public_signals` bytes.
    ///
    /// Return values sit at the **end** of `public_signals`, after any
    /// `pub` input parameters. This method indexes from the tail.
    pub fn extract_field<'a>(&self, public_signals: &'a [u8], name: &str) -> Option<&'a [u8]> {
        let fields = match self {
            CircuitOutputLayout::Fixed { fields } => fields,
            CircuitOutputLayout::None => return None,
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

/// C4 — DKG share decryption.
pub const DKG_SHARE_DECRYPTION_OUTPUTS: &[OutputField] = &[f("commitment")];

/// C5 — Public key aggregation.
pub const PK_AGGREGATION_OUTPUTS: &[OutputField] = &[f("commitment")];

/// C6 — Threshold share decryption (prefix commitment to `d`, per CRT limb).
pub const THRESHOLD_SHARE_DECRYPTION_OUTPUTS: &[OutputField] = &[f("d_commitment")];

// ── Per-circuit input field constants ───────────────────────────────────────

/// C3 — Share encryption public inputs (at HEAD of `public_signals`).
pub const SHARE_ENCRYPTION_INPUTS: &[OutputField] = &[
    f("expected_pk_commitment"),
    f("expected_message_commitment"),
    f("party_idx"),
    f("mod_idx"),
];

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
        // C1 has no pub inputs, only 3 outputs = 96 bytes total
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
