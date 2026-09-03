// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fail-closed CKKS artifact resolution.
//!
//! Every CKKS proof posture is `Proven` (`CkksProofPosture`), so the
//! artifacts each posture needs MUST be staged before an E3 starts. This
//! module names them per `(param set, transport preset, committee,
//! ceremony plan)` and checks their presence under the node's circuits
//! directory, returning the EXACT missing artifact name. Consumers call it
//! at `CiphernodeSelected` and refuse the E3 (error) when anything is
//! absent — never a silent proof-free fallback. The explicit operator
//! off-switch (`CKKS_ALLOW_PROOF_FREE=1`) bypasses the check because nothing
//! is proven under it.

use e3_events::{CircuitName, CircuitVariant};
use e3_fhe_params::ckks_presets::{relin_ceremony_plan_for_param_set, CkksProofPosture};
use e3_fhe_params::BfvPreset;
use std::path::{Path, PathBuf};

/// One required artifact: which circuit, under which artifacts directory
/// (`<preset>/<committee>`), in which variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredArtifact {
    pub circuit: CircuitName,
    pub artifacts_dir: String,
    pub variant: CircuitVariant,
    /// Which posture this artifact serves (log/error text).
    pub role: &'static str,
}

impl RequiredArtifact {
    /// `<circuits_dir>/<artifacts_dir>/<variant>/<group>/<name>/<name>.{json,vk}`.
    pub fn paths(&self, circuits_dir: &Path) -> (PathBuf, PathBuf) {
        let dir = circuits_dir
            .join(&self.artifacts_dir)
            .join(self.variant.as_str())
            .join(self.circuit.dir_path());
        (
            dir.join(format!("{}.json", self.circuit.as_str())),
            dir.join(format!("{}.vk", self.circuit.as_str())),
        )
    }
}

/// The artifacts a CKKS E3 with `posture` needs, in the order the
/// protocol consumes them: C0 (transport keys), C1 (pk shares), C8 (only
/// when a hybrid ceremony runs), C6, C7. `threshold_preset` is the E3's
/// on-chain (threshold) preset; the transport preset comes from the
/// posture.
pub fn required_ckks_artifacts(
    posture: &CkksProofPosture,
    threshold_preset: BfvPreset,
    committee: &str,
) -> anyhow::Result<Vec<RequiredArtifact>> {
    let set = posture.param_set;
    let transport_dir = posture.transport.artifacts_dir_for_committee(committee);
    let threshold_dir = threshold_preset.artifacts_dir_for_committee(committee);
    let missing_name = |what: &str| {
        anyhow::anyhow!("no {what} circuit is registered for CKKS on-chain ParamSet {set}")
    };
    let mut out = vec![
        RequiredArtifact {
            circuit: CircuitName::PkBfv,
            artifacts_dir: transport_dir.clone(),
            variant: CircuitVariant::Recursive,
            role: "C0 (transport key)",
        },
        RequiredArtifact {
            circuit: CircuitName::pk_generation_ckks(set).ok_or_else(|| missing_name("C1-CKKS"))?,
            artifacts_dir: threshold_dir.clone(),
            variant: CircuitVariant::Recursive,
            role: "C1-CKKS (pk share)",
        },
    ];
    if relin_ceremony_plan_for_param_set(set)?.is_hybrid() {
        out.push(RequiredArtifact {
            circuit: CircuitName::RelinRound1HybridCkksDigit,
            artifacts_dir: threshold_dir.clone(),
            variant: CircuitVariant::Recursive,
            role: "C8-CKKS (relin round-1 digit)",
        });
    }
    out.push(RequiredArtifact {
        circuit: CircuitName::share_decryption_ckks(set).ok_or_else(|| missing_name("C6-CKKS"))?,
        artifacts_dir: threshold_dir.clone(),
        variant: CircuitVariant::Recursive,
        role: "C6-CKKS (decryption share)",
    });
    out.push(RequiredArtifact {
        circuit: CircuitName::decrypted_shares_aggregation_ckks(set)
            .ok_or_else(|| missing_name("C7-CKKS"))?,
        artifacts_dir: threshold_dir,
        variant: CircuitVariant::Default,
        role: "C7-CKKS (aggregation)",
    });
    Ok(out)
}

/// The required artifacts that are NOT present under `circuits_dir`
/// (`.json` + `.vk` both required). Empty means fully staged.
pub fn missing_ckks_artifacts(
    circuits_dir: &Path,
    required: &[RequiredArtifact],
) -> Vec<(RequiredArtifact, PathBuf)> {
    required
        .iter()
        .filter_map(|r| {
            let (json, vk) = r.paths(circuits_dir);
            if !json.exists() {
                Some((r.clone(), json))
            } else if !vk.exists() {
                Some((r.clone(), vk))
            } else {
                None
            }
        })
        .collect()
}

/// Fail-closed gate: `Ok(())` when every artifact the posture needs is
/// staged, else an error naming EVERY missing artifact (circuit name,
/// role, expected path). Under the explicit off-switch nothing is
/// required and `Ok(())` is returned.
pub fn check_ckks_artifacts(
    circuits_dir: &Path,
    posture: &CkksProofPosture,
    threshold_preset: BfvPreset,
    committee: &str,
) -> anyhow::Result<()> {
    if posture.is_proof_free_override() {
        return Ok(());
    }
    let required = required_ckks_artifacts(posture, threshold_preset, committee)?;
    let missing = missing_ckks_artifacts(circuits_dir, &required);
    if missing.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = missing
        .iter()
        .map(|(r, path)| {
            format!(
                "  - {} `{}` ({}) expected at {}",
                r.role,
                r.circuit.as_str(),
                r.variant,
                path.display()
            )
        })
        .collect();
    anyhow::bail!(
        "CKKS proof posture for ParamSet {} is PROVEN but {} required artifact(s) are missing \
         under {} — refusing the E3 (fail closed; stage the circuits or set {}=1 explicitly):\n{}",
        posture.param_set,
        missing.len(),
        circuits_dir.display(),
        e3_fhe_params::ckks_presets::CKKS_ALLOW_PROOF_FREE_ENV,
        lines.join("\n")
    )
}

/// Fail-closed gate for one E3, resolved from the facts every consumer
/// already holds: the E3's threshold preset, its encoded CKKS params, and
/// its committee shape. Computes the posture (with the explicit
/// off-switch applied), then [`check_ckks_artifacts`]. Callers pass
/// `circuits_dir = None` when the process has no circuits directory
/// (in-process tests without a ZK backend), which skips ONLY the
/// presence check — the posture itself is still derived and returned.
pub fn check_ckks_artifacts_for_e3(
    circuits_dir: Option<&Path>,
    threshold_preset: BfvPreset,
    ckks_params_bytes: &[u8],
    threshold_m: usize,
    threshold_n: usize,
) -> anyhow::Result<CkksProofPosture> {
    let standard = threshold_preset
        .dkg_counterpart()
        .unwrap_or(threshold_preset);
    let posture = CkksProofPosture::from_bytes(standard, ckks_params_bytes)?;
    let committee =
        e3_zk_helpers::CiphernodesCommitteeSize::from_threshold(threshold_m, threshold_n)?;
    if let Some(dir) = circuits_dir {
        check_ckks_artifacts(dir, &posture, threshold_preset, committee.as_str())?;
    }
    Ok(posture)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::ckks_presets::{
        ckks_dkg_transport_preset, ckks_params_for_on_chain_param_set,
    };

    fn posture(set: u8) -> CkksProofPosture {
        let params = ckks_params_for_on_chain_param_set(set).unwrap();
        let transport =
            ckks_dkg_transport_preset(BfvPreset::InsecureDkg512, params.moduli()).unwrap();
        CkksProofPosture::new(set, transport)
    }

    fn stage(dir: &Path, r: &RequiredArtifact) {
        let (json, vk) = r.paths(dir);
        std::fs::create_dir_all(json.parent().unwrap()).unwrap();
        std::fs::write(&json, b"{}").unwrap();
        std::fs::write(&vk, b"vk").unwrap();
    }

    /// Set 2 (wide transport, hybrid ceremony) needs C0 under the WIDE
    /// directory, per-set C1/C6/C7 and the C8 digit circuit; set 3
    /// (standard transport, per-level ceremony) needs no C8.
    #[test]
    fn required_artifacts_follow_param_set_transport_and_plan() {
        let req2 =
            required_ckks_artifacts(&posture(2), BfvPreset::InsecureThreshold512, "micro").unwrap();
        let names: Vec<(&str, &str)> = req2
            .iter()
            .map(|r| (r.circuit.as_str(), r.artifacts_dir.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("pk", "insecure-dkg-wide-512/micro"),
                ("pk_generation_ckks_ps2", "insecure-512/micro"),
                ("relin_round1_hybrid_ckks_digit", "insecure-512/micro"),
                ("share_decryption_ckks_ps2", "insecure-512/micro"),
                (
                    "decrypted_shares_aggregation_ckks_ps2",
                    "insecure-512/micro"
                ),
            ]
        );
        let req3 =
            required_ckks_artifacts(&posture(3), BfvPreset::InsecureThreshold512, "micro").unwrap();
        assert!(req3
            .iter()
            .all(|r| r.circuit != CircuitName::RelinRound1HybridCkksDigit));
        assert!(req3
            .iter()
            .any(|r| r.circuit.as_str() == "pk" && r.artifacts_dir == "insecure-512/micro"));
        let req0 =
            required_ckks_artifacts(&posture(0), BfvPreset::InsecureThreshold512, "micro").unwrap();
        assert!(req0
            .iter()
            .any(|r| r.circuit == CircuitName::ThresholdShareDecryptionCkks));
    }

    /// Missing artifacts fail closed with the exact name; staging them all
    /// passes; the explicit off-switch bypasses the gate.
    #[test]
    fn check_fails_closed_naming_the_missing_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let p = posture(2);
        let err = check_ckks_artifacts(tmp.path(), &p, BfvPreset::InsecureThreshold512, "micro")
            .unwrap_err()
            .to_string();
        assert!(err.contains("fail closed"), "{err}");
        assert!(err.contains("pk_generation_ckks_ps2"), "{err}");
        assert!(err.contains("relin_round1_hybrid_ckks_digit"), "{err}");
        assert!(err.contains("insecure-dkg-wide-512/micro"), "{err}");

        let required =
            required_ckks_artifacts(&p, BfvPreset::InsecureThreshold512, "micro").unwrap();
        for (i, r) in required.iter().enumerate() {
            stage(tmp.path(), r);
            let result =
                check_ckks_artifacts(tmp.path(), &p, BfvPreset::InsecureThreshold512, "micro");
            if i + 1 < required.len() {
                let err = result.unwrap_err().to_string();
                // A staged artifact no longer appears (match the exact
                // backticked name: `pk` is a prefix of `pk_generation_…`).
                assert!(!err.contains(&format!("`{}`", r.circuit.as_str())), "{err}");
                assert!(
                    err.contains(&format!("`{}`", required[i + 1].circuit.as_str())),
                    "{err}"
                );
            } else {
                result.unwrap();
            }
        }
        // A vk-less circuit is still missing.
        let (_, vk) = required[1].paths(tmp.path());
        std::fs::remove_file(&vk).unwrap();
        let err = check_ckks_artifacts(tmp.path(), &p, BfvPreset::InsecureThreshold512, "micro")
            .unwrap_err()
            .to_string();
        assert!(err.contains("pk_generation_ckks_ps2.vk"), "{err}");

        // Off-switch: nothing required.
        let off = p.with_proof_free_override(true);
        check_ckks_artifacts(
            tempfile::tempdir().unwrap().path(),
            &off,
            BfvPreset::InsecureThreshold512,
            "micro",
        )
        .unwrap();
    }
}
