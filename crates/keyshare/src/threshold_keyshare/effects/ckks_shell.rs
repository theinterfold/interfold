// SPDX-License-Identifier: LGPL-3.0-only

//! CKKS branch of the ThresholdKeyshare actor (the actor-shell splice).
//!
//! When `state.scheme == E3Scheme::Ckks`, the BFV handlers delegate here.
//! This shell owns a [`CkksRuntime`] (fhe adaptor + pure state machine) and
//! does exactly three things per event: feed the machine, persist the
//! machine snapshot into the recovery record, translate emitted commands
//! into the SAME bus events the BFV flow publishes (`EncryptionKeyPending`,
//! `ThresholdShareCreated`, `KeyshareCreated`, `DecryptionshareCreated`,
//! plus `RelinCeremonyShare` for the ceremony). All crypto and validation
//! live in the machine and its modules; the C2 proof gate
//! (`proofs::verify_ckks_share_witnesses`) runs before the dealt-share
//! broadcast, so an invalid dealing never reaches the wire.
//!
//! Everything committee-wide is derived from the E3's own parameters —
//! never from configuration: the relin-ceremony plan
//! (`relin_ceremony_plan_for_param_set`: hybrid single-key for ParamSet 2,
//! per-level for ParamSet 3), DKG transport preset, chunk bounds,
//! and the proof posture ([`CkksProofPosture`], logged once at
//! `CiphernodeSelected` and consulted for C6). The only node-local input
//! is WHERE the joint relin keys land on disk (`ckks_artifacts_dir`,
//! derived from the node's data dir by the builder; `CKKS_RELIN_KEY_DIR`
//! overrides it for tooling): `rlk_hybrid.bin` for a hybrid ceremony,
//! `rlk_level_{L}.bin` per level otherwise.
//!
//! PARTY-ID BASES: bus events and `ThresholdKeyshareState` carry the
//! 0-based on-chain committee slot (`party_id_chain`); the machine speaks
//! 1-based Shamir x-coordinates (`party_id_machine`). Conversion happens
//! ONLY through [`party_id_machine`] / [`party_id_chain`] in this file.
//!
//! HONEST SCOPE: C3a/C3b proof emission is not wired for CKKS (slots
//! travel empty; witnesses exist).

use super::*;
use crate::threshold_keyshare_ckks::machine::{
    CkksC1Witness, CkksC8Witness, CkksCommand, CkksKeyshareMachine, CkksPhase, CkksProgress,
    RelinChunkBounds, RelinProofGate, RelinShareChunk, CKKS_RELIN_CHUNK_BYTES, HYBRID_RELIN_LEVEL,
};
use crate::threshold_keyshare_ckks::proofs::verify_ckks_share_witnesses;
use crate::threshold_keyshare_ckks::timing::{CkksTimeline, Detail};
use e3_events::{
    DecryptionshareCreated, E3id, KeyshareCreated, PartyProofsToVerify,
    PkGenerationCkksProofPending, PkGenerationCkksProofRequest, RelinCeremonyProofSigned,
    RelinCeremonyShare, RelinRound1CkksProofRequest, RelinRound1ProofPending,
    ShareDecryptionProofPending, ThresholdShareDecryptionProofRequest,
};
use e3_fhe::{CkksFhe, SchemeParams};
use e3_fhe_params::ckks_presets::{
    relin_ceremony_plan_for_param_set, relin_plan_matches_params, CkksProofPosture, ProofPosture,
};
use e3_fhe_params::BfvParamSet;
use e3_trbfv::helpers::deserialize_secret_key;
use e3_zk_helpers::threshold::user_data_encryption_ckks::CkksPreset;
use rand::rngs::OsRng;
use rand_core::UnwrapErr;
use std::path::{Path, PathBuf};

/// Demo-grade smudging bits for the insecure preset; production derives
/// this via `fhe::trckks::CkksSmudgingBoundCalculator` per E3 circuit.
const CKKS_SMUDGING_BITS: usize = 20;

/// Environment override for the joint relin-key output directory
/// (tooling only; the node default derives from its data dir).
pub const CKKS_RELIN_KEY_DIR_ENV: &str = "CKKS_RELIN_KEY_DIR";

/// Subdirectory of the CKKS artifacts dir holding joint relin keys.
pub const RELIN_KEYS_SUBDIR: &str = "relin-keys";

/// File name of the ONE joint key a hybrid ceremony writes.
pub const HYBRID_RELIN_KEY_FILE: &str = "rlk_hybrid.bin";

/// File name of the joint key for `level` (per-level ceremony), or the
/// hybrid key file for the hybrid slot.
pub fn relin_key_file_name(level: usize) -> String {
    if level == HYBRID_RELIN_LEVEL {
        HYBRID_RELIN_KEY_FILE.to_string()
    } else {
        format!("rlk_level_{level}.bin")
    }
}

/// Convert an on-chain committee slot (0-based) to the machine's Shamir
/// id (1-based). The only place this arithmetic lives.
pub(crate) fn party_id_machine(party_id_chain: u64) -> u64 {
    party_id_chain + 1
}

/// Convert a machine Shamir id (1-based) back to the on-chain committee
/// slot (0-based). Errors on 0, which no dealing can carry.
pub(crate) fn party_id_chain(party_id_machine: u64) -> Result<u64> {
    party_id_machine
        .checked_sub(1)
        .ok_or_else(|| anyhow!("machine party id 0 is not a Shamir coordinate"))
}

/// Resolve the directory joint relin keys are written to for `e3_id`:
/// `$CKKS_RELIN_KEY_DIR/<e3_id>` when the override is set, else
/// `<artifacts_dir>/relin-keys/<e3_id>`, else `None` (no persistent data
/// dir — in-process tests).
pub(crate) fn relin_key_dir(artifacts_dir: Option<&Path>, e3_id: &E3id) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(CKKS_RELIN_KEY_DIR_ENV) {
        if !dir.is_empty() {
            return Some(Path::new(&dir).join(e3_id.to_string()));
        }
    }
    artifacts_dir.map(|d| d.join(RELIN_KEYS_SUBDIR).join(e3_id.to_string()))
}

/// Process-local CKKS runtime rebuilt on start/hydrate (never persisted:
/// contains the fhe adaptor; the MACHINE is what snapshots).
pub(crate) struct CkksRuntime {
    /// CKKS fhe adaptor for this E3's parameters and committee shape.
    pub fhe: CkksFhe,
    /// The pure phase machine (snapshotted after every transition).
    pub machine: CkksKeyshareMachine,
    /// This node's ephemeral BFV keypair (share transport decryption).
    pub sk_bfv: SensitiveBytes,
    /// Serialized ephemeral BFV public key (announced to the committee).
    pub pk_bfv: ArcBytes,
    /// Proof posture for this E3 (deterministic from its params).
    pub posture: CkksProofPosture,
    /// Timing marks (process-local).
    pub timeline: CkksTimeline,
}

impl ThresholdKeyshare {
    /// Build the CKKS runtime at CiphernodeSelected (or rebuild on
    /// hydrate from a persisted machine snapshot; `origin` names which).
    pub(crate) fn init_ckks_runtime(
        &mut self,
        selected: &CiphernodeSelected,
        machine: Option<CkksKeyshareMachine>,
        origin: &'static str,
    ) -> Result<()> {
        let SchemeParams::Ckks(params) = SchemeParams::from_encoded(&selected.params)? else {
            bail!("init_ckks_runtime called for non-CKKS params");
        };
        let n_parties = selected.threshold_n;
        let threshold = selected.threshold_m;
        // CRP from the E3's public seed: all nodes derive the same one.
        let seed: [u8; 32] = selected.seed.into();
        // SECRET sampling rng: OS entropy, NEVER the public E3 seed — this
        // rng samples the party's secret-key contribution and smudging
        // noise inside `generate_keyshare`. Seeding it from the public
        // seed would make every node's "secret" identical and publicly
        // recomputable. Only the CRP below derives from the public seed.
        let mut secret_seed = [0u8; 32];
        rand_core::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut secret_seed)
            .map_err(|e| anyhow!("OS entropy unavailable: {e}"))?;
        let rng = std::sync::Arc::new(std::sync::Mutex::new(
            <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(secret_seed),
        ));
        let fhe = CkksFhe::from_encoded(&selected.params, seed, n_parties, threshold, rng)?;
        let BfvKeypairMaterial { sk_bfv, pk_bfv } =
            generate_bfv_keypair(&self.share_enc_preset, &self.cipher)?;

        // Committee-wide facts, derived from the params bytes every node
        // received on-chain: the param set, its relin levels, the proof
        // posture, and the chunk-transport bounds.
        // FAIL CLOSED: the posture is PROVEN for every known param set,
        // and every circuit artifact it needs must be staged under the
        // node's circuits directory — a missing one refuses the E3 here,
        // naming the artifact (never a silent proof-free fallback; the
        // only proof-free path is the explicit `CKKS_ALLOW_PROOF_FREE=1`).
        let posture = e3_zk_prover::ckks_artifacts::check_ckks_artifacts_for_e3(
            self.zk_circuits_dir.as_deref(),
            selected.params_preset,
            &selected.params,
            threshold,
            n_parties,
        )
        .map_err(|e| {
            anyhow!(
                "CKKS E3 {} refused at CiphernodeSelected: {e}",
                selected.e3_id
            )
        })?;
        if posture.transport != self.share_enc_preset {
            bail!(
                "CKKS E3 {}: share transport preset {} disagrees with the posture's {}",
                selected.e3_id,
                self.share_enc_preset.name(),
                posture.transport.name()
            );
        }
        let plan = relin_ceremony_plan_for_param_set(posture.param_set)?;
        if !relin_plan_matches_params(&plan, &params) {
            bail!(
                "CKKS E3 {}: ceremony plan {plan:?} for param set {} disagrees with the params \
                 bytes (hybrid_enabled = {}) — version skew",
                selected.e3_id,
                posture.param_set,
                params.hybrid_enabled()
            );
        }
        let bounds = RelinChunkBounds::for_params(&params, CKKS_RELIN_CHUNK_BYTES);

        let machine = machine.unwrap_or_else(|| {
            CkksKeyshareMachine::with_relin_plan(
                party_id_machine(selected.party_id),
                n_parties,
                threshold,
                &plan,
                seed,
            )
        });
        if machine.relin_plan() != plan {
            bail!(
                "CKKS E3 {}: persisted machine ceremony plan {:?} disagrees with the param set's {:?}",
                selected.e3_id,
                machine.relin_plan(),
                plan
            );
        }
        // C8 gate: hybrid plan + proven ceremony posture => every party's
        // digit proofs are verified before its R1 share is aggregated.
        let gate = if plan.is_hybrid() && !posture.ceremony.is_proof_free() {
            RelinProofGate::Required
        } else {
            RelinProofGate::Off
        };
        let machine = machine
            .with_relin_bounds(bounds)
            .with_relin_proof_gate(gate);
        let timeline = CkksTimeline::start(selected.e3_id.to_string(), selected.party_id, origin);
        info!(
            e3_id = %selected.e3_id,
            party_id_chain = selected.party_id,
            relin_plan = ?plan,
            c8_gate = ?gate,
            special_moduli = params.special_moduli().len(),
            dnum = params.dnum(),
            max_relin_chunks = ?bounds.max_chunk_count,
            "CKKS proof posture: {}",
            posture.summary()
        );
        self.ckks = Some(CkksRuntime {
            fhe,
            machine,
            sk_bfv,
            pk_bfv,
            posture,
            timeline,
        });
        Ok(())
    }

    /// CKKS branch of CiphernodeSelected: announce our ephemeral key.
    pub(crate) fn ckks_handle_ciphernode_selected(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        self.init_ckks_runtime(&msg, None, "selected")?;
        // The recovery record's `ciphernode_selected` is what a restart
        // rebuilds the runtime from (`ext.rs` seeds it at construction;
        // pin it here too so every construction path agrees).
        let selected_event = TypedEvent::new(msg.clone(), ec.clone());
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.ciphernode_selected = Some(selected_event.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        let runtime = self.ckks.as_mut().expect("just initialized");
        runtime.timeline.mark("dkg.selected");
        let pk_bfv = runtime.pk_bfv.clone();
        let state = self.state.try_get()?;
        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        self.bus.publish(
            EncryptionKeyPending {
                e3_id: state.e3_id.clone(),
                key: Arc::new(EncryptionKey::new(state.party_id, pk_bfv.clone())),
                params_preset: self.share_enc_preset,
                committee_size,
            },
            ec.clone(),
        )?;
        // Feed our own key into the machine directly: the C0-verified
        // EncryptionKeyCreated broadcast only delivers PEERS' keys (no
        // self-delivery on the real network), and the machine needs all N.
        // If the network DOES loop our key back, on_encryption_key is
        // idempotent and ignores the duplicate.
        let own_key = EncryptionKey::new(state.party_id, pk_bfv);
        self.ckks_handle_encryption_key(&own_key, ec)?;
        Ok(())
    }

    /// CKKS branch of EncryptionKeyCreated: feed the machine; on
    /// completion the machine deals + we gate on C2 before broadcasting.
    pub(crate) fn ckks_handle_encryption_key(
        &mut self,
        key: &EncryptionKey,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let share_enc_params = BfvParamSet::from(self.share_enc_preset).build_arc();
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let ckks_params = runtime.fhe.params.clone();
        let mut rng = UnwrapErr(OsRng);
        // The Nth key triggers keyshare generation + Shamir dealing inside
        // `on_encryption_key`; time it only when it actually dealt.
        let started = std::time::Instant::now();
        let (machine, fhe) = (&mut runtime.machine, &runtime.fhe);
        let commands = machine.on_encryption_key(
            party_id_machine(key.party_id),
            key.pk_bfv.clone(),
            fhe,
            &share_enc_params,
            ckks_params.moduli(),
            CKKS_SMUDGING_BITS,
            &mut rng,
        )?;
        // C2 proof gate: before the dealt broadcast leaves this node, its
        // material must satisfy every C2a/C2b circuit constraint.
        if commands
            .iter()
            .any(|c| matches!(c, CkksCommand::PublishThresholdShare { .. }))
        {
            runtime.timeline.mark_with(
                "dkg.encryption_keys_collected",
                Detail::count(state.threshold_n as usize),
            );
            runtime.timeline.record_span(
                "dkg.threshold_share_generated",
                Detail::count(state.threshold_n as usize),
                started.elapsed(),
            );
            if let CkksPhase::CollectingThresholdShares { material, .. } = &runtime.machine.phase {
                let preset = CkksPreset {
                    params: ckks_params.clone(),
                    input_bound: 100.0,
                };
                let (n, t, cipher) = (
                    state.threshold_n as usize,
                    state.threshold_m as usize,
                    self.cipher.clone(),
                );
                runtime
                    .timeline
                    .span("dkg.c2_share_gate", Detail::default(), || {
                        verify_ckks_share_witnesses(&preset, material, n, t, &cipher)
                    })?;
            }
        }
        self.ckks_dispatch_commands(commands, &state, ec)
    }

    /// CKKS branch of ThresholdShareCreated.
    pub(crate) fn ckks_handle_threshold_share(
        &mut self,
        share: Arc<ThresholdShare>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let share_enc_params = BfvParamSet::from(self.share_enc_preset).build_arc();
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let sk_bytes = runtime.sk_bfv.access(&self.cipher)?;
        let sk = deserialize_secret_key(&sk_bytes, &share_enc_params)?;
        let started = std::time::Instant::now();
        let commands =
            runtime
                .machine
                .on_threshold_share(share, &runtime.fhe, &sk, &share_enc_params)?;
        if commands
            .iter()
            .any(|c| matches!(c, CkksCommand::PublishKeyshareCreated { .. }))
        {
            runtime.timeline.mark_with(
                "dkg.threshold_shares_collected",
                Detail::count(state.threshold_n as usize),
            );
            runtime
                .timeline
                .record_span("dkg.finalized", Detail::default(), started.elapsed());
        }
        self.ckks_dispatch_commands(commands, &state, ec.clone())?;
        // pk consensus may have been confirmed BEFORE our DKG finished
        // (or before a restart): release round 1 now that we can.
        self.ckks_release_relin_round_1_if_pending(ec)
    }

    /// CKKS branch of CiphertextOutputPublished.
    pub(crate) fn ckks_handle_ciphertext_output(
        &mut self,
        msg: &CiphertextOutputPublished,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let output = msg
            .ciphertext_output
            .first()
            .ok_or_else(|| anyhow!("empty ciphertext output"))?;
        let (machine, fhe, timeline) = (&mut runtime.machine, &runtime.fhe, &mut runtime.timeline);
        let commands = timeline.span(
            "decrypt.share_generated",
            Detail {
                bytes: Some(output.size()),
                ..Detail::default()
            },
            || machine.on_ciphertext_output(output, fhe),
        )?;
        self.ckks_dispatch_commands(commands, &state, ec)
    }

    /// Translate machine commands into the bus events the network expects.
    fn ckks_dispatch_commands(
        &mut self,
        commands: Vec<CkksCommand>,
        state: &ThresholdKeyshareState,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        for cmd in commands {
            match cmd {
                CkksCommand::PublishEncryptionKey { .. } => {
                    // Emitted only by init; handled in ciphernode_selected.
                }
                CkksCommand::PublishThresholdShare { share } => {
                    // The network layer delivers ThresholdShareCreated ONLY
                    // to `Filter::Item(target_party_id)` (see
                    // net/event_conversion). The CKKS dealt broadcast must
                    // reach EVERY peer (rows are per-recipient encrypted
                    // inside), so publish one copy per recipient, keyed by
                    // their CHAIN party id (0-based). Our own machine feeds
                    // itself directly, so no self-copy is needed — but the
                    // local bus loops all copies back and the machine
                    // ignores duplicates.
                    let share = Arc::new(*share);
                    for target_party_id_chain in 0..state.threshold_n {
                        if target_party_id_chain == state.party_id {
                            continue;
                        }
                        self.bus.publish(
                            ThresholdShareCreated {
                                e3_id: state.e3_id.clone(),
                                share: share.clone(),
                                target_party_id: target_party_id_chain,
                                external: false,
                                signed_c2a_proof: None,
                                signed_c2b_proof: None,
                                signed_c3a_proofs: Vec::new(),
                                signed_c3b_proofs: Vec::new(),
                            },
                            ec.clone(),
                        )?;
                    }
                    self.ckks_mark("dkg.threshold_share_published", Detail::default());
                }
                CkksCommand::PublishKeyshareCreated {
                    pk_share,
                    c1_witness,
                } => {
                    self.ckks_publish_keyshare_created(pk_share, c1_witness, state, &ec)?;
                }
                CkksCommand::PublishDecryptionShare { share, ciphertext } => {
                    self.ckks_publish_decryption_share(share, ciphertext, state, &ec)?;
                }
                CkksCommand::PublishRelinRound1 { chunks, c8_witness } => {
                    let n = chunks.len();
                    self.ckks_publish_relin_round(1, chunks, state, &ec)?;
                    self.ckks_mark("ceremony.r1_published", Detail::count(n));
                    if let Some(witness) = c8_witness {
                        self.ckks_request_relin_round1_proofs(witness, state, &ec)?;
                    }
                }
                CkksCommand::PublishRelinRound2 { chunks } => {
                    let n = chunks.len();
                    self.ckks_publish_relin_round(2, chunks, state, &ec)?;
                    self.ckks_mark("ceremony.r2_published", Detail::count(n));
                }
                CkksCommand::RelinKeysReady { keys } => {
                    self.ckks_write_relin_keys(&keys, state)?;
                    // The chunk log has served its purpose.
                    if let Some(ceremony) = self.ckks_ceremony.as_mut() {
                        ceremony.log.clear(&ec)?;
                    }
                }
                CkksCommand::VerifyRelinRound1Proofs { bundles } => {
                    self.ckks_dispatch_relin_round1_verification(bundles, state, &ec)?;
                }
                CkksCommand::RelinCeremonyFailed { party_id, reason } => {
                    error!(
                        e3_id = %state.e3_id,
                        party_id_machine = party_id,
                        "CKKS relin ceremony FAILED (C8 gate): {reason}"
                    );
                    self.bus.publish(
                        E3Failed {
                            e3_id: state.e3_id.clone(),
                            failed_at_stage: E3Stage::CommitteeFinalized,
                            reason: FailureReason::DKGInvalidShares,
                        },
                        ec.clone(),
                    )?;
                }
            }
        }
        // Persist the machine snapshot for restart recovery.
        let snapshot = self
            .ckks
            .as_ref()
            .map(|r| bincode::serialize(&r.machine))
            .transpose()?;
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.ckks_machine = snapshot.clone();
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        Ok(())
    }

    /// The preset whose artifact directory holds the per-param-set CKKS
    /// circuits (C1/C6/C7/C8): the THRESHOLD preset (`insecure-512/...`),
    /// never the share-transport preset — a WIDE transport E3 still proves
    /// its CKKS circuits under the threshold directory
    /// (`e3_zk_prover::ckks_artifacts::required_ckks_artifacts`). Only C0
    /// (the transport key) resolves under the transport preset's own dir.
    /// The aggregator's `ShareVerificationDispatched.params_preset` is the
    /// same threshold preset, so prover and verifier agree.
    fn ckks_proof_artifacts_preset(&self) -> e3_fhe_params::BfvPreset {
        self.share_enc_preset
            .threshold_counterpart()
            .unwrap_or(self.share_enc_preset)
    }

    /// Record a timing mark on the runtime's timeline (no-op without a
    /// runtime).
    fn ckks_mark(&mut self, phase: &'static str, detail: Detail) {
        if let Some(runtime) = self.ckks.as_mut() {
            runtime.timeline.mark_with(phase, detail);
        }
    }

    /// CKKS branch of `KeyshareCreated` (own loopback and peers'): record
    /// the party's C1-CKKS sk commitment as the C8 `s_commitment` anchor.
    /// A proof-less event records nothing (the aggregator's rogue-key gate
    /// already fails such an E3; the C8 gate fails attributably on the
    /// missing anchor should the ceremony ever start).
    pub(crate) fn ckks_handle_keyshare_created(
        &mut self,
        msg: &KeyshareCreated,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(runtime) = self.ckks.as_mut() else {
            return Ok(());
        };
        if runtime.machine.relin_proof_gate != RelinProofGate::Required {
            return Ok(());
        }
        let Some(signed) = msg.signed_pk_generation_proof.as_ref() else {
            warn!(
                e3_id = %msg.e3_id,
                party_id_chain = msg.party_id,
                "KeyshareCreated carries no C1-CKKS proof — no C8 anchor recorded for this party"
            );
            return Ok(());
        };
        // Field 0 of the C1 output layout is the sk commitment.
        let sk_field = e3_zk_helpers::PK_GENERATION_OUTPUTS[0].name;
        let Some(bytes) = signed.payload.proof.extract_output(sk_field) else {
            warn!(
                e3_id = %msg.e3_id,
                party_id_chain = msg.party_id,
                "KeyshareCreated proof has no sk commitment output — no C8 anchor recorded"
            );
            return Ok(());
        };
        let mut anchor = [0u8; 32];
        if bytes.len() != 32 {
            bail!("C1-CKKS sk commitment output is not 32 bytes");
        }
        anchor.copy_from_slice(&bytes[..]);
        runtime
            .machine
            .on_c1_sk_commitment(party_id_machine(msg.party_id), anchor)?;
        let state = self.state.try_get()?;
        self.ckks_dispatch_commands(Vec::new(), &state, ec)
    }

    /// CKKS branch of `RelinCeremonyProofSigned` (own loopback and peers'):
    /// feed the party's signed C8 digit-proof bundle into the machine's
    /// gate.
    pub(crate) fn ckks_handle_relin_ceremony_proofs(
        &mut self,
        msg: &RelinCeremonyProofSigned,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let sender_chain = party_id_chain(msg.party_id)?;
        if sender_chain >= state.threshold_n {
            bail!(
                "RelinCeremonyProofSigned from machine party {} is outside the {}-member committee",
                msg.party_id,
                state.threshold_n
            );
        }
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let (machine, fhe) = (&mut runtime.machine, &runtime.fhe);
        let commands = machine.on_relin_round_1_proofs(
            msg.party_id,
            msg.round,
            msg.level as usize,
            msg.signed_proofs.clone(),
            fhe,
        )?;
        self.ckks_dispatch_commands(commands, &state, ec)
    }

    /// Dispatch every party's C8 bundle for Honk verification through the
    /// scheme-agnostic ShareVerificationActor round (same path as C1/C6).
    fn ckks_dispatch_relin_round1_verification(
        &mut self,
        bundles: Vec<(u64, Vec<SignedProofPayload>)>,
        state: &ThresholdKeyshareState,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        // The verifier keys signers by the 0-based committee slot.
        let share_proofs = bundles
            .into_iter()
            .map(|(party_machine, signed_proofs)| {
                Ok(PartyProofsToVerify {
                    sender_party_id: party_id_chain(party_machine)?,
                    signed_proofs,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        info!(
            e3_id = %state.e3_id,
            parties = share_proofs.len(),
            digits = share_proofs.first().map(|p| p.signed_proofs.len()).unwrap_or(0),
            "C8-CKKS bindings hold for every party — dispatching digit proofs for Honk verification"
        );
        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: state.e3_id.clone(),
                kind: VerificationKind::RelinRound1Proofs,
                share_proofs,
                decryption_proofs: Vec::new(),
                pre_dishonest: std::collections::BTreeSet::new(),
                params_preset: self.ckks_proof_artifacts_preset(),
                committee_size,
            },
            ec.clone(),
        )?;
        self.ckks_mark("ceremony.c8_verification_dispatched", Detail::default());
        Ok(())
    }

    /// CKKS branch of `ShareVerificationComplete { kind: RelinRound1Proofs }`:
    /// open (or fail) the C8 gate.
    pub(crate) fn ckks_handle_relin_round1_verification_complete(
        &mut self,
        dishonest_chain: &std::collections::BTreeSet<u64>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let dishonest: std::collections::BTreeSet<u64> = dishonest_chain
            .iter()
            .map(|c| party_id_machine(*c))
            .collect();
        if dishonest.is_empty() {
            info!(
                e3_id = %state.e3_id,
                "C8-CKKS digit proofs verified for every party — relin round 1 may aggregate"
            );
        }
        let (machine, fhe, timeline) = (&mut runtime.machine, &runtime.fhe, &mut runtime.timeline);
        let mut observe = |p: CkksProgress| observe_progress(timeline, p);
        let commands = machine.on_relin_round_1_proofs_verified(&dishonest, fhe, &mut observe)?;
        self.ckks_mark("ceremony.c8_verified", Detail::default());
        self.ckks_dispatch_commands(commands, &state, ec)
    }

    /// Publish this party's pk share according to the E3's C1 posture.
    ///
    /// `Proven`: routes through `PkGenerationCkksProofPending` so the
    /// ProofRequestActor generates + signs the C1-CKKS proof and publishes
    /// `KeyshareCreated` WITH `signed_pk_generation_proof: Some(..)` — the
    /// aggregator's rogue-key gate treats a missing proof as dishonest.
    /// `ProofFree` (explicit operator off-switch only): publishes the
    /// share directly with no proof.
    fn ckks_publish_keyshare_created(
        &mut self,
        pk_share: ArcBytes,
        witness: CkksC1Witness,
        state: &ThresholdKeyshareState,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let runtime = self
            .ckks
            .as_ref()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        if let ProofPosture::ProofFree(reason) = runtime.posture.c1 {
            info!(
                e3_id = %state.e3_id,
                param_set = runtime.posture.param_set,
                "CKKS pk share published proof-free: {reason}"
            );
            self.bus.publish(
                KeyshareCreated {
                    pubkey: pk_share,
                    e3_id: state.e3_id.clone(),
                    node: state.address.clone(),
                    party_id: state.party_id,
                    signed_pk_generation_proof: None,
                },
                ec.clone(),
            )?;
            self.ckks_mark("dkg.pk_share_published", Detail::default());
            return Ok(());
        }
        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        let ckks_params = ArcBytes::from_bytes(&{
            use fhe_traits::Serialize as _;
            runtime.fhe.params.to_bytes()
        });
        let crp_seed = runtime.machine.relin_crp_seed;
        let encode = |v: &Vec<i64>| -> Result<SensitiveBytes> {
            SensitiveBytes::new(bincode::serialize(v)?, &self.cipher)
        };
        info!(
            e3_id = %state.e3_id,
            "Publishing PkGenerationCkksProofPending for C1-CKKS proof generation..."
        );
        self.bus.publish(
            PkGenerationCkksProofPending {
                e3_id: state.e3_id.clone(),
                party_id: state.party_id,
                node: state.address.clone(),
                pk_share: pk_share.clone(),
                proof_request: PkGenerationCkksProofRequest {
                    ckks_params,
                    crp_seed,
                    pk_share,
                    sk_coeffs: encode(&witness.sk_coeffs)?,
                    eek_coeffs: encode(&witness.e_coeffs)?,
                    e_sm_coeffs: encode(&witness.e_sm_coeffs)?,
                    params_preset: self.ckks_proof_artifacts_preset(),
                    committee_size,
                },
            },
            ec.clone(),
        )?;
        self.ckks_mark("dkg.c1_proof_requested", Detail::default());
        Ok(())
    }

    /// Request the per-digit C8-CKKS proofs for this party's hybrid
    /// round-1 share (posture `ceremony`). The ProofRequestActor signs
    /// them and publishes `RelinCeremonyProofSigned`, which every peer
    /// verifies before aggregating this party's round-1 contribution.
    fn ckks_request_relin_round1_proofs(
        &mut self,
        witness: CkksC8Witness,
        state: &ThresholdKeyshareState,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let runtime = self
            .ckks
            .as_ref()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        if let ProofPosture::ProofFree(reason) = runtime.posture.ceremony {
            info!(
                e3_id = %state.e3_id,
                "CKKS relin round-1 share published proof-free: {reason}"
            );
            return Ok(());
        }
        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        let ckks_params = ArcBytes::from_bytes(&{
            use fhe_traits::Serialize as _;
            runtime.fhe.params.to_bytes()
        });
        let sensitive = |bytes: Vec<u8>| SensitiveBytes::new(bytes, &self.cipher);
        info!(
            e3_id = %state.e3_id,
            dnum = runtime.fhe.params.dnum(),
            "Publishing RelinRound1ProofPending for C8-CKKS digit proof generation..."
        );
        self.bus.publish(
            RelinRound1ProofPending {
                e3_id: state.e3_id.clone(),
                party_id: party_id_machine(state.party_id),
                node: state.address.clone(),
                level: u32::try_from(HYBRID_RELIN_LEVEL)
                    .map_err(|_| anyhow!("hybrid relin level exceeds u32"))?,
                proof_request: RelinRound1CkksProofRequest {
                    ckks_params,
                    crp_seed: runtime.machine.relin_crp_seed,
                    share: ArcBytes::from_bytes(&witness.share),
                    sk_coeffs: sensitive(bincode::serialize(&witness.sk_coeffs)?)?,
                    u_coeffs: sensitive(bincode::serialize(&witness.u_coeffs)?)?,
                    e0_coeffs: sensitive(bincode::serialize(&witness.e0_coeffs)?)?,
                    e1_coeffs: sensitive(bincode::serialize(&witness.e1_coeffs)?)?,
                    params_preset: self.ckks_proof_artifacts_preset(),
                    committee_size,
                },
            },
            ec.clone(),
        )?;
        self.ckks_mark("ceremony.c8_proofs_requested", Detail::default());
        Ok(())
    }

    /// Persist the ceremony's joint relin keys for the evaluator. Every
    /// honest party derives identical bytes; an on-chain flow would
    /// publish a commitment instead of relying on a local file.
    fn ckks_write_relin_keys(
        &mut self,
        keys: &[(usize, ArcBytes)],
        state: &ThresholdKeyshareState,
    ) -> Result<()> {
        let Some(dir) = relin_key_dir(self.ckks_artifacts_dir.as_deref(), &state.e3_id) else {
            warn!(
                e3_id = %state.e3_id,
                "CKKS relin ceremony complete but no artifacts dir is configured; {} joint keys \
                 not written",
                keys.len()
            );
            self.ckks_mark("ceremony.keys_ready", Detail::count(keys.len()));
            return Ok(());
        };
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating relin key dir {}", dir.display()))?;
        for (level, key) in keys {
            let path = dir.join(relin_key_file_name(*level));
            std::fs::write(&path, key.to_vec())
                .with_context(|| format!("writing relin key {}", path.display()))?;
        }
        let total_bytes: usize = keys.iter().map(|(_, k)| k.size()).sum();
        info!(
            e3_id = %state.e3_id,
            hybrid = keys.iter().any(|(l, _)| *l == HYBRID_RELIN_LEVEL),
            total_bytes,
            "CKKS relin ceremony complete: {} joint key(s) written to {}",
            keys.len(),
            dir.display()
        );
        self.ckks_mark(
            "ceremony.keys_written",
            Detail {
                count: Some(keys.len()),
                bytes: Some(total_bytes),
                level: None,
            },
        );
        Ok(())
    }

    /// Broadcast this party's relin-ceremony share chunks for one round:
    /// one `RelinCeremonyShare` event per fixed-size chunk, so any
    /// parameter size fits the gossip/DHT document limits.
    fn ckks_publish_relin_round(
        &mut self,
        round: u8,
        chunks: Vec<RelinShareChunk>,
        state: &ThresholdKeyshareState,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        for chunk in chunks {
            self.bus.publish(
                RelinCeremonyShare {
                    e3_id: state.e3_id.clone(),
                    party_id: party_id_machine(state.party_id),
                    node: state.address.clone(),
                    round,
                    level: u32::try_from(chunk.level)
                        .map_err(|_| anyhow!("relin level {} exceeds u32", chunk.level))?,
                    chunk_index: chunk.chunk_index,
                    chunk_count: chunk.chunk_count,
                    payload_keccak: chunk.payload_keccak,
                    chunk: chunk.bytes,
                    external: false,
                },
                ec.clone(),
            )?;
        }
        Ok(())
    }

    /// CKKS branch of PublicKeyAggregated / CommitteePublished: pk
    /// consensus is confirmed, so the machine may generate and release its
    /// relin round-1 shares (deferred to keep bulky ceremony documents from
    /// starving DKG traffic on the DHT). Idempotent; remembered if the DKG
    /// has not completed yet.
    pub(crate) fn ckks_handle_public_key_aggregated(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(runtime) = self.ckks.as_mut() else {
            // BFV E3 (or CKKS runtime not yet initialized): nothing to do.
            return Ok(());
        };
        let newly_confirmed = !runtime.machine.pk_confirmed;
        runtime.machine.pk_confirmed = true;
        if runtime.machine.relin_round_1_pending() {
            return self.ckks_release_relin_round_1_if_pending(ec);
        }
        if newly_confirmed {
            // Remember the confirmation across a restart (empty dispatch
            // persists the machine snapshot).
            let state = self.state.try_get()?;
            self.ckks_dispatch_commands(Vec::new(), &state, ec)?;
        }
        Ok(())
    }

    /// Generate + publish this node's relin round-1 shares when the
    /// machine reports the release is due (pk confirmed, DKG complete, not
    /// yet released). No-op otherwise — safe to call after any event.
    pub(crate) fn ckks_release_relin_round_1_if_pending(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let Some(runtime) = self.ckks.as_mut() else {
            return Ok(());
        };
        if !runtime.machine.relin_round_1_pending() {
            return Ok(());
        }
        info!(
            e3_id = %state.e3_id,
            plan = ?runtime.machine.relin_plan(),
            "CKKS pk consensus confirmed — generating and releasing relin round 1"
        );
        let (machine, fhe, timeline) = (&mut runtime.machine, &runtime.fhe, &mut runtime.timeline);
        let mut observe = |p: CkksProgress| observe_progress(timeline, p);
        let commands = machine.on_public_key_aggregated(fhe, &mut observe)?;
        self.ckks_mark("ceremony.r1_generated", Detail::default());
        self.ckks_dispatch_commands(commands, &state, ec)
    }

    /// CKKS branch of RelinCeremonyShare (both rounds, own loopback and
    /// network deliveries): one chunk per event; the machine buffers and
    /// reassembles per (party, round, level).
    pub(crate) fn ckks_handle_relin_ceremony_share(
        &mut self,
        msg: &RelinCeremonyShare,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        // Trust boundary: the wire party id is the sender's 1-based Shamir
        // id; the machine rejects 0 and > N. Its committee slot must exist.
        let sender_chain = party_id_chain(msg.party_id)?;
        if sender_chain >= state.threshold_n {
            bail!(
                "RelinCeremonyShare from machine party {} (chain slot {sender_chain}) is outside \
                 the {}-member committee",
                msg.party_id,
                state.threshold_n
            );
        }
        // Record-before-process: the durable chunk log is what a restart
        // replays into the machine's non-snapshot buffers.
        if let Some(ceremony) = self.ckks_ceremony.as_mut() {
            ceremony.log.record(msg, &ec)?;
        }
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let chunk = RelinShareChunk {
            level: msg.level as usize,
            chunk_index: msg.chunk_index,
            chunk_count: msg.chunk_count,
            payload_keccak: msg.payload_keccak,
            bytes: msg.chunk.clone(),
        };
        let commands = Self::ckks_feed_relin_chunk(runtime, msg.round, msg.party_id, &chunk)?;
        self.ckks_dispatch_commands(commands, &state, ec)
    }

    /// Feed one chunk into the machine for `round`, timing progress.
    fn ckks_feed_relin_chunk(
        runtime: &mut CkksRuntime,
        round: u8,
        party_id_machine: u64,
        chunk: &RelinShareChunk,
    ) -> Result<Vec<CkksCommand>> {
        let (machine, fhe, timeline) = (&mut runtime.machine, &runtime.fhe, &mut runtime.timeline);
        let mut observe = |p: CkksProgress| observe_progress(timeline, p);
        match round {
            1 => machine.on_relin_round_1(party_id_machine, chunk, fhe, &mut observe),
            2 => machine.on_relin_round_2(party_id_machine, chunk, fhe, &mut observe),
            other => bail!(
                "RelinCeremonyShare from party {party_id_machine} names round {other}; only 1 \
                 and 2 exist"
            ),
        }
    }

    /// Recovery: replay the chunks the durable log held at hydrate into
    /// the rebuilt machine (its buffers are not snapshot). Idempotent —
    /// chunks the machine already completed are no-ops. Returns the
    /// number of chunks replayed.
    pub(crate) fn ckks_replay_ceremony_chunks(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<usize> {
        let Some(replay) = self
            .ckks_ceremony
            .as_mut()
            .map(|c| std::mem::take(&mut c.replay))
        else {
            return Ok(0);
        };
        if replay.is_empty() {
            return Ok(0);
        }
        let state = self.state.try_get()?;
        let runtime = self
            .ckks
            .as_mut()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let count = replay.len();
        let mut commands = Vec::new();
        for stored in replay {
            let chunk = RelinShareChunk {
                level: stored.key.level as usize,
                chunk_index: stored.key.chunk_index,
                chunk_count: stored.chunk_count,
                payload_keccak: stored.payload_keccak,
                bytes: stored.bytes,
            };
            match Self::ckks_feed_relin_chunk(
                runtime,
                stored.key.round,
                stored.key.party_id_machine,
                &chunk,
            ) {
                Ok(cmds) => commands.extend(cmds),
                // A chunk that was bad before the restart is still bad;
                // attribute it and keep replaying the honest ones.
                Err(err) => warn!(?stored.key, "replayed relin chunk rejected: {err}"),
            }
        }
        runtime
            .timeline
            .mark_with("ceremony.chunks_replayed", Detail::count(count));
        self.ckks_dispatch_commands(commands, &state, ec)?;
        Ok(count)
    }

    /// Publish this party's CKKS decryption share according to the E3's
    /// C6 posture.
    ///
    /// `Proven`: routes through `ShareDecryptionProofPending` so
    /// ProofRequestActor generates + signs C6-CKKS proofs and publishes the
    /// `DecryptionshareCreated` itself — the exact BFV flow. `ProofFree`
    /// (non-canonical param sets without a compiled C6 circuit): publishes
    /// the share directly; the aggregator accepts all-empty proof sets for
    /// CKKS. Without a decryption domain (pure in-process tests that never
    /// see PublicKeyAggregated) the proven path also degrades to a
    /// proof-less publication so the aggregation seam still converges.
    fn ckks_publish_decryption_share(
        &mut self,
        share: ArcBytes,
        ciphertext: ArcBytes,
        state: &ThresholdKeyshareState,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let runtime = self
            .ckks
            .as_ref()
            .ok_or_else(|| anyhow!("CKKS runtime missing"))?;
        let proof_free_reason = match runtime.posture.c6 {
            ProofPosture::ProofFree(reason) => Some(reason),
            ProofPosture::Proven => None,
        };
        let domain = (state.decryption_domain, state.aggregated_pk.clone());
        let (decryption_domain, aggregated_pk) = match (proof_free_reason, domain) {
            (Some(reason), _) => {
                info!(
                    e3_id = %state.e3_id,
                    param_set = runtime.posture.param_set,
                    "CKKS decryption share published proof-free: {reason}"
                );
                return self.ckks_publish_decryption_share_plain(share, state, ec);
            }
            (None, (Some(d), Some(pk))) => (d, pk),
            (None, _) => {
                info!(
                    e3_id = %state.e3_id,
                    "CKKS decryption share: no decryption domain/pk (in-process test path) — \
                     publishing without a C6 proof"
                );
                return self.ckks_publish_decryption_share_plain(share, state, ec);
            }
        };

        let ready = match runtime.machine.phase() {
            CkksPhase::ReadyForDecryption(r) => r.clone(),
            CkksPhase::Decrypting { ready, .. } => ready.clone(),
            other => bail!("CKKS decryption share outside decryption phase: {other:?}"),
        };
        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;

        info!("Publishing ShareDecryptionProofPending for C6-CKKS proof generation...");
        self.bus.publish(
            ShareDecryptionProofPending {
                e3_id: state.e3_id.clone(),
                party_id: state.party_id,
                node: state.address.clone(),
                decryption_share: vec![share.clone()],
                proof_request: ThresholdShareDecryptionProofRequest {
                    scheme: e3_events::E3Scheme::Ckks,
                    ciphertext_bytes: vec![ciphertext],
                    aggregated_pk_bytes: aggregated_pk,
                    sk_poly_sum: SensitiveBytes::new(ready.sk_poly_sum.to_vec(), &self.cipher)?,
                    es_poly_sum: vec![SensitiveBytes::new(
                        ready.es_poly_sum.to_vec(),
                        &self.cipher,
                    )?],
                    d_share_bytes: vec![share],
                    decryption_domain,
                    // BFV-typed field selecting the artifact directory:
                    // the THRESHOLD preset (per-param-set CKKS circuits
                    // live under `insecure-512/...`, see
                    // `ckks_proof_artifacts_preset`).
                    params_preset: self.ckks_proof_artifacts_preset(),
                    committee_size,
                    // The C6-CKKS prover resolves circuit params + artifact
                    // from the E3's OWN CKKS params (per-param-set proven
                    // posture), never from a hardcoded canonical set.
                    ckks_params: Some(ArcBytes::from_bytes(&{
                        use fhe_traits::Serialize as _;
                        runtime.fhe.params.to_bytes()
                    })),
                },
            },
            ec.clone(),
        )?;
        self.ckks_mark("decrypt.c6_proof_requested", Detail::default());
        Ok(())
    }

    /// Publish a `DecryptionshareCreated` with no proofs attached.
    fn ckks_publish_decryption_share_plain(
        &mut self,
        share: ArcBytes,
        state: &ThresholdKeyshareState,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.bus.publish(
            DecryptionshareCreated {
                party_id: state.party_id,
                decryption_share: vec![share],
                e3_id: state.e3_id.clone(),
                node: state.address.clone(),
                signed_decryption_proofs: Vec::new(),
            },
            ec.clone(),
        )?;
        self.ckks_mark("decrypt.share_published", Detail::default());
        Ok(())
    }
}

/// Map a machine progress fact onto the timeline. Hybrid-ceremony facts
/// (the single [`HYBRID_RELIN_LEVEL`] slot) get their own phase names
/// with no level, so the timing report shows ONE r1/r2 row instead of a
/// per-level ladder.
fn observe_progress(timeline: &mut CkksTimeline, p: CkksProgress) {
    let hybrid = |level: usize| level == HYBRID_RELIN_LEVEL;
    match p {
        CkksProgress::RelinRound1LevelGenerated { level, bytes } if hybrid(level) => {
            timeline.mark_with("ceremony.hybrid_r1_generated", Detail::bytes(bytes))
        }
        CkksProgress::RelinRound1LevelComplete { level } if hybrid(level) => {
            timeline.mark_with("ceremony.hybrid_r1_complete", Detail::default())
        }
        CkksProgress::RelinRound2LevelGenerated { level, bytes } if hybrid(level) => {
            timeline.mark_with("ceremony.hybrid_r2_generated", Detail::bytes(bytes))
        }
        CkksProgress::RelinRound2LevelComplete { level } if hybrid(level) => {
            timeline.mark_with("ceremony.hybrid_r2_complete", Detail::default())
        }
        CkksProgress::RelinRound1LevelGenerated { level, bytes } => timeline.mark_with(
            "ceremony.r1_level_generated",
            Detail::level_bytes(level, bytes),
        ),
        CkksProgress::RelinRound1LevelComplete { level } => {
            timeline.mark_with("ceremony.r1_level_complete", Detail::level(level))
        }
        CkksProgress::RelinRound2LevelGenerated { level, bytes } => timeline.mark_with(
            "ceremony.r2_level_generated",
            Detail::level_bytes(level, bytes),
        ),
        CkksProgress::RelinRound2LevelComplete { level } => {
            timeline.mark_with("ceremony.r2_level_complete", Detail::level(level))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn party_id_conversion_is_a_bijection_off_zero() {
        for chain in 0..5u64 {
            assert_eq!(party_id_chain(party_id_machine(chain)).unwrap(), chain);
        }
        assert!(party_id_chain(0).is_err());
    }

    #[test]
    fn relin_key_dir_derives_from_artifacts_dir() {
        let e3 = E3id::new("7", 31337);
        let dir = relin_key_dir(Some(Path::new("/data/cn1/ckks")), &e3).unwrap();
        assert_eq!(dir, PathBuf::from("/data/cn1/ckks/relin-keys/31337:7"));
        assert!(relin_key_dir(None, &e3).is_none());
    }
}
