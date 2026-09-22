// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use std::{collections::HashMap, num::NonZero, sync::Arc, time::Duration};

use super::*;
use crate::events::NetCommand;
use crate::{domain::EventConversionService, ContentHash};
use actix::Addr;
use alloy::{
    primitives::{Address, B256, U256},
    signers::local::PrivateKeySigner,
};
use anyhow::{bail, Result};
use chrono::Utc;
use e3_ciphernode_builder::EventSystem;
use e3_committee_hash::{hash_lbfv_proof_session, LbfvProofDomainContext};
use e3_events::{
    AggregateConfig, AggregateId, BusHandle, CiphernodeSelected, DocumentKind, DocumentMeta, E3id,
    EncryptionKey, EncryptionKeyCreated, GetEvents, HistoryCollector, InterfoldError,
    InterfoldEvent, LbfvKeyShareDocument, LbfvKeyShareDocumentContextV1,
    LbfvKeyShareDocumentFetchFailureClass, LbfvKeyShareDocumentFetchRequested,
    LbfvKeyShareDocumentFetchRequestedV1, LbfvKeyShareDocumentRole, LbfvPublicKeyShareDocumentV1,
    LbfvRelinearizationKeyShareDocumentV1, Proof, ProofPayload, ProofType,
    PublishDocumentRequested, SignedProofPayload, TakeEvents,
};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_utils::ArcBytes;
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare};
use fhe_traits::Serialize as FheSerialize;
use libp2p::kad::{GetRecordError, PutRecordError, RecordKey};
use std::time::Instant;
use tokio::{
    sync::{broadcast, mpsc},
    time::{sleep, timeout},
};
use tracing::subscriber::DefaultGuard;

#[allow(clippy::type_complexity)]
fn setup_test() -> Result<(
    DefaultGuard,
    BusHandle,
    mpsc::Sender<NetCommand>,
    mpsc::Receiver<NetCommand>,
    broadcast::Sender<NetEvent>,
    NetEventSubscriber,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<HistoryCollector<InterfoldEvent>>,
    Addr<DocumentPublisher>,
)> {
    use tracing_subscriber::{fmt, EnvFilter};

    let subscriber = fmt()
        .with_env_filter(EnvFilter::new("debug"))
        .with_test_writer()
        .finish();

    let guard = tracing::subscriber::set_default(subscriber);

    let aggregate_config =
        AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config);
    let bus = system.handle()?.enable("test");
    let (net_cmd_tx, net_cmd_rx) = mpsc::channel(100);
    let (net_evt_tx, _net_evt_rx) = broadcast::channel(100);
    let net_evt_rx = NetEventSubscriber::from(&net_evt_tx);
    let history = HistoryCollector::<InterfoldEvent>::new().start();
    let error = HistoryCollector::<InterfoldEvent>::new().start();
    bus.subscribe(EventType::All, history.clone().recipient());
    bus.subscribe(EventType::InterfoldError, error.clone().recipient());
    let publisher = DocumentPublisher::setup(&bus, &net_cmd_tx, &net_evt_rx, "topic");

    Ok((
        guard, bus, net_cmd_tx, net_cmd_rx, net_evt_tx, net_evt_rx, history, error, publisher,
    ))
}

mod notifications;
mod publishing;

fn is_between(instant: Instant, start: Instant, end: Instant) -> bool {
    let (min, max) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    instant >= min && instant <= max
}

fn days_from_now(days: u64) -> Instant {
    Instant::now() + Duration::from_secs(60 * 60 * 24 * days)
}

fn lbfv_context() -> LbfvKeyShareDocumentContextV1 {
    let e3_id = E3id::new("9", 1);
    let proof_domain = LbfvProofDomainContext {
        protocol_version: 4,
        chain_id: 1,
        interfold_address: Address::repeat_byte(0x11),
        e3_id: U256::from(9),
        crypto_config_id: B256::repeat_byte(0x22),
        finalized_committee_hash: B256::repeat_byte(0x33),
        lbfv_constants_version: 1,
        ciphertext_level: 0,
        key_level: 0,
    };
    LbfvKeyShareDocumentContextV1 {
        e3_id,
        proof_domain,
        proof_session_id: hash_lbfv_proof_session(proof_domain),
        party_id: 1,
    }
}

fn lbfv_signer() -> PrivateKeySigner {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse()
        .unwrap()
}

fn lbfv_signed_proof(
    context: &LbfvKeyShareDocumentContextV1,
    proof_type: ProofType,
    row: u32,
) -> SignedProofPayload {
    let circuit = proof_type.circuit_names()[0];
    let public_signals = if proof_type.is_multirow() {
        let layout = circuit.input_layout();
        let session = e3_committee_hash::split_hash_to_field_limbs(context.proof_session_id);
        let field_count =
            layout.field_count().unwrap() + circuit.output_layout().field_count().unwrap();
        let mut signals = vec![0u8; field_count * 32];
        let session_hi = layout.field_index("session_id_hi").unwrap();
        signals[session_hi * 32 + 16..session_hi * 32 + 32]
            .copy_from_slice(&session.hi.to_be_bytes());
        let session_lo = layout.field_index("session_id_lo").unwrap();
        signals[session_lo * 32 + 16..session_lo * 32 + 32]
            .copy_from_slice(&session.lo.to_be_bytes());
        let party_id = layout.field_index("party_id").unwrap();
        signals[party_id * 32 + 28..party_id * 32 + 32]
            .copy_from_slice(&context.party_id.to_be_bytes());
        let row_index = layout.field_index("row_index").unwrap();
        signals[row_index * 32 + 28..row_index * 32 + 32].copy_from_slice(&row.to_be_bytes());
        signals
    } else {
        vec![0; circuit.output_layout().field_count().unwrap() * 32]
    };
    SignedProofPayload::sign(
        ProofPayload {
            e3_id: context.e3_id.clone(),
            proof_type,
            proof: Proof::new(
                circuit,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&public_signals),
            ),
        },
        &lbfv_signer(),
    )
    .unwrap()
}

fn lbfv_documents() -> (LbfvKeyShareDocument, LbfvKeyShareDocument) {
    let context = lbfv_context();
    let public_key = LbfvKeyShareDocument::PublicKeyV1(LbfvPublicKeyShareDocumentV1 {
        context: context.clone(),
        share: ArcBytes::from_bytes(&lbfv_share_bytes(true, 64)),
        signed_c1_proof: lbfv_signed_proof(&context, ProofType::C1PkGeneration, 0),
        signed_row_proofs: std::array::from_fn(|row| {
            lbfv_signed_proof(&context, ProofType::LbfvPkGeneration, row as u32)
        }),
    });
    let relinearization_key =
        LbfvKeyShareDocument::RelinearizationKeyV1(LbfvRelinearizationKeyShareDocumentV1 {
            context,
            share: ArcBytes::from_bytes(&lbfv_share_bytes(false, 64)),
            signed_row_proofs: std::array::from_fn(|row| {
                lbfv_signed_proof(public_key.context(), ProofType::RlkGeneration, row as u32)
            }),
        });
    (public_key, relinearization_key)
}

fn lbfv_share_bytes(public_key: bool, minimum_len: usize) -> Vec<u8> {
    let preset = BfvPreset::InsecureThreshold512;
    let (params, _) = build_pair_for_preset(preset).unwrap();
    let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(preset).unwrap()).unwrap();
    let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(preset).unwrap()).unwrap();
    let mut random = rand::rng();
    let secret_key = SecretKey::random(&params, &mut random);
    let mut bytes = if public_key {
        PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut random)
            .unwrap()
            .to_bytes()
    } else {
        RelinKeyShare::contribution_with_crp_extended(&secret_key, &urs, &crs, 0, 0, &mut random)
            .unwrap()
            .0
            .to_bytes()
    };
    bytes.resize(bytes.len().max(minimum_len), 0);
    bytes
}

fn lbfv_fetch_request(
    document: &LbfvKeyShareDocument,
    attempt: u32,
) -> LbfvKeyShareDocumentFetchRequested {
    LbfvKeyShareDocumentFetchRequested::V1(LbfvKeyShareDocumentFetchRequestedV1 {
        e3_id: document.e3_id().clone(),
        proof_session_id: document.context().proof_session_id,
        party_id: document.context().party_id,
        role: document.role(),
        content_hash: document.content_hash().unwrap(),
        attempt,
    })
}
