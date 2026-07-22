// SPDX-License-Identifier: LGPL-3.0-only

//! Pure protocol-readiness evaluation and Prometheus rendering.

use crate::projection::E3Summary;
use e3_evm::{EvmIngestionSnapshot, EvmWriterHealth};
use e3_net::NetworkSnapshot;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct ReadinessPolicy {
    pub min_connected_peers: usize,
    pub max_rpc_poll_age_ms: u64,
    pub max_chain_head_age_ms: u64,
    pub max_sync_lag_blocks: u64,
    pub max_outbox_age_ms: u64,
    pub max_active_e3_idle_ms: u64,
}

#[derive(Clone, Debug)]
pub struct WriterObservation {
    pub health: Option<EvmWriterHealth>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ReadinessObservations {
    pub now_ms: u64,
    pub schema_compatible: bool,
    pub storage_error: Option<String>,
    pub event_pipeline_error: Option<String>,
    pub network: NetworkSnapshot,
    pub chains: Vec<EvmIngestionSnapshot>,
    pub writers: Vec<WriterObservation>,
    pub e3s: Vec<E3Summary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComponentCheck {
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerReadiness {
    pub ok: bool,
    pub required: usize,
    pub connected: usize,
    pub authenticated: usize,
    pub protocol_authentication_required: bool,
    pub configured: usize,
    pub transport_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChainReadiness {
    pub ok: bool,
    pub chain_name: String,
    pub expected_chain_id: u64,
    pub connected_chain_id: Option<u64>,
    pub confirmations: u64,
    pub raw_head: Option<u64>,
    pub confirmed_head: Option<u64>,
    pub cursor: Option<u64>,
    pub cursor_lag_blocks: Option<u64>,
    pub rpc_poll_age_ms: Option<u64>,
    pub chain_head_age_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WriterReadiness {
    pub ok: bool,
    pub writer: String,
    pub chain_id: Option<u64>,
    pub contract_address: Option<String>,
    pub effects_enabled: bool,
    pub pending_effects: usize,
    pub oldest_pending_age_ms: Option<u64>,
    pub in_flight_effects: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActiveE3Readiness {
    pub ok: bool,
    pub e3_id: String,
    pub chain_id: u64,
    pub phase: String,
    pub last_progress_age_ms: u64,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReadinessSnapshot {
    pub ready: bool,
    pub checked_at_ms: u64,
    pub schema: ComponentCheck,
    pub storage: ComponentCheck,
    pub event_pipeline: ComponentCheck,
    pub peers: PeerReadiness,
    pub chains: Vec<ChainReadiness>,
    pub writers: Vec<WriterReadiness>,
    pub active_e3s: Vec<ActiveE3Readiness>,
}

pub fn evaluate(
    policy: &ReadinessPolicy,
    observations: ReadinessObservations,
) -> ReadinessSnapshot {
    let schema = ComponentCheck {
        ok: observations.schema_compatible,
        detail: if observations.schema_compatible {
            "persisted schema preflight passed".to_owned()
        } else {
            "persisted schema preflight did not pass".to_owned()
        },
    };
    let storage = component_from_error("durable store flush succeeded", observations.storage_error);
    let event_pipeline = component_from_error(
        "event store query succeeded",
        observations.event_pipeline_error,
    );

    let active_protocol = observations.e3s.iter().any(|e3| e3.status == "active");
    let connected = observations.network.connected_peers.len();
    let authenticated = observations.network.authenticated_peers.len();
    let eligible = if active_protocol {
        authenticated
    } else {
        connected
    };
    let peer_transport_ok = observations.network.last_error.is_none();
    let peers = PeerReadiness {
        ok: peer_transport_ok && eligible >= policy.min_connected_peers,
        required: policy.min_connected_peers,
        connected,
        authenticated,
        protocol_authentication_required: active_protocol,
        configured: observations.network.configured_peers,
        transport_error: observations.network.last_error,
    };

    let mut chains: Vec<_> = observations
        .chains
        .into_iter()
        .map(|chain| evaluate_chain(policy, observations.now_ms, chain))
        .collect();
    chains.sort_by_key(|chain| chain.expected_chain_id);

    let mut writers: Vec<_> = observations
        .writers
        .into_iter()
        .map(|writer| evaluate_writer(policy, writer))
        .collect();
    writers.sort_by(|a, b| {
        (a.chain_id, &a.writer, &a.contract_address).cmp(&(
            b.chain_id,
            &b.writer,
            &b.contract_address,
        ))
    });

    let now_us = observations.now_ms.saturating_mul(1_000);
    let mut active_e3s: Vec<_> = observations
        .e3s
        .into_iter()
        .filter(|e3| e3.status == "active")
        .map(|e3| {
            let last_progress_age_ms = now_us.saturating_sub(e3.last_seen_us) / 1_000;
            ActiveE3Readiness {
                ok: last_progress_age_ms <= policy.max_active_e3_idle_ms,
                e3_id: e3.e3_id,
                chain_id: e3.chain_id,
                phase: format!("{:?}", e3.current_phase).to_ascii_lowercase(),
                last_progress_age_ms,
                errors: e3.error_count,
                warnings: e3.warning_count,
            }
        })
        .collect();
    active_e3s.sort_by(|a, b| a.e3_id.cmp(&b.e3_id));

    let ready = schema.ok
        && storage.ok
        && event_pipeline.ok
        && peers.ok
        && !chains.is_empty()
        && chains.iter().all(|chain| chain.ok)
        && !writers.is_empty()
        && writers.iter().all(|writer| writer.ok)
        && active_e3s.iter().all(|e3| e3.ok);

    ReadinessSnapshot {
        ready,
        checked_at_ms: observations.now_ms,
        schema,
        storage,
        event_pipeline,
        peers,
        chains,
        writers,
        active_e3s,
    }
}

fn component_from_error(success: &str, error: Option<String>) -> ComponentCheck {
    match error {
        Some(error) => ComponentCheck {
            ok: false,
            detail: error,
        },
        None => ComponentCheck {
            ok: true,
            detail: success.to_owned(),
        },
    }
}

fn evaluate_chain(
    policy: &ReadinessPolicy,
    now_ms: u64,
    chain: EvmIngestionSnapshot,
) -> ChainReadiness {
    let rpc_poll_age_ms = chain
        .last_success_at_ms
        .map(|success| now_ms.saturating_sub(success));
    let chain_head_age_ms = chain
        .head_timestamp_secs
        .map(|timestamp| now_ms.saturating_sub(timestamp.saturating_mul(1_000)));
    let cursor_lag_blocks = chain
        .confirmed_head
        .zip(chain.cursor)
        .map(|(head, cursor)| head.saturating_sub(cursor));
    let chain_id_ok = chain.connected_chain_id == Some(chain.expected_chain_id);
    let rpc_fresh = rpc_poll_age_ms.is_some_and(|age| age <= policy.max_rpc_poll_age_ms);
    let head_fresh = chain_head_age_ms.is_some_and(|age| age <= policy.max_chain_head_age_ms);
    let cursor_fresh = cursor_lag_blocks.is_some_and(|lag| lag <= policy.max_sync_lag_blocks);
    let ok = chain_id_ok && rpc_fresh && head_fresh && cursor_fresh && chain.last_error.is_none();

    ChainReadiness {
        ok,
        chain_name: chain.chain_name,
        expected_chain_id: chain.expected_chain_id,
        connected_chain_id: chain.connected_chain_id,
        confirmations: chain.confirmations,
        raw_head: chain.raw_head,
        confirmed_head: chain.confirmed_head,
        cursor: chain.cursor,
        cursor_lag_blocks,
        rpc_poll_age_ms,
        chain_head_age_ms,
        error: chain.last_error,
    }
}

fn evaluate_writer(policy: &ReadinessPolicy, observation: WriterObservation) -> WriterReadiness {
    let Some(health) = observation.health else {
        return WriterReadiness {
            ok: false,
            writer: "unavailable".to_owned(),
            chain_id: None,
            contract_address: None,
            effects_enabled: false,
            pending_effects: 0,
            oldest_pending_age_ms: None,
            in_flight_effects: 0,
            error: observation
                .error
                .or_else(|| Some("required writer did not respond".to_owned())),
        };
    };
    let outbox_fresh = health
        .oldest_pending_age_ms
        .is_none_or(|age| age <= policy.max_outbox_age_ms);
    let ok = health.effects_enabled && outbox_fresh && observation.error.is_none();
    WriterReadiness {
        ok,
        writer: health.writer,
        chain_id: Some(health.chain_id),
        contract_address: Some(health.contract_address),
        effects_enabled: health.effects_enabled,
        pending_effects: health.pending_effects,
        oldest_pending_age_ms: health.oldest_pending_age_ms,
        in_flight_effects: health.in_flight_effects,
        error: observation.error,
    }
}

impl ReadinessSnapshot {
    pub fn prometheus(&self) -> String {
        let mut output = String::from(
            "# HELP interfold_ready Whether all protocol readiness gates pass.\n\
             # TYPE interfold_ready gauge\n",
        );
        metric(&mut output, "interfold_ready", self.ready, "");
        metric(&mut output, "interfold_schema_ready", self.schema.ok, "");
        metric(&mut output, "interfold_storage_ready", self.storage.ok, "");
        metric(
            &mut output,
            "interfold_event_pipeline_ready",
            self.event_pipeline.ok,
            "",
        );
        numeric_metric(
            &mut output,
            "interfold_connected_peers",
            self.peers.connected as u64,
            "",
        );
        numeric_metric(
            &mut output,
            "interfold_authenticated_peers",
            self.peers.authenticated as u64,
            "",
        );
        numeric_metric(
            &mut output,
            "interfold_required_peers",
            self.peers.required as u64,
            "",
        );
        metric(&mut output, "interfold_peer_ready", self.peers.ok, "");
        metric(
            &mut output,
            "interfold_peer_authentication_required",
            self.peers.protocol_authentication_required,
            "",
        );
        for chain in &self.chains {
            let labels = format!(
                "{{chain_id=\"{}\",chain=\"{}\"}}",
                chain.expected_chain_id,
                escape_label(&chain.chain_name)
            );
            metric(&mut output, "interfold_chain_ready", chain.ok, &labels);
            numeric_metric(
                &mut output,
                "interfold_chain_head",
                chain.raw_head.unwrap_or(0),
                &labels,
            );
            numeric_metric(
                &mut output,
                "interfold_chain_cursor_lag_blocks",
                chain.cursor_lag_blocks.unwrap_or(u64::MAX),
                &labels,
            );
            numeric_metric(
                &mut output,
                "interfold_rpc_poll_age_seconds",
                chain.rpc_poll_age_ms.unwrap_or(u64::MAX) / 1_000,
                &labels,
            );
            numeric_metric(
                &mut output,
                "interfold_chain_head_age_seconds",
                chain.chain_head_age_ms.unwrap_or(u64::MAX) / 1_000,
                &labels,
            );
        }
        for writer in &self.writers {
            let labels = format!(
                "{{chain_id=\"{}\",writer=\"{}\"}}",
                writer.chain_id.unwrap_or(0),
                escape_label(&writer.writer)
            );
            metric(&mut output, "interfold_writer_ready", writer.ok, &labels);
            numeric_metric(
                &mut output,
                "interfold_outbox_pending_effects",
                writer.pending_effects as u64,
                &labels,
            );
            numeric_metric(
                &mut output,
                "interfold_outbox_oldest_age_seconds",
                writer.oldest_pending_age_ms.unwrap_or(0) / 1_000,
                &labels,
            );
        }
        numeric_metric(
            &mut output,
            "interfold_active_e3_total",
            self.active_e3s.len() as u64,
            "",
        );
        for e3 in &self.active_e3s {
            let labels = format!(
                "{{chain_id=\"{}\",e3_id=\"{}\",phase=\"{}\"}}",
                e3.chain_id,
                escape_label(&e3.e3_id),
                escape_label(&e3.phase)
            );
            metric(&mut output, "interfold_active_e3_ready", e3.ok, &labels);
            numeric_metric(
                &mut output,
                "interfold_active_e3_idle_seconds",
                e3.last_progress_age_ms / 1_000,
                &labels,
            );
        }
        output
    }
}

fn metric(output: &mut String, name: &str, value: bool, labels: &str) {
    numeric_metric(output, name, u64::from(value), labels);
}

fn numeric_metric(output: &mut String, name: &str, value: u64, labels: &str) {
    output.push_str(name);
    output.push_str(labels);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::E3Phase;

    fn policy() -> ReadinessPolicy {
        ReadinessPolicy {
            min_connected_peers: 1,
            max_rpc_poll_age_ms: 30_000,
            max_chain_head_age_ms: 120_000,
            max_sync_lag_blocks: 2,
            max_outbox_age_ms: 300_000,
            max_active_e3_idle_ms: 1_200_000,
        }
    }

    fn healthy(now_ms: u64) -> ReadinessObservations {
        ReadinessObservations {
            now_ms,
            schema_compatible: true,
            storage_error: None,
            event_pipeline_error: None,
            network: NetworkSnapshot {
                configured_peers: 1,
                connected_peers: vec![e3_net::ConnectedPeer {
                    peer_id: "peer".to_owned(),
                    remote_address: "/ip4/127.0.0.1".to_owned(),
                    direction: "outbound".to_owned(),
                    connections: 1,
                    connected_at_ms: now_ms,
                }],
                authenticated_peers: vec![e3_net::AuthenticatedPeer {
                    peer_id: "peer".to_owned(),
                    signer: "0x1".to_owned(),
                    e3_id: "1:7".to_owned(),
                    authenticated_at_ms: now_ms,
                }],
                listen_addresses: vec!["/ip4/0.0.0.0".to_owned()],
                last_error: None,
            },
            chains: vec![EvmIngestionSnapshot {
                chain_name: "test".to_owned(),
                expected_chain_id: 1,
                connected_chain_id: Some(1),
                confirmations: 12,
                raw_head: Some(100),
                confirmed_head: Some(88),
                cursor: Some(88),
                head_timestamp_secs: Some(now_ms / 1_000),
                last_success_at_ms: Some(now_ms),
                last_error_at_ms: None,
                last_error: None,
            }],
            writers: vec![WriterObservation {
                health: Some(EvmWriterHealth {
                    writer: "interfold".to_owned(),
                    chain_id: 1,
                    contract_address: "0x1".to_owned(),
                    effects_enabled: true,
                    pending_effects: 0,
                    oldest_pending_age_ms: None,
                    in_flight_effects: 0,
                }),
                error: None,
            }],
            e3s: vec![E3Summary {
                e3_id: "1:7".to_owned(),
                chain_id: 1,
                status: "active".to_owned(),
                current_phase: E3Phase::Computation,
                event_count: 10,
                error_count: 0,
                warning_count: 0,
                committee_size: 3,
                first_seen_us: now_ms.saturating_sub(10_000).saturating_mul(1_000),
                last_seen_us: now_ms.saturating_sub(1_000).saturating_mul(1_000),
            }],
        }
    }

    #[test]
    fn all_protocol_gates_produce_ready_snapshot_and_metrics() {
        let snapshot = evaluate(&policy(), healthy(1_700_000_000_000));
        assert!(snapshot.ready);
        let metrics = snapshot.prometheus();
        assert!(metrics.contains("interfold_ready 1"));
        assert!(metrics.contains("interfold_chain_cursor_lag_blocks"));
        assert!(metrics.contains("interfold_chain_head_age_seconds"));
        assert!(metrics.contains("interfold_outbox_pending_effects"));
    }

    #[test]
    fn injected_failures_revoke_readiness() {
        let now = 1_700_000_000_000;
        let mut cases = Vec::new();

        let mut no_schema = healthy(now);
        no_schema.schema_compatible = false;
        cases.push(no_schema);

        let mut disk = healthy(now);
        disk.storage_error = Some("disk read-only".to_owned());
        cases.push(disk);

        let mut eventstore = healthy(now);
        eventstore.event_pipeline_error = Some("event query timed out".to_owned());
        cases.push(eventstore);

        let mut peers = healthy(now);
        peers.network.connected_peers.clear();
        peers.network.authenticated_peers.clear();
        cases.push(peers);

        let mut wrong_chain = healthy(now);
        wrong_chain.chains[0].connected_chain_id = Some(2);
        cases.push(wrong_chain);

        let mut stale_rpc = healthy(now);
        stale_rpc.chains[0].last_success_at_ms = Some(now - 31_000);
        cases.push(stale_rpc);

        let mut stale_head = healthy(now);
        stale_head.chains[0].head_timestamp_secs = Some((now - 121_000) / 1_000);
        cases.push(stale_head);

        let mut lagged = healthy(now);
        lagged.chains[0].cursor = Some(80);
        cases.push(lagged);

        let mut dead_writer = healthy(now);
        dead_writer.writers[0] = WriterObservation {
            health: None,
            error: Some("mailbox closed".to_owned()),
        };
        cases.push(dead_writer);

        let mut wedged_outbox = healthy(now);
        wedged_outbox.writers[0]
            .health
            .as_mut()
            .unwrap()
            .oldest_pending_age_ms = Some(300_001);
        cases.push(wedged_outbox);

        let mut stalled_e3 = healthy(now);
        stalled_e3.e3s[0].last_seen_us = (now - 1_200_001).saturating_mul(1_000);
        cases.push(stalled_e3);

        for observations in cases {
            assert!(!evaluate(&policy(), observations).ready);
        }
    }

    #[test]
    fn transport_only_peer_does_not_satisfy_an_active_protocol_quorum() {
        let now = 1_700_000_000_000;
        let mut observations = healthy(now);
        observations.network.authenticated_peers.clear();

        let snapshot = evaluate(&policy(), observations);
        assert!(!snapshot.ready);
        assert_eq!(snapshot.peers.connected, 1);
        assert_eq!(snapshot.peers.authenticated, 0);
        assert!(snapshot.peers.protocol_authentication_required);
    }

    #[test]
    fn connected_peer_quorum_is_sufficient_while_protocol_is_idle() {
        let now = 1_700_000_000_000;
        let mut observations = healthy(now);
        observations.e3s.clear();
        observations.network.authenticated_peers.clear();

        let snapshot = evaluate(&policy(), observations);
        assert!(snapshot.ready);
        assert!(!snapshot.peers.protocol_authentication_required);
    }
}
