// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_config::AppConfig;
use e3_logger::{
    is_sensitive_field, telemetry_metadata_is_safe, LogCollector, OperationalLogLayer,
    REDACTED_FIELD_VALUE,
};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use std::{fmt, path::PathBuf};
use tracing::{
    field::{Field, Visit},
    Level,
};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::{FormatFields, Writer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Level filter shared by every subscriber setup.
///
/// `-vv` (DEBUG) is the level an operator reaches for when a node misbehaves, so it has to stay
/// readable. Dependency internals dominate it otherwise: in a measured 8-minute 5-node run,
/// `sled`'s page-cache alone emitted 8.9k of 39.4k DEBUG lines (31%), with multistream protocol
/// negotiation and the HTTP transport adding thousands more — all of it noise for diagnosing
/// protocol behaviour. Pin those crates to WARN so `-vv` shows Interfold's own diagnostics.
///
/// Raise an individual dependency with `RUST_LOG` when you genuinely need its internals.
fn level_targets(log_level: Level) -> Targets {
    Targets::new()
        .with_default(log_level)
        .with_target("alloy_pubsub", Level::WARN)
        // Storage engine page-cache/IO-buffer churn.
        .with_target("sled", Level::WARN)
        // libp2p connection-establishment protocol negotiation.
        .with_target("multistream_select", Level::WARN)
        // Gossipsub/Kademlia poll-loop internals (mesh churn is surfaced by our own
        // "Peer subscribed to topic" / "Peer disconnected" lines instead).
        .with_target("libp2p_gossipsub", Level::WARN)
        .with_target("libp2p_kad", Level::WARN)
        .with_target("libp2p_swarm", Level::WARN)
        // HTTP transport connection pooling behind the EVM provider.
        .with_target("alloy_transport_http", Level::WARN)
        .with_target("hyper", Level::WARN)
        .with_target("hyper_util", Level::WARN)
        .with_target("reqwest", Level::WARN)
}

pub fn setup_simple_tracing(log_level: Level) {
    LogCollector::init("interfold", None);
    let targets = level_targets(log_level);
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(true)
                .fmt_fields(TerminalFields)
                .with_target(false),
        )
        .with(OperationalLogLayer)
        .with(targets)
        .try_init();
}

pub fn setup_tracing(config: &AppConfig, log_level: Level) -> Result<()> {
    let name = config.name();
    LogCollector::init(&name, Some(operational_log_path(config)));

    let targets = level_targets(log_level);

    match config.otel() {
        Some(endpoint) => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .with_protocol(Protocol::Grpc)
                .build()?;
            let provider = SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(Resource::builder().with_service_name(name).build())
                .build();
            let telemetry = tracing_opentelemetry::layer()
                .with_tracer(provider.tracer("interfold-ciphernode"))
                .with_filter(tracing_subscriber::filter::filter_fn(
                    telemetry_metadata_is_safe,
                ));

            let _ = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .with_ansi(true)
                        .fmt_fields(TerminalFields)
                        .with_target(false),
                )
                .with(OperationalLogLayer)
                .with(telemetry)
                .with(targets)
                .try_init();
        }
        None => {
            let _ = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .with_ansi(true)
                        .fmt_fields(TerminalFields)
                        .with_target(false),
                )
                .with(OperationalLogLayer)
                .with(targets)
                .try_init();
        }
    }
    Ok(())
}

fn operational_log_path(config: &AppConfig) -> PathBuf {
    config
        .log_file()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ciphernode.jsonl")
}

#[derive(Clone, Copy, Debug, Default)]
struct TerminalFields;

impl<'writer> FormatFields<'writer> for TerminalFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = TerminalFieldVisitor::new(writer);
        fields.record(&mut visitor);
        visitor.finish()
    }
}

struct TerminalFieldVisitor<'writer> {
    writer: Writer<'writer>,
    is_empty: bool,
    result: fmt::Result,
}

impl<'writer> TerminalFieldVisitor<'writer> {
    fn new(writer: Writer<'writer>) -> Self {
        Self {
            writer,
            is_empty: true,
            result: Ok(()),
        }
    }

    fn finish(self) -> fmt::Result {
        self.result
    }

    fn begin_field(&mut self) -> bool {
        if self.result.is_err() {
            return false;
        }

        if self.is_empty {
            self.is_empty = false;
            true
        } else {
            self.result = write!(self.writer, " ");
            self.result.is_ok()
        }
    }

    fn record_message_debug(&mut self, value: &dyn fmt::Debug) {
        if self.begin_field() {
            self.result = write!(self.writer, "{value:?}");
        }
    }

    fn record_message_display(&mut self, value: impl fmt::Display) {
        if self.begin_field() {
            self.result = write!(self.writer, "{value}");
        }
    }

    fn record_named_debug(&mut self, name: &str, value: &dyn fmt::Debug) {
        if !self.begin_field() {
            return;
        }

        let name = name.strip_prefix("r#").unwrap_or(name);
        if is_sensitive_field(name) {
            self.result = write!(self.writer, "{name}={REDACTED_FIELD_VALUE:?}");
        } else {
            self.result = write!(self.writer, "{name}={value:?}");
        }
    }

    fn record_named_display(&mut self, name: &str, value: impl fmt::Display) {
        if !self.begin_field() {
            return;
        }

        let name = name.strip_prefix("r#").unwrap_or(name);
        if is_sensitive_field(name) {
            self.result = write!(self.writer, "{name}={REDACTED_FIELD_VALUE}");
        } else {
            self.result = write!(self.writer, "{name}={value}");
        }
    }
}

impl Visit for TerminalFieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_message_display(value);
        } else {
            self.record_named_debug(field.name(), &value);
        }
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.record_named_debug(field.name(), &value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if field.name() == "message" {
            self.record_message_display(value);
        } else {
            self.record_named_display(field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let name = field.name();

        if name.starts_with("log.") {
            return;
        }

        if name == "message" {
            self.record_message_debug(value);
        } else {
            self.record_named_debug(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::{fmt::writer::MakeWriter, layer::SubscriberExt};

    #[derive(Clone, Default)]
    struct CapturedLogs {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            let bytes = self.bytes.lock().expect("captured logs lock poisoned");
            String::from_utf8(bytes.clone()).expect("captured logs should be valid UTF-8")
        }
    }

    struct CapturedLogWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("captured logs lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    #[test]
    fn terminal_fields_preserve_ansi_escape_bytes_in_messages() {
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(false)
                .fmt_fields(TerminalFields)
                .with_writer(captured.clone()),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("{}\x1b[33mcolored\x1b[0m", "terminal ");
        });

        let output = captured.contents();
        assert!(output.contains("\x1b[33mcolored\x1b[0m"));
        assert!(!output.contains("\\x1b[33mcolored\\x1b[0m"));
    }

    #[test]
    fn terminal_fields_redact_sensitive_values() {
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(false)
                .fmt_fields(TerminalFields)
                .with_writer(captured.clone()),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                private_key = "terminal-private-key-sentinel",
                tx_hash = "0xsafe"
            );
        });

        let output = captured.contents();
        assert!(!output.contains("terminal-private-key-sentinel"));
        assert!(output.contains(REDACTED_FIELD_VALUE));
        assert!(output.contains("0xsafe"));
    }

    #[test]
    fn telemetry_layer_excludes_sensitive_callsites() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let telemetry = tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("redaction-test"))
            .with_filter(tracing_subscriber::filter::filter_fn(
                telemetry_metadata_is_safe,
            ));
        let subscriber = tracing_subscriber::registry().with(telemetry);

        tracing::subscriber::with_default(subscriber, || {
            let sensitive = tracing::info_span!(
                "sensitive-otel-span",
                private_key = "otel-private-key-sentinel"
            );
            drop(sensitive);
            let safe = tracing::info_span!("safe-otel-span", e3_id = "31337:1");
            drop(safe);
        });
        provider.force_flush().expect("flush in-memory exporter");

        let spans = exporter.get_finished_spans().expect("exported spans");
        let rendered = format!("{spans:?}");
        assert!(!rendered.contains("otel-private-key-sentinel"));
        assert!(!rendered.contains("sensitive-otel-span"));
        assert!(rendered.contains("safe-otel-span"));
    }
}
