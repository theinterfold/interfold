// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `tracing` integration for the operator log store.

use serde_json::{Map, Number, Value};
use tracing::{span, Id, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

use crate::LogCollector;

/// Maximum characters retained for a single string/Debug field value. A large
/// `?`-logged value (e.g. a ciphertext) is truncated so it cannot blow up the
/// in-memory store or the rotating JSONL file.
const MAX_FIELD_VALUE_CHARS: usize = 1024;

/// Maximum number of structured fields retained per log entry, bounding the
/// growth from inheriting every ancestor span's fields.
const MAX_FIELDS: usize = 64;

pub const REDACTED_FIELD_VALUE: &str = "[REDACTED]";

/// Field-name based fail-safe for values that must never reach the in-memory log store or JSONL
/// exporter. Tracing field names are static callsite metadata, so this check is deterministic and
/// runs before values are retained or inherited by child spans.
pub fn is_sensitive_field(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();

    matches!(
        normalized.as_str(),
        "password"
            | "passphrase"
            | "mnemonic"
            | "seed"
            | "seedphrase"
            | "seedwords"
            | "jwt"
            | "authorization"
            | "bearer"
            | "apikey"
            | "accesstoken"
            | "refreshtoken"
            | "rpcauth"
            | "rpcurl"
    ) || normalized.contains("privatekey")
        || normalized.contains("secret")
        || normalized.contains("keyshare")
        || normalized.contains("plaintext")
        || normalized.contains("decrypted")
        || normalized.contains("credential")
        || normalized.contains("authorization")
        || normalized.contains("jwt")
        || normalized.contains("bearertoken")
        || normalized.ends_with("apikey")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("rpcauth")
        || normalized.ends_with("rpcurl")
}

/// OpenTelemetry cannot rewrite a sibling layer's fields. Sensitive callsites
/// are therefore excluded from that exporter using their static field metadata.
pub fn telemetry_metadata_is_safe(metadata: &tracing::Metadata<'_>) -> bool {
    !metadata
        .fields()
        .iter()
        .any(|field| is_sensitive_field(field.name()))
}

/// Strip ANSI escape sequences (e.g. the terminal colours the event bus adds
/// to log lines) so the structured store and JSONL file hold clean text.
fn strip_ansi(input: &str) -> String {
    if !input.contains('\u{1b}') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI sequence: ESC '[' params... final-byte in 0x40..=0x7E.
            if chars.peek() == Some(&'[') {
                chars.next();
                for nc in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&nc) {
                        break;
                    }
                }
            }
            // Any other escape: drop the ESC and continue.
            continue;
        }
        out.push(c);
    }
    out
}

/// Strip ANSI then truncate an over-long string value with an ellipsis marker.
fn clean_value(value: String) -> Value {
    let value = strip_ansi(&value);
    if value.chars().count() > MAX_FIELD_VALUE_CHARS {
        let truncated: String = value.chars().take(MAX_FIELD_VALUE_CHARS).collect();
        Value::String(format!("{truncated}…"))
    } else {
        Value::String(value)
    }
}

/// Captures structured tracing events for the bounded dashboard store and
/// rotating JSONL file. It does not subscribe to or mutate the protocol bus.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationalLogLayer;

impl<S> Layer<S> for OperationalLogLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attributes: &span::Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut visitor = LogVisitor::default();
        attributes.record(&mut visitor);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(visitor.fields));
        }
    }

    fn on_record(&self, id: &Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = LogVisitor::default();
        values.record(&mut visitor);
        let mut extensions = span.extensions_mut();
        if let Some(fields) = extensions.get_mut::<SpanFields>() {
            fields.0.extend(visitor.fields);
        } else {
            extensions.insert(SpanFields(visitor.fields));
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let Some(collector) = LogCollector::global() else {
            return;
        };
        let mut visitor = LogVisitor::default();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(fields) = span.extensions().get::<SpanFields>() {
                    for (key, value) in &fields.0 {
                        // Respect the per-entry field cap during inheritance;
                        // closer (child) spans overwrite ancestors' values.
                        if visitor.fields.len() >= MAX_FIELDS && !visitor.fields.contains_key(key) {
                            continue;
                        }
                        visitor.fields.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        event.record(&mut visitor);
        let message = visitor
            .message
            .take()
            .unwrap_or_else(|| event.metadata().name().to_owned());
        collector.record(
            event.metadata().level().as_str(),
            event.metadata().target(),
            message,
            visitor.fields,
        );
    }
}

struct SpanFields(Map<String, Value>);

#[derive(Default)]
struct LogVisitor {
    message: Option<String>,
    fields: Map<String, Value>,
}

impl LogVisitor {
    fn record_value(&mut self, field: &tracing::field::Field, value: Value) {
        if field.name() == "message" {
            self.message = value
                .as_str()
                .map(str::to_owned)
                .or_else(|| Some(value.to_string()));
        } else {
            let value = if is_sensitive_field(field.name()) {
                Value::String(REDACTED_FIELD_VALUE.to_owned())
            } else {
                value
            };
            // Bound the field count so a deeply nested span tree can't grow an
            // entry without limit; always allow overwriting an existing key.
            if self.fields.len() >= MAX_FIELDS && !self.fields.contains_key(field.name()) {
                return;
            }
            self.fields.insert(field.name().to_owned(), value);
        }
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_value(field, Value::Bool(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_value(field, Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_value(field, Value::Number(value.into()));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        let value = Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null);
        self.record_value(field, value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field, clean_value(value.to_owned()));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.record_value(field, clean_value(value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_value(field, clean_value(format!("{value:?}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn events_inherit_structured_span_fields() {
        let collector = LogCollector::init("test-node", None);
        let subscriber = tracing_subscriber::registry().with(OperationalLogLayer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "compute",
                e3_id = "31337:9",
                stage = "computation",
                operation = "verify_c5"
            );
            let _guard = span.enter();
            tracing::info!(duration_ms = 7_u64, "span inheritance test");
        });

        let result = collector.query(None, Some(10), None, None, Some("span inheritance test"));
        let entry = result.entries.last().expect("captured tracing event");
        assert_eq!(entry.fields["e3_id"], "31337:9");
        assert_eq!(entry.fields["stage"], "computation");
        assert_eq!(entry.fields["operation"], "verify_c5");
        assert_eq!(entry.fields["duration_ms"], 7);
    }

    #[test]
    fn strip_ansi_removes_color_codes() {
        assert_eq!(strip_ansi("\u{1b}[33mhi\u{1b}[0m"), "hi");
        assert_eq!(strip_ansi("plain text"), "plain text");
        assert_eq!(strip_ansi("\u{1b}[1;36mA\u{1b}[0mB"), "AB");
        assert_eq!(strip_ansi(">>> already clean"), ">>> already clean");
    }

    #[test]
    fn strips_ansi_from_captured_message() {
        let collector = LogCollector::init("test-node", None);
        let subscriber = tracing_subscriber::registry().with(OperationalLogLayer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("\u{1b}[33m>>> ansi-marker-xyz\u{1b}[0m payload");
        });

        let result = collector.query(None, Some(50), None, None, Some("ansi-marker-xyz"));
        let entry = result.entries.last().expect("captured tracing event");
        assert!(
            !entry.message.contains('\u{1b}'),
            "message retained ANSI: {:?}",
            entry.message
        );
        assert_eq!(entry.message, ">>> ansi-marker-xyz payload");
    }

    #[test]
    fn redacts_sensitive_event_and_span_fields_before_storage() {
        let collector = LogCollector::init("test-node", None);
        let subscriber = tracing_subscriber::registry().with(OperationalLogLayer);
        let sentinels = [
            "wallet-private-key-sentinel",
            "keyshare-sentinel",
            "password-sentinel",
            "plaintext-sentinel",
            "credential-sentinel",
            "jwt-sentinel",
        ];

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "sensitive-span",
                private_key = sentinels[0],
                key_share = ?sentinels[1],
                password = sentinels[2],
                e3_id = "31337:11"
            );
            let _guard = span.enter();
            tracing::info!(
                decrypted_plaintext = sentinels[3],
                signing_credentials = sentinels[4],
                pinata_jwt = sentinels[5],
                tx_hash = "0xsafe",
                "sensitive redaction test"
            );
        });

        let result = collector.query(None, Some(10), None, None, Some("sensitive redaction test"));
        let entry = result.entries.last().expect("captured tracing event");
        for field in [
            "private_key",
            "key_share",
            "password",
            "decrypted_plaintext",
            "signing_credentials",
            "pinata_jwt",
        ] {
            assert_eq!(entry.fields[field], REDACTED_FIELD_VALUE);
        }
        assert_eq!(entry.fields["e3_id"], "31337:11");
        assert_eq!(entry.fields["tx_hash"], "0xsafe");

        let serialized = serde_json::to_string(entry).expect("log entry must serialize");
        for sentinel in sentinels {
            assert!(
                !serialized.contains(sentinel),
                "sensitive value leaked through field redaction: {sentinel}"
            );
        }
    }

    #[test]
    fn sensitive_field_matching_handles_common_name_styles() {
        for field in [
            "privateKey",
            "SECRET_KEY",
            "threshold-keyshare",
            "raw_plaintext",
            "rpc_url",
            "access_token",
        ] {
            assert!(is_sensitive_field(field), "field was not redacted: {field}");
        }
        for field in ["public_key", "tx_hash", "e3_id", "token_amount"] {
            assert!(
                !is_sensitive_field(field),
                "safe field was redacted: {field}"
            );
        }
    }
}
