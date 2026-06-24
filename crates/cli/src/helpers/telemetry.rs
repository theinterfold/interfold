// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_config::AppConfig;
use e3_logger::{LogCollector, OperationalLogLayer};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn setup_simple_tracing(log_level: Level) {
    LogCollector::init("interfold", None);
    let targets = Targets::new()
        .with_default(log_level)
        .with_target("alloy_pubsub", Level::WARN);
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(false),
        )
        .with(OperationalLogLayer)
        .with(targets)
        .try_init();
}

pub fn setup_tracing(config: &AppConfig, log_level: Level) -> Result<()> {
    let name = config.name();
    LogCollector::init(&name, Some(operational_log_path(config)));

    let targets = Targets::new()
        .with_default(log_level)
        .with_target("alloy_pubsub", Level::WARN);

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
            let telemetry =
                tracing_opentelemetry::layer().with_tracer(provider.tracer("interfold-ciphernode"));

            let _ = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
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
