// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_config::AppConfig;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub fn setup_simple_tracing(log_level: Level) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            log_level,
        ))
        .try_init()
        .ok();
}

pub fn setup_tracing(config: &AppConfig, log_level: Level) -> Result<()> {
    let name = config.name();
    let maybe_otel_endpoint = config.otel();

    match maybe_otel_endpoint {
        Some(endpoint) => {
            let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .with_protocol(Protocol::Grpc)
                .build()?;

            let resource = Resource::builder().with_service_name(name).build();

            let provider = SdkTracerProvider::builder()
                .with_batch_exporter(otlp_exporter)
                .with_resource(resource)
                .build();

            let tracer = provider.tracer("interfold");
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer())
                .with(telemetry)
                .with(tracing_subscriber::filter::LevelFilter::from_level(
                    log_level,
                ))
                .try_init()
                .ok();
        }
        None => {
            // TODO: we might be able to dedupe this with above but there were
            //       issues with telemetry so have left this like so for now
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer())
                .with(tracing_subscriber::filter::LevelFilter::from_level(
                    log_level,
                ))
                .try_init()
                .ok();
        }
    }

    Ok(())
}
