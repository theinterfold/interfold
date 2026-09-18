ARG RUST_VERSION=1.91.1
FROM rust:${RUST_VERSION}-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config git libssl-dev ca-certificates protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The support workspace uses repository-local guest dependencies.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY examples/CRISP/program ./examples/CRISP/program
RUN cargo build --locked --release --manifest-path crates/support/Cargo.toml -p e3-support-app
# Mount a separately built OpenVM worker, its configuration, and its proving artifacts.
ENV OPENVM_BIND_ADDR=0.0.0.0:13151
CMD ["./crates/support/target/release/e3-support-app"]
