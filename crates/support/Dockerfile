ARG RUST_VERSION=1.91.1
FROM rust:${RUST_VERSION}-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config git libssl-dev ca-certificates protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# CRISP's OpenVM proving service. It is built in the CRISP workspace against the repository crates.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY examples/CRISP/Cargo.toml examples/CRISP/Cargo.lock ./examples/CRISP/
COPY examples/CRISP/.interfold/support ./examples/CRISP/.interfold/support
COPY examples/CRISP/program ./examples/CRISP/program
COPY examples/CRISP/server ./examples/CRISP/server
COPY examples/CRISP/crates ./examples/CRISP/crates
RUN cd examples/CRISP && cargo build --locked --release --bin e3-support-scripts-openvm
# Mount the separately built OpenVM workers, their configuration, and the proving artifacts, and
# set OPENVM_PROVER_BIN, OPENVM_PROVER_BIN_CUDA, OPENVM_PROVER_CONFIG and OPENVM_BACKEND.
ENV OPENVM_BIND_ADDR=0.0.0.0:13151
CMD ["./examples/CRISP/target/release/e3-support-scripts-openvm"]
