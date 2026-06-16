############### stage 0: base-dev ###############
ARG RUST_VERSION=1.91.1
ARG SKIP_SOLIDITY=0

FROM rust:${RUST_VERSION}-slim-bullseye AS base-dev

ENV CARGO_HOME=/usr/local/cargo

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    jq pkg-config libssl-dev curl wget ca-certificates protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/argotorg/solidity/releases/download/v0.8.27/solc-static-linux \
    && chmod +x solc-static-linux \
    && mv solc-static-linux /usr/local/bin/solc \
    && solc --version

RUN curl -sSfL https://risczero.com/install | bash

RUN cargo install --locked cargo-chef

#################################################
############### stage 1: chef ###################
FROM base-dev AS chef
WORKDIR /app

# COPY examples/CRISP/.interfold/support/dev/Cargo.toml examples/CRISP/.interfold/support/dev/
COPY examples/CRISP/server/Cargo.toml examples/CRISP/server/
COPY examples/CRISP/program/Cargo.toml examples/CRISP/program/
COPY examples/CRISP/program/client/Cargo.toml examples/CRISP/program/client/
COPY examples/CRISP/program/core/Cargo.toml examples/CRISP/program/core/
COPY examples/CRISP/Cargo.toml examples/CRISP/
COPY examples/CRISP/crates/zk-inputs/Cargo.toml examples/CRISP/crates/zk-inputs/

COPY crates/sdk/Cargo.toml crates/sdk/
COPY Cargo.toml Cargo.lock ./
COPY crates/compute-provider/Cargo.toml crates/compute-provider/

WORKDIR /app/examples/CRISP/server
RUN cargo chef prepare --recipe-path recipe.json

############### stage 2: planner ###############
FROM base-dev AS planner

ARG SKIP_SOLIDITY
ENV SKIP_SOLIDITY=${SKIP_SOLIDITY}

WORKDIR /app
COPY --from=chef /app/examples/CRISP/server/recipe.json \
    /app/examples/CRISP/server/recipe.json

COPY examples/CRISP/server/Cargo.toml examples/CRISP/server/Cargo.lock examples/CRISP/server/
COPY examples/CRISP/program/core/Cargo.toml examples/CRISP/program/core/
COPY examples/CRISP/crates/zk-inputs/Cargo.toml examples/CRISP/crates/zk-inputs/

COPY Cargo.lock ./Cargo.lock
COPY Cargo.toml ./Cargo.toml

# find crates/* -name "Cargo.toml" -not -path "*/support/*" -printf "COPY %p %p\n"
COPY crates/aggregator/Cargo.toml crates/aggregator/Cargo.toml
COPY crates/bfv-client/Cargo.toml crates/bfv-client/Cargo.toml
COPY crates/ciphernode-builder/Cargo.toml crates/ciphernode-builder/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml
COPY crates/compute-provider/Cargo.toml crates/compute-provider/Cargo.toml
COPY crates/config/Cargo.toml crates/config/Cargo.toml
COPY crates/console/Cargo.toml crates/console/Cargo.toml
COPY crates/crypto/Cargo.toml crates/crypto/Cargo.toml
COPY crates/data/Cargo.toml crates/data/Cargo.toml
COPY crates/entrypoint/Cargo.toml crates/entrypoint/Cargo.toml
COPY crates/events/Cargo.toml crates/events/Cargo.toml
COPY crates/evm/Cargo.toml crates/evm/Cargo.toml
COPY crates/evm-helpers/Cargo.toml crates/evm-helpers/Cargo.toml
COPY crates/fhe/Cargo.toml crates/fhe/Cargo.toml
COPY crates/fhe-params/Cargo.toml crates/fhe-params/Cargo.toml
COPY crates/fs/Cargo.toml crates/fs/Cargo.toml
COPY crates/hamt/Cargo.toml crates/hamt/Cargo.toml
COPY crates/indexer/Cargo.toml crates/indexer/Cargo.toml
COPY crates/init/Cargo.toml crates/init/Cargo.toml
COPY crates/keyshare/Cargo.toml crates/keyshare/Cargo.toml
COPY crates/logger/Cargo.toml crates/logger/Cargo.toml
COPY crates/multithread/Cargo.toml crates/multithread/Cargo.toml
COPY crates/net/Cargo.toml crates/net/Cargo.toml
COPY crates/program-server/Cargo.toml crates/program-server/Cargo.toml
COPY crates/request/Cargo.toml crates/request/Cargo.toml
COPY crates/sdk/Cargo.toml crates/sdk/Cargo.toml
COPY crates/sortition/Cargo.toml crates/sortition/Cargo.toml
COPY crates/daemon-server/Cargo.toml crates/daemon-server/Cargo.toml
COPY crates/support-scripts/Cargo.toml crates/support-scripts/Cargo.toml
COPY crates/sync/Cargo.toml crates/sync/Cargo.toml
COPY crates/test-helpers/Cargo.toml crates/test-helpers/Cargo.toml
COPY crates/tests/Cargo.toml crates/tests/Cargo.toml
COPY crates/trbfv/Cargo.toml crates/trbfv/Cargo.toml
COPY crates/utils/Cargo.toml crates/utils/Cargo.toml
COPY crates/utils-derive/Cargo.toml crates/utils-derive/Cargo.toml
COPY crates/wasm/Cargo.toml crates/wasm/Cargo.toml
COPY crates/zk-helpers/Cargo.toml crates/zk-helpers/Cargo.toml

RUN set -eux; \
    find \
    examples/CRISP/program \
    examples/CRISP/crates \
    crates \
    -type f -name Cargo.toml ! -path '*/target/*' -print0 \
    | while IFS= read -r -d '' manifest_path; do \
        crate_dir="$(dirname "$manifest_path")"; \
        if [ "$manifest_path" = "examples/CRISP/program/Cargo.toml" ]; then \
            continue; \
        fi; \
        mkdir -p "$crate_dir/src"; \
        if [ ! -f "$crate_dir/src/lib.rs" ] && [ ! -f "$crate_dir/src/main.rs" ]; then \
            echo "// Stub lib.rs for $crate_dir" > "$crate_dir/src/lib.rs"; \
        fi; \
    done

WORKDIR /app/examples/CRISP/server
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/app/target,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

############### stage 3: builder ###############
FROM base-dev AS builder

ARG SKIP_SOLIDITY
ENV SKIP_SOLIDITY=${SKIP_SOLIDITY}

WORKDIR /app

COPY examples/CRISP/.interfold/   examples/CRISP/.interfold/
COPY examples/CRISP/server/    examples/CRISP/server/
COPY examples/CRISP/program/   examples/CRISP/program/
COPY examples/CRISP/crates/   examples/CRISP/crates/
COPY examples/CRISP/Cargo.*    examples/CRISP/
COPY Cargo.*                        ./
COPY crates/           crates/
COPY crates/compute-provider/     crates/compute-provider/

WORKDIR /app/examples/CRISP
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/app/target,sharing=locked \
    cargo build --locked --release --bin server && \
    mkdir -p /app/dist && cp target/release/server /app/dist/server

############### stage 4: runtime ###############
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /

COPY --from=builder /app/dist/server \
    /usr/local/bin/server
ENTRYPOINT ["/usr/local/bin/server"]
