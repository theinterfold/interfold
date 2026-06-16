FROM node:22 AS evm-builder

WORKDIR /build
COPY crates/wasm/package.json ./crates/wasm/package.json
COPY packages/interfold-react ./packages/interfold-react
COPY packages/interfold-sdk ./packages/interfold-sdk
COPY packages/interfold-config ./packages/interfold-config
COPY packages/interfold-contracts ./packages/interfold-contracts
COPY package.json .
COPY pnpm-workspace.yaml .
COPY pnpm-lock.yaml .

RUN npm install -g corepack
RUN corepack enable

# We just need the contracts to be compiled here
RUN cd packages/interfold-contracts && pnpm install && pnpm compile:contracts

# Build stage
FROM rust:1.91 AS ciphernode-builder

# Force incremental 
ENV CARGO_INCREMENTAL=1
ENV RUSTC_FORCE_INCREMENTAL=1
ENV CARGO_BUILD_JOBS=8

# Install deps
RUN apt-get update && apt-get install -y --no-install-recommends jq protobuf-compiler
RUN wget https://github.com/argotorg/solidity/releases/download/v0.8.27/solc-static-linux \
    && chmod +x solc-static-linux \
    && mv solc-static-linux /usr/local/bin/solc \
    && solc --version

# Create build directory

WORKDIR /build
COPY Cargo.lock ./Cargo.lock
COPY Cargo.toml ./Cargo.toml
COPY ./rust-toolchain.toml .

WORKDIR /build/crates
COPY --from=evm-builder /build/packages/interfold-contracts/artifacts ../packages/interfold-contracts/artifacts
COPY --from=evm-builder /build/packages/interfold-contracts/deployed_contracts.json ../packages/interfold-contracts/deployed_contracts.json

# find crates/* -name "Cargo.toml" -not -path "*/support/*" -printf "COPY %p %p\n" | sed 's|COPY \(.*\) crates/|COPY \1 ./|'
COPY crates/aggregator/Cargo.toml ./aggregator/Cargo.toml
COPY crates/bfv-client/Cargo.toml ./bfv-client/Cargo.toml
COPY crates/cli/Cargo.toml ./cli/Cargo.toml
COPY crates/ciphernode-builder/Cargo.toml ./ciphernode-builder/Cargo.toml
COPY crates/compute-provider/Cargo.toml ./compute-provider/Cargo.toml
COPY crates/committee-hash/Cargo.toml ./committee-hash/Cargo.toml
COPY crates/config/Cargo.toml ./config/Cargo.toml
COPY crates/console/Cargo.toml ./console/Cargo.toml
COPY crates/crypto/Cargo.toml ./crypto/Cargo.toml
COPY crates/data/Cargo.toml ./data/Cargo.toml
COPY crates/interfoldup/Cargo.toml ./interfoldup/Cargo.toml
COPY crates/entrypoint/Cargo.toml ./entrypoint/Cargo.toml
COPY crates/events/Cargo.toml ./events/Cargo.toml
COPY crates/evm/Cargo.toml ./evm/Cargo.toml
COPY crates/evm-helpers/Cargo.toml ./evm-helpers/Cargo.toml
COPY crates/fhe/Cargo.toml ./fhe/Cargo.toml
COPY crates/fhe-params/Cargo.toml ./fhe-params/Cargo.toml
COPY crates/fs/Cargo.toml ./fs/Cargo.toml
COPY crates/hamt/Cargo.toml ./hamt/Cargo.toml
COPY crates/indexer/Cargo.toml ./indexer/Cargo.toml
COPY crates/init/Cargo.toml ./init/Cargo.toml
COPY crates/keyshare/Cargo.toml ./keyshare/Cargo.toml
COPY crates/logger/Cargo.toml ./logger/Cargo.toml
COPY crates/multithread/Cargo.toml ./multithread/Cargo.toml
COPY crates/net/Cargo.toml ./net/Cargo.toml
COPY crates/parity-matrix/Cargo.toml ./parity-matrix/Cargo.toml
COPY crates/zk-prover/Cargo.toml ./zk-prover/Cargo.toml
COPY crates/polynomial/Cargo.toml ./polynomial/Cargo.toml
COPY crates/polynomial/benches ./polynomial/benches
COPY crates/program-server/Cargo.toml ./program-server/Cargo.toml
COPY crates/request/Cargo.toml ./request/Cargo.toml
COPY crates/safe/Cargo.toml ./safe/Cargo.toml
COPY crates/sdk/Cargo.toml ./sdk/Cargo.toml
COPY crates/slashing/Cargo.toml ./slashing/Cargo.toml
COPY crates/sortition/Cargo.toml ./sortition/Cargo.toml
COPY crates/dashboard/Cargo.toml ./dashboard/Cargo.toml
COPY crates/daemon-server/Cargo.toml ./daemon-server/Cargo.toml
COPY crates/support-scripts/Cargo.toml ./support-scripts/Cargo.toml
COPY crates/sync/Cargo.toml ./sync/Cargo.toml
COPY crates/test-helpers/Cargo.toml ./test-helpers/Cargo.toml
COPY crates/tests/Cargo.toml ./tests/Cargo.toml
COPY crates/trbfv/Cargo.toml ./trbfv/Cargo.toml
COPY crates/utils/Cargo.toml ./utils/Cargo.toml
COPY crates/utils-derive/Cargo.toml ./utils-derive/Cargo.toml
COPY crates/wasm/Cargo.toml ./wasm/Cargo.toml
COPY crates/zk-helpers/Cargo.toml ./zk-helpers/Cargo.toml

RUN echo 'fn main() { println!("cargo:warning=dependency cache build"); }' > ./entrypoint/build.rs
RUN echo 'fn main() { println!("cargo:warning=dependency cache build"); }' > ./cli/build.rs
RUN for d in ./*/ ; do \
        if [ -f "$d/Cargo.toml" ]; then \
          if [ "$d" = "./cli/" ] || [ "$d" = "./interfoldup/" ]; then \
            mkdir -p "$d/src" && \
            echo "fn main() {}" > "$d/src/main.rs"; \
          elif [ "$d" = "./utils-derive/" ]; then \
            mkdir -p "$d/src" && \
            echo "" > "$d/src/lib.rs"; \
          else \
            mkdir -p "$d/src" && \
            echo "pub fn main() {}" > "$d/src/lib.rs"; \
          fi \
        fi \
    done

# Crates with [[bin]] in Cargo.toml need stub binaries so the first build succeeds
RUN mkdir -p ./zk-helpers/src/bin && \
    echo 'fn main() {}' > ./zk-helpers/src/bin/zk_cli.rs && \
    echo 'fn main() {}' > ./zk-helpers/src/bin/compute_vk_hash.rs
RUN mkdir -p ./fhe-params/src/bin && echo 'fn main() {}' > ./fhe-params/src/bin/search_params.rs

RUN cargo build --locked --release

COPY ./crates .

RUN find . -name "*.rs" -exec touch {} +
RUN cargo build --locked --release -p e3-cli

# Runtime stage
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends iptables dnsutils iputils-ping ca-certificates jq && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash ciphernode

# Create necessary directories with proper permissions
RUN mkdir -p /home/ciphernode/.config/interfold \
    /home/ciphernode/.local/share/interfold \
    /run/secrets && \
    chown -R ciphernode:ciphernode /home/ciphernode /run/secrets

# Switch to non-root user
USER ciphernode
WORKDIR /home/ciphernode

# Copy binary from builder
COPY --from=ciphernode-builder --chown=ciphernode:ciphernode /build/target/release/interfold /usr/local/bin/
COPY --from=ciphernode-builder --chmod=755 --chown=ciphernode:ciphernode /build/crates/ciphernode-entrypoint.sh /usr/local/bin/

# Environment variables for configuration
ENV CONFIG_DIR=/home/ciphernode/.config/interfold
ENV DATA_DIR=/home/ciphernode/.local/share/interfold

# Add entrypoint script
ENTRYPOINT ["ciphernode-entrypoint.sh"]
