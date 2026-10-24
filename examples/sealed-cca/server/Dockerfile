# The sealed-cca coordination server and its Avail helper.
#
# Build from the repository root, after the host build of the workspace packages that the server
# imports (the image does not rebuild them: the SDK build needs the circuit toolchain):
#
#   pnpm install && pnpm evm:build && pnpm wasm:build && pnpm sdk:build
#   (cd examples/sealed-cca && pnpm compile && pnpm build:sdk)   # build:sdk writes sdk/dist, which the server imports
#   docker build -f examples/sealed-cca/server/Dockerfile -t sealed-cca-server .
#
# The ignore file next to this Dockerfile keeps secrets and build output out of the image.

# --- The Avail helper, built from source ---
FROM rust:1.91-bookworm AS da-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY examples/sealed-cca/Cargo.toml examples/sealed-cca/Cargo.lock examples/sealed-cca/rust-toolchain.toml ./examples/sealed-cca/
COPY examples/sealed-cca/da ./examples/sealed-cca/da
COPY examples/sealed-cca/program ./examples/sealed-cca/program
COPY examples/sealed-cca/runner ./examples/sealed-cca/runner
RUN cargo build --release --locked --manifest-path examples/sealed-cca/Cargo.toml -p sealed-cca-da

# --- The server's Node dependencies ---
FROM node:22-bookworm-slim AS node-builder
RUN corepack enable
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile --filter sealed-cca-example...

# --- Runtime ---
FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=da-builder /src/examples/sealed-cca/target/release/sealed-cca-da /usr/local/bin/sealed-cca-da
COPY --from=node-builder /app /app
WORKDIR /app/examples/sealed-cca

ENV NODE_ENV=production \
    PORT=8080 \
    SEALED_CCA_DA_BIN=/usr/local/bin/sealed-cca-da \
    DATA_DIRECTORY=/data

# Keep the published objects and the Avail publication records on a volume: after a restart the
# server resumes the publications that it did not finish.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
EXPOSE 8080
USER node
CMD ["./node_modules/.bin/tsx", "server/index.ts"]
