# The private-round coordination server and its Avail helper.
#
# Build from the repository root, after the host build of the workspace packages that the server
# imports (the image does not rebuild them: the SDK build needs the circuit toolchain):
#
#   pnpm install && pnpm evm:build && pnpm wasm:build && pnpm sdk:build
#   (cd examples/private-round && pnpm compile && pnpm build:sdk)   # build:sdk writes sdk/dist, which the server imports
#   docker build -f examples/private-round/server/Dockerfile -t private-round-server .
#
# The ignore file next to this Dockerfile keeps secrets and build output out of the image.

# --- The Avail helper, built from source ---
FROM rust:1.91-bookworm AS da-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY examples/private-round/Cargo.toml examples/private-round/Cargo.lock examples/private-round/rust-toolchain.toml ./examples/private-round/
COPY examples/private-round/da ./examples/private-round/da
COPY examples/private-round/program ./examples/private-round/program
COPY examples/private-round/runner ./examples/private-round/runner
RUN cargo build --release --locked --manifest-path examples/private-round/Cargo.toml -p private-round-da

# --- The server's Node dependencies ---
FROM node:22-bookworm-slim AS node-builder
RUN corepack enable
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile --filter private-round-example...

# --- Runtime ---
FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=da-builder /src/examples/private-round/target/release/private-round-da /usr/local/bin/private-round-da
COPY --from=node-builder /app /app
WORKDIR /app/examples/private-round

ENV NODE_ENV=production \
    PORT=8080 \
    PRIVATE_ROUND_DA_BIN=/usr/local/bin/private-round-da \
    DATA_DIRECTORY=/data

# Keep the published objects and the Avail publication records on a volume: after a restart the
# server resumes the publications that it did not finish.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
EXPOSE 8080
USER node
CMD ["./node_modules/.bin/tsx", "server/index.ts"]
