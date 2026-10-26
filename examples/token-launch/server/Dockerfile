# The token-launch coordination server and its Avail helper.
#
# Build from the repository root, after the host build of the workspace packages that the server
# imports (the image does not rebuild them: the SDK build needs the circuit toolchain):
#
#   pnpm install && pnpm evm:build && pnpm wasm:build && pnpm sdk:build
#   (cd examples/token-launch && pnpm compile && pnpm build:sdk)   # build:sdk writes sdk/dist, which the server imports
#   docker build -f examples/token-launch/server/Dockerfile -t token-launch-server .
#
# The ignore file next to this Dockerfile keeps secrets and build output out of the image.

# --- The Avail helper, built from source ---
FROM rust:1.91-bookworm AS da-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY examples/token-launch/Cargo.toml examples/token-launch/Cargo.lock examples/token-launch/rust-toolchain.toml ./examples/token-launch/
COPY examples/token-launch/da ./examples/token-launch/da
COPY examples/token-launch/program ./examples/token-launch/program
COPY examples/token-launch/runner ./examples/token-launch/runner
RUN cargo build --release --locked --manifest-path examples/token-launch/Cargo.toml -p token-launch-da

# --- The server's Node dependencies ---
FROM node:22-bookworm-slim AS node-builder
RUN corepack enable
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile --filter token-launch-example...

# --- Runtime ---
FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=da-builder /src/examples/token-launch/target/release/token-launch-da /usr/local/bin/token-launch-da
COPY --from=node-builder /app /app
WORKDIR /app/examples/token-launch

ENV NODE_ENV=production \
    PORT=8080 \
    TOKEN_LAUNCH_DA_BIN=/usr/local/bin/token-launch-da \
    DATA_DIRECTORY=/data

# Keep the published objects and the Avail publication records on a volume: after a restart the
# server resumes the publications that it did not finish.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
EXPOSE 8080
USER node
CMD ["./node_modules/.bin/tsx", "server/index.ts"]
