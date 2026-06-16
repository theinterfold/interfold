# ────────────────────────────────────────────────────────────────────────────────
#   Base image & build-time versions
# ────────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

ARG CPP_VERSION=2024.1.5
ARG RUST_VERSION=1.91.1

# ────────────────────────────────────────────────────────────────────────────────
#   OS packages
# ────────────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake curl git libssl-dev pkg-config \
    python3 python3-pip sudo wget jq \
 && rm -rf /var/lib/apt/lists/*

# Node 18 / 22 + pnpm
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y nodejs \
 && npm install -g corepack concurrently wait-on \
 && corepack enable \
 && corepack prepare pnpm@10.7.1 --activate

# ────────────────────────────────────────────────────────────────────────────────
#  Non-root user (skip if it already exists)
# ────────────────────────────────────────────────────────────────────────────────
ARG USERNAME=ubuntu
ARG USER_UID=1000
ARG USER_GID=100         # use any free GID you like

RUN set -eux; \
    if ! id -u "${USERNAME}" 2>/dev/null; then \
        groupadd --gid "${USER_GID}" "${USERNAME}"; \
        useradd  --uid "${USER_UID}" --gid "${USER_GID}" -m "${USERNAME}"; \
    fi && \
    echo "${USERNAME} ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} && \
    chmod 0440 /etc/sudoers.d/${USERNAME}

USER $USERNAME
WORKDIR /home/$USERNAME

# ────────────────────────────────────────────────────────────────────────────────
#   Rust toolchain
# ────────────────────────────────────────────────────────────────────────────────
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
 | sh -s -- -y --default-toolchain ${RUST_VERSION}
ENV PATH="/home/${USERNAME}/.cargo/bin:${PATH}"
RUN rustup component add rustfmt clippy
ENV RUSTFLAGS="-C debuginfo=0 -C strip=symbols" \
    CARGO_TERM_COLOR=always
RUN cargo install --locked wasm-pack

# ────────────────────────────────────────────────────────────────────────────────
#   Foundry
# ────────────────────────────────────────────────────────────────────────────────
ENV PATH="/home/${USERNAME}/.foundry/bin:${PATH}"
RUN curl -L https://foundry.paradigm.xyz | bash \
 && foundryup

# ────────────────────────────────────────────────────────────────────────────────
#   Helpers (yq)  & workspace dir
# ────────────────────────────────────────────────────────────────────────────────
RUN sudo wget -qO- https://github.com/mikefarah/yq/releases/download/v4.45.1/yq_linux_amd64.tar.gz \
 | sudo tar xz -C /usr/local/bin --transform='s|yq_linux_amd64|yq|' --no-same-owner

RUN sudo mkdir -p /app && sudo chown -R $USERNAME:$USERNAME /app
WORKDIR /app/examples/CRISP

# Pre-set pnpm store path (speeds up mounts)
RUN pnpm config set store-dir "/home/${USERNAME}/.pnpm-store" \
 && pnpm --version

# ────────────────────────────────────────────────────────────────────────────────
#   Default entrypoint
# ────────────────────────────────────────────────────────────────────────────────
ENTRYPOINT ["bash", "-l"]
