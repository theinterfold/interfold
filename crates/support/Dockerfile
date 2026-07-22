ARG RUST_VERSION=1.91.1
ARG RISC0_VERSION=3.0.3
ARG RISC0_TOOLCHAIN=1.88.0
ARG RZUP_SHA256=7cdc1dd5d4b8ef38ea6170c45bd29ba65d389f0e96b365da61631d1fc5c6c1ca
ARG FOUNDRY_VERSION=1.7.1
ARG FOUNDRY_LINUX_AMD64_SHA256=cf7e688ed0c4c48adffca788b496076e31060b67ac5afe1e43dbb5499c20c88b
ARG SKIP_SOLIDITY=0
FROM rust:${RUST_VERSION}-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS base-dev

ARG RISC0_VERSION
ARG RISC0_TOOLCHAIN
ARG RZUP_SHA256
ARG FOUNDRY_VERSION
ARG FOUNDRY_LINUX_AMD64_SHA256
ARG DEBIAN_SNAPSHOT=20260720T000000Z

ENV CARGO_HOME=/usr/local/cargo
RUN sed -ri \
        "s|https?://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|g; \
         s|https?://security.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    git \
    libssl-dev \
    curl \
    sudo \
    ca-certificates \
    protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*
    
# Create user
ENV USERNAME=devuser
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
WORKDIR /home/$USERNAME

ENV SHELL=/bin/bash

ENV PATH="/home/${USERNAME}/.risc0/bin:${PATH}"
RUN install -d /home/${USERNAME}/.risc0/bin \
    && curl --fail --show-error --silent --location \
        --output /tmp/rzup \
        https://risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/prod/Linux-X64/rzup \
    && echo "${RZUP_SHA256}  /tmp/rzup" | sha256sum --check --strict \
    && install -m 0755 /tmp/rzup /home/${USERNAME}/.risc0/bin/rzup \
    && rm /tmp/rzup
RUN rzup install rust ${RISC0_TOOLCHAIN}
RUN rzup install r0vm ${RISC0_VERSION}
RUN rzup install cargo-risczero ${RISC0_VERSION}

RUN sudo ln -sf "$(readlink -f "$(command -v r0vm)")" /usr/local/bin/r0vm && \
    test -x /usr/local/bin/r0vm
ENV RISC0_SERVER_PATH=/usr/local/bin/r0vm

ENV PATH="/home/${USERNAME}/.foundry/bin:${PATH}"
RUN install -d /home/${USERNAME}/.foundry/bin \
    && curl --fail --show-error --silent --location \
        --output /tmp/foundry.tar.gz \
        "https://github.com/foundry-rs/foundry/releases/download/v${FOUNDRY_VERSION}/foundry_v${FOUNDRY_VERSION}_linux_amd64.tar.gz" \
    && echo "${FOUNDRY_LINUX_AMD64_SHA256}  /tmp/foundry.tar.gz" | sha256sum --check --strict \
    && tar -xzf /tmp/foundry.tar.gz -C /home/${USERNAME}/.foundry/bin \
    && rm /tmp/foundry.tar.gz \
    && forge --version \
    && cast --version \
    && anvil --version

COPY . /app

RUN sudo chown -R $USERNAME:$USERNAME /app

WORKDIR /app

CMD ["/bin/bash"]
