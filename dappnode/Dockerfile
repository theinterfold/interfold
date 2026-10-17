# DAppNode Interfold Ciphernode Dockerfile
# Uses official upstream image from GitHub Container Registry

ARG UPSTREAM_VERSION=0.19.0
FROM ghcr.io/theinterfold/ciphernode:${UPSTREAM_VERSION}

USER root

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext-base \
    iproute2 \
    nginx-light \
    python3-websocket \
    python3-yaml \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# The data volume stages wizard uploads until encrypted identity provisioning succeeds.
RUN install -d -o ciphernode -g ciphernode -m 0700 /data
ENV CONFIG_DIR=/data

# Copy package startup and configuration
COPY --chmod=755 dappnode/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=755 dappnode/healthcheck.sh /usr/local/bin/healthcheck.sh
COPY --chmod=644 dappnode/configure.py /usr/local/bin/configure.py
COPY --chmod=644 deployments/manifest.json /opt/deployments.json
COPY --chmod=644 dappnode/nginx.conf /opt/nginx.conf.template
COPY --chmod=644 dappnode/rpc-proxy.conf /opt/rpc-proxy.conf.template
COPY --chmod=644 dappnode/starting.html /opt/starting.html
ARG DAPPNODE_NETWORK=mainnet
RUN printf '%s\n' "${DAPPNODE_NETWORK}" > /opt/package-network

# Labels
LABEL maintainer="Gnosis Guild <https://gnosisguild.org>"
LABEL org.opencontainers.image.source="https://github.com/theinterfold/interfold"
LABEL org.opencontainers.image.description="Interfold Ciphernode for Dappnode"

USER ciphernode
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
