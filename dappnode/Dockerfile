# DAppNode Interfold Ciphernode Dockerfile
# Uses official upstream image from GitHub Container Registry

ARG UPSTREAM_VERSION
FROM ghcr.io/theinterfold/ciphernode:${UPSTREAM_VERSION} AS upstream

# Runtime image
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gettext-base \
    iproute2 \
    jq \
    expect \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash ciphernode

# Create writable data and ephemeral credential-upload directories.
RUN install -d -o ciphernode -g ciphernode -m 0750 /data \
    && install -d -o ciphernode -g ciphernode -m 0700 /run/secrets \
    && install -d -o ciphernode -g ciphernode -m 0700 /run/interfold

# Copy binary from upstream
COPY --from=upstream /usr/local/bin/interfold /usr/local/bin/interfold
RUN chmod +x /usr/local/bin/interfold

# Copy entrypoint and config template
COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=755 healthcheck.sh /usr/local/bin/healthcheck.sh
COPY --chmod=644 config.template.yaml /opt/config.template.yaml
COPY --chmod=444 provision-credentials.exp /opt/provision-credentials.exp

# Labels
LABEL maintainer="Interfold <https://interfold.network>"
LABEL org.opencontainers.image.source="https://github.com/theinterfold/interfold"
LABEL org.opencontainers.image.description="Interfold Ciphernode for DAppNode"

USER ciphernode
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
