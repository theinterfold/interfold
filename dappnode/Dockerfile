# DAppNode Interfold Ciphernode Dockerfile
# Uses official upstream image from GitHub Container Registry

ARG UPSTREAM_VERSION
FROM ghcr.io/gnosisguild/ciphernode:${UPSTREAM_VERSION} AS upstream

# Runtime image
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    procps \
    gettext-base \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash ciphernode

# Create data directory
RUN mkdir -p /data && chown ciphernode:ciphernode /data

# Copy binary from upstream
COPY --from=upstream /usr/local/bin/interfold /usr/local/bin/interfold
RUN chmod +x /usr/local/bin/interfold

# Copy entrypoint and config template
COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=644 config.template.yaml /opt/config.template.yaml

# Labels
LABEL maintainer="Gnosis Guild <https://gnosisguild.org>"
LABEL org.opencontainers.image.source="https://github.com/gnosisguild/interfold"
LABEL org.opencontainers.image.description="Interfold Ciphernode for DAppNode"

USER ciphernode
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD pgrep -f interfold || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
