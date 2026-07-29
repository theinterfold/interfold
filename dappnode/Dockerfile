# DAppNode Interfold Ciphernode Dockerfile.
# The exact candidate archive must be staged in this build context by CI or the developer.

ARG UPSTREAM_VERSION
ARG UPSTREAM_BINARY_SOURCE=interfold-linux-x86_64.tar.gz
ARG UPSTREAM_BINARY_SHA256

# Runtime image
FROM debian:12.15-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG UPSTREAM_VERSION
ARG UPSTREAM_BINARY_SOURCE
ARG UPSTREAM_BINARY_SHA256
ARG DEBIAN_SNAPSHOT=20260720T202350Z
ARG DEBIAN_SECURITY_SNAPSHOT=20260720T143120Z

RUN sed -ri \
        "s|https?://security\.debian\.org/debian-security|http://snapshot.debian.org/archive/debian-security/${DEBIAN_SECURITY_SNAPSHOT}|g; \
         s|https?://deb\.debian\.org/debian-security|http://snapshot.debian.org/archive/debian-security/${DEBIAN_SECURITY_SNAPSHOT}|g; \
         s|https?://deb\.debian\.org/debian|http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gettext-base \
    iproute2 \
    jq \
    expect \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash ciphernode

# Create writable data and ephemeral credential-upload directories.
RUN install -d -o ciphernode -g ciphernode -m 0750 /data \
    && install -d -o ciphernode -g ciphernode -m 0700 /run/secrets \
    && install -d -o ciphernode -g ciphernode -m 0700 /run/interfold

# Install only the staged, checksum-verified candidate binary. The archive must contain exactly the
# expected executable, report the package version, and expose the protocol-readiness surface used by
# this image's health check.
COPY ${UPSTREAM_BINARY_SOURCE} /tmp/interfold.tar.gz
RUN test -n "${UPSTREAM_VERSION}" \
    && echo "${UPSTREAM_BINARY_SHA256}" | grep -Eq '^[0-9a-f]{64}$' \
    && echo "${UPSTREAM_BINARY_SHA256}  /tmp/interfold.tar.gz" | sha256sum --check --strict \
    && test "$(tar -tzf /tmp/interfold.tar.gz)" = interfold \
    && tar -xzf /tmp/interfold.tar.gz -C /usr/local/bin interfold \
    && chmod 0755 /usr/local/bin/interfold \
    && test "$(/usr/local/bin/interfold --version)" = "interfold ${UPSTREAM_VERSION}" \
    && grep -aFq '/health/ready' /usr/local/bin/interfold \
    && grep -aFq 'interfold_ready' /usr/local/bin/interfold \
    && rm /tmp/interfold.tar.gz

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
