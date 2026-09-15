ARG RISC0_TOOLCHAIN=1.91.1

# Keep the base image content-addressed. The tag documents the matching RISC Zero Rust
# toolchain; the digest prevents a registry-side tag change from changing the guest ELF.
FROM risczero/risc0-guest-builder:r0.${RISC0_TOOLCHAIN}@sha256:fafb377a44e1cfca415577c48d2f7012bda99ed36f2fae27f9a663b9fe6048f0

# fhe.rs generates its Protobuf bindings while the guest dependency graph is compiled.
# The upstream RISC Zero guest-builder image does not include protoc.
RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler=3.12.4-1ubuntu7.22.04.6 && \
    rm -rf /var/lib/apt/lists/*
