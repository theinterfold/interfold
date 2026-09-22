ARG RISC0_TOOLCHAIN=1.91.1

# Keep the base image content-addressed. The tag documents the matching RISC Zero Rust
# toolchain; the digest prevents a registry-side tag change from changing the guest ELF.
FROM risczero/risc0-guest-builder:r0.${RISC0_TOOLCHAIN}@sha256:fafb377a44e1cfca415577c48d2f7012bda99ed36f2fae27f9a663b9fe6048f0
