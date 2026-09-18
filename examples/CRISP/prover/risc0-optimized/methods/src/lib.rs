// SPDX-License-Identifier: LGPL-3.0-only

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

pub use CRISP_RISC0_OPTIMIZED_GUEST_ELF as GUEST_ELF;
pub use CRISP_RISC0_OPTIMIZED_GUEST_ID as GUEST_ID;
pub const KERNEL: &str = "experimental local compute-provider, shared CRISP program source, production bincode input and RISC Zero journal";
pub const COMPUTE_PROVIDER_REVISION: &str =
    "local experimental source; identify the guest by its ELF hash";
pub const OPTIMIZATIONS: &[&str] = &[
    "lazy BFV multiplication tables",
    "checked canonical power-basis decoding",
    "direct centered RNS coefficient packing",
    "fixed-word packing fallback",
];

pub fn selected_guest() -> (
    &'static [u8],
    [u32; 8],
    &'static str,
    &'static [&'static str],
) {
    if std::env::var("CRISP_RISC0_REFERENCE").as_deref() == Ok("1") {
        (
            CRISP_RISC0_REFERENCE_GUEST_ELF,
            CRISP_RISC0_REFERENCE_GUEST_ID,
            "experimental local compute-provider with reference ciphertext decoding and packing",
            &[
                "lazy BFV multiplication tables",
                "fixed-word packing fallback",
            ],
        )
    } else {
        (GUEST_ELF, GUEST_ID, KERNEL, OPTIMIZATIONS)
    }
}
