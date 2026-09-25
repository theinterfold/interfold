#!/usr/bin/env python3
"""r123: derive the keccak-domain DA leg test from the r122 file.

Deterministic, count-asserted replacements. Re-run:
    python3 poc/r123/build_test_r123.py
and verify:  diff crates/zk-prover/tests/da_secure_small_r123.rs <committed copy>
Every replacement is anchored on text RAN-verified present in the r122 source
(count asserted; any drift hard-fails). The on-disk r123 test is the
commit-of-record for this round; this script documents the derivation.
"""
import sys

SRC = "crates/zk-prover/tests/da_secure_small_r122.rs"
DST = "crates/zk-prover/tests/da_secure_small_r123.rs"

text = open(SRC).read()
orig_len = len(text)
misses = []


def rep(old, new, count):
    global text
    n = text.count(old)
    if n != count:
        misses.append(f"count {n} (expected {count}) for anchor: {old[:80]!r}")
        return
    text = text.replace(old, new)


# ---- imports (r123 additions) ----
rep("use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};",
    "use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter, Serialize};", 1)
rep("use e3_events::CircuitVariant;",
    "use e3_committee_hash::{decryption_domain_limbs, DecryptionDomainContext};\n"
    "use e3_events::CircuitVariant;\n"
    "use alloy::primitives::{keccak256, B256, U256};\n"
    "use e3_zk_helpers::circuits::threshold::user_data_encryption::utils::compute_public_key_commitment;", 1)

# header doc: one-line marker (full doc lives in the committed r123 file;
# the r122 header's stand-in disclaimer is the load-bearing difference)
rep("[stand-in (1,2), not the production keccak domain]",
    "[r123: the REAL production keccak-derived domain]", 1)
rep("//! r122 - the `DecryptionAggregator` (DA) PRODUCTION-FIELD anchor.",
    "//! r123 - the `DecryptionAggregator` (DA) anchor on the PRODUCTION keccak\n"
    "//! decryption domain (the r122 (1,2) stand-in RAN-CLOSED). Same coherent\n"
    "//! world, same stage tree (reused poc/r122/root), zero compile. Domain\n"
    "//! derivation = the production code path (crates/multithread/src/multithread.rs:452-457):\n"
    "//!   domain_hash = keccak256(abi.encode(chainId, interfold_address, e3_id,\n"
    "//!                committee_hash, ciphertext_output_hash, committee_pk))\n"
    "//!   (domain_hi, domain_lo) = hi/lo 128-bit limbs. Every C6 inner + the\n"
    "//! c6_fold chain + the DA EVM witness carry the SAME derived keccak domain.", 1)
rep("//! DOMAIN STAND-IN (HONEST): (domain_hi, domain_lo) = (1, 2) for all 10\n"
    "//! inners.",
    "//! DOMAIN (r123: REAL keccak, no stand-in): (domain_hi, domain_lo) for all 10\n"
    "//! inners = the production keccak-derived limbs (see header).", 1)
rep("//! consistency bind, exercised IDENTICALLY by the (1,2) stand-in. Every\n"
    "//! OTHER cross-assert runs on real RAN data. This is the ONE\n"
    "//! intentionally-simplified input; the wall and RAM of the DA proof are\n"
    "//! domain-invariant.",
    "//! consistency bind, run on the REAL keccak limbs. EVERY input is now\n"
    "//! production-shape; the (1,2) stand-in line from r122 is closed.", 1)
rep("//! STAGE TREE (produced by poc/r122/stage_da_secure_small_r122.py):",
    "//! STAGE TREE (reused from r122 byte-conserved tree - zero compile this round):", 1)

# ---- context constants ----
rep("/// SMALL committee: N=19, T=9, H=10, L=3.",
    "/// Production-context identity for the keccak decryption domain (test-only\n"
    "/// deployment values; the DERIVATION path is the production one).\n"
    "const CHAIN_ID: u64 = 31_337;\n"
    "const E3_TEST_ID: u64 = 123;\n"
    "const INTERFOLD_ADDRESS: &str = \"0x1111111111111111111111111111111111111111\";\n\n"
    "/// SMALL committee: N=19, T=9, H=10, L=3.", 1)

# ---- env var + e3 ids + run command (5 env refs, 3 da ids, rest once each) ----
rep("E3_R122_STAGE_ROOT", "E3_R123_STAGE_ROOT", 4)
rep("let e3 = format!(\"e3-r122-c6i-{}", "let e3 = format!(\"e3-r123-c6i-{}", 1)
rep('let e3_c7 = "e3-r122-c7";', 'let e3_c7 = "e3-r123-c7";', 1)
rep('"e3-r122-da"', '"e3-r123-da"', 3)
rep("da_secure_small_r122 -- --nocapture", "da_secure_small_r123 -- --nocapture", 1)
# the env-var line in the header run command doubles $(pwd) prefix; r122 has exactly one
rep("E3_R122_STAGE_ROOT=$(pwd)/poc/r122/root", "E3_R123_STAGE_ROOT=$(pwd)/poc/r122/root", 0)
text = text.replace("E3_R122_STAGE_ROOT=$(pwd)/poc/r122/root",
                    "E3_R123_STAGE_ROOT=$(pwd)/poc/r122/root")

# ---- THE derivation block (single physical println line; Rust has NO\n"
#      implicit string concatenation - one literal per physical line with \,\n"
#      continuations is the ONLY in-literal continuation) ----
old_inner = "    let prover = ZkProver::new(&backend);\n    let mut walls: Vec<(String, f64)> = Vec::new();\n\n    // ---- 10 C6 inners (Recursive variant), from the SAME shared world ----"
new_inner = (
    "    let prover = ZkProver::new(&backend);\n"
    "    let mut walls: Vec<(String, f64)> = Vec::new();\n\n"
    "    // ---- PRODUCTION keccak decryption domain (the production code path) ----\n"
    "    // Same 19 ordered addresses the DA consumes below as on-chain topNodes.\n"
    "    let addresses: Vec<Address> = (0..N)\n"
    "        .map(|i| Address::with_last_byte((0xA0u8).wrapping_add(i as u8)))\n"
    "        .collect();\n"
    "    let chain_id = CHAIN_ID;\n"
    "    let e3_num = U256::from(E3_TEST_ID);\n"
    "    let interfold_address: Address = INTERFOLD_ADDRESS.parse().expect(\"addr\");\n"
    "    let committee_hash = e3_committee_hash::hash_committee_addresses(&addresses);\n"
    "    // pk_commitment = C1-style commitment of the SAME aggregated pk this\n"
    "    // world encrypted with (the on-chain committed pk of the topNodes).\n"
    "    let (params_r123, _) = build_pair_for_preset(preset).unwrap();\n"
    "    let pk_commitment: [u8; 32] =\n"
    "        compute_public_key_commitment(&params_r123, &pk).expect(\"pk commitment\");\n"
    "    let ct_bytes = ct.to_bytes();\n"
    "    let ct_output_hash: B256 = keccak256(&ct_bytes);\n"
    "    let domain_ctx = DecryptionDomainContext {\n"
    "        interfold_address,\n"
    "        committee_hash,\n"
    "        committee_public_key: B256::from(pk_commitment),\n"
    "    };\n"
    "    let domain = decryption_domain_limbs(chain_id, e3_num, domain_ctx, ct_output_hash);\n"
    "    println!(\n"
    "        \"  r123 PRODUCTION keccak domain: hi={} lo={} pkc={} cth={} chain={} e3={}\",\n"
    "        domain.hi, domain.lo,\n"
    "        hex::encode(pk_commitment),\n"
    "        ct_output_hash,\n"
    "        chain_id,\n"
    "        E3_TEST_ID,\n"
    "    );\n\n"
    "    // ---- 10 C6 inners (Recursive variant), from the SAME shared world ----")
rep(old_inner, new_inner, 1)

# ---- stand-in domain -> derived domain ----
rep("            domain_hi: 1,\n            domain_lo: 2,",
    "            domain_hi: domain.hi,\n            domain_lo: domain.lo,", 1)

# ---- remove the now-duplicated old addresses block (declared above now) ----
rep("    let addresses: Vec<Address> = (0..N)\n"
    "        .map(|i| Address::with_last_byte((0xA0u8).wrapping_add(i as u8)))\n"
    "        .collect();\n"
    "    let slot_indices",
    "    let slot_indices", 1)

if misses:
    print("MISSES:")
    for m in misses:
        print(" -", m)
    sys.exit(1)

open(DST, "w").write(text)
print(f"OK: {orig_len} -> {len(text)} bytes; wrote {DST}")