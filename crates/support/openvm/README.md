# CRISP OpenVM compute backend

OpenVM replaces RISC Zero and Boundless in the support service and the CRISP deployment path. This
is a new guest and verifier deployment, not an upgrade of an existing receipt. Existing deployment
records and legacy RISC Zero contracts remain unchanged. This branch does not deploy contracts or
change a live network.

## Build

Use Rust 1.91.1 and the OpenVM CLI and guest toolchain for the pinned v2.0.2 SDK. Install the SDK
prerequisites before these commands. CUDA builds also require the CUDA toolkit, driver libraries,
and the correct GPU architecture in the build environment.

From the repository root:

```sh
pnpm openvm setup-fhe
pnpm openvm guest build
pnpm openvm guest keygen --app-only
pnpm openvm prover-build --features cuda
pnpm openvm service-build --release
```

Omit `--features cuda` for a CPU worker. The native HTTP service has no SDK or CUDA dependency. The
worker is a separate executable so a proof failure does not abort the service process.

The FHE setup checks out a fixed revision and applies the checked-in optimization patch under
`target/openvm/fhe`. It refuses unrelated changes. The optimized guest enables direct coefficient
packing, canonical power-basis decoding, lazy BFV products, modular Poseidon2, SHA-256, and Keccak.
The native service uses the same CRISP policy source and compares its journal with the proved
output.

Use the built worker's `prepare <app.pk> <guest.vmexe> <new-output-directory>` command to generate
the full aggregation key and application identity. Do not use an aggregation key from another VM
configuration. `check` and `prove` derive the identity from the executable and keys and reject a
mismatch.

Obtain the compatible Halo2 proving key, KZG parameters, and generated verifier artifact for the
pinned OpenVM release. Verify their provenance and checksums. Keep all generated artifacts under
`target/` or outside the repository. Never commit proving keys, proofs, inputs, benchmark reports,
operator accounts, or machine-specific configuration.

## Worker configuration

Create a private deployment-local JSON configuration with these fields. There are no deployment
identity or path defaults.

| Field                  | Value                                                                    |
| ---------------------- | ------------------------------------------------------------------------ |
| `app_pk`               | Absolute path to the guest application proving key                       |
| `executable`           | Absolute path to the guest VM executable                                 |
| `aggregation_pk`       | Absolute path to the full aggregation key from `prepare`                 |
| `halo2_pk`             | Absolute path to the compatible Halo2 proving key                        |
| `halo2_params_dir`     | Absolute path to the KZG parameter directory                             |
| `verifier_artifact`    | Absolute path to the SDK-generated verifier bytecode JSON                |
| `verifier_sha256`      | SHA-256 digest of that JSON file, lowercase hexadecimal without a prefix |
| `app_commit`           | The `app_commit` object from `prepare`'s identity JSON                   |
| `segment_memory_bytes` | Nonzero segment memory limit for the prover machine                      |

Run `interfold-openvm-prover check <config.json>` before service startup. Configure
`OPENVM_PROVER_BIN` and `OPENVM_PROVER_CONFIG` with absolute file paths, then run
`pnpm openvm service-start`. For the Interfold CLI, set `program.openvm.repository`,
`program.openvm.prover_bin`, and `program.openvm.prover_config`; these are deployment-local paths.
Legacy `program.risc0` settings do not select a fallback backend. Explicit `program.dev` remains a
separate development runner and does not produce an OpenVM receipt.

The service binds to `127.0.0.1:13151` by default. Set `OPENVM_BIND_ADDR` to change the listener.
The container binds to `0.0.0.0:13151`; restrict its published port and network access. The JSON
request limit is 128 MiB. Set `OPENVM_MAX_REQUEST_BYTES` to change it, up to 1 GiB. The guest's
binary input limit is separate and remains 512 MiB minus 16 bytes.

The existing `POST /run_compute` and completed/failed callback formats remain unchanged. The worker
generates an application proof, recursive aggregate, and Halo2 EVM proof. It executes the configured
EVM verifier, checks both application commitments, and checks the expected journal before it writes
a seal. A failed proof sends a failed callback. There is no fake-proof mode.

Jobs are in memory, with one active computation per service process. A restart can lose an accepted
job. Operators must reconcile jobs and retry failed callback delivery; this change does not add a
durable job queue. Run the service behind authenticated admission control. Set callback access
policy for the deployment; do not expose an unrestricted service to the Internet.

## Contract migration

The guest reveals SHA-256 of nine consecutive 32-byte ABI words:

1. Chain ID
2. Interfold address
3. Full uint256 E3 ID
4. Encryption scheme ID
5. Committee public-key hash
6. Ciphertext output hash
7. SAFE ciphertext commitment
8. Parameter hash
9. Input root

The seal is `abi.encode(uint8(1), bytes(halo2ProofData), bytes32[9](journalWords))`. The compute
envelope remains `abi.encode(bytes(seal), bytes32(paramsHash), bytes32(inputRoot))`. The journal is
288 bytes, not the legacy RISC Zero serialization.

Deploy the generated Halo2 verifier from the checked artifact. The CRISP deploy script requires
`OPENVM_HALO2_VERIFIER`, `OPENVM_HALO2_RUNTIME_CODE_HASH`, `OPENVM_APP_EXE_COMMIT`, and
`OPENVM_APP_VM_COMMIT`. It checks the deployed code hash and installs `OpenVmReceiptVerifier` and
`OpenVmBfvCiphertextVerifier`. Its mock mode applies only to other test components; it never creates
a mock compute receipt verifier.

The receipt identity binds the Halo2 verifier address, executable commitment, and VM commitment.
Both the protocol BFV verifier and CRISP application verifier must use that identity. Both
verification calls remain mandatory. CRISP independently checks its stored parameter hash and input
root. Existing rounds retain their request-time verifier snapshot and must drain before a live
migration. The historical RISC Zero mainnet activation scripts are not OpenVM migration scripts. Do
not use them to activate this backend.

No gas override or proof-verification bypass is included. On-chain verifier optimization is separate
work. The compute path remains unaudited.

## Checks

```sh
pnpm openvm service-test
pnpm openvm contract-test
```

`pnpm openvm proof-test` requires externally supplied `OPENVM_TEST_IDENTITY`, `OPENVM_TEST_JOURNAL`,
`OPENVM_TEST_VERIFIER`, and `OPENVM_TEST_VERIFIER_SHA256`. Set `OPENVM_TEST_PROOF` to a proof JSON
file or `OPENVM_TEST_SEAL` to a binary seal from the worker. It verifies a real proof on an
in-memory chain and rejects changed journal words, application commitments, and proof data. It does
not submit a public transaction. No local proof fixture is part of this branch.
