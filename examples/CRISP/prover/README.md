# Archived RISC Zero optimizations

This branch preserves the CRISP RISC Zero work independently of the OpenVM integration. It does not
change the deployed guest, image ID, verifier, or production configuration.

The optimized guest retains the production bincode input and nine-field RISC Zero journal. It uses
deferred BFV multiplication tables, checked power-basis decoding, direct centered RNS packing, and a
fixed-word packing path with the original arbitrary-precision fallback. The reference guest disables
direct wire decoding so both implementations can be compared.

No benchmark inputs, keys, proofs, measurements, account files, or machine-specific paths are
included. Provide your own input and expected 288-byte ABI journal to the host. The host compares
all nine words with the RISC Zero journal and rejects fake receipts.

## Build and run

Use the pinned RISC Zero 3.0.3 toolchain. Run these commands from the repository root:

```sh
pnpm crisp:risc0 setup
pnpm crisp:risc0 build
pnpm crisp:risc0 optimized <input.bincode> <journal.bin> <new-report.json>
```

The default mode executes only. Set `CRISP_RISC0_MODE=prove` to request a real composite receipt
from `RISC0_SERVER_PATH`. Set `CRISP_RISC0_MODE=verify` to verify a saved receipt instead of
executing an input. `CRISP_RISC0_REFERENCE=1` selects the reference guest.

The setup command applies the checked-in FHE patch to a pinned revision under the ignored `target/`
directory. It refuses a checkout with different changes. Generated files must remain untracked.
