# BFV protocol compatibility vectors

`bfv_protocol.json` contains exact ABI bytes, parameter hashes, and configuration IDs for current
threshold presets and the indexer's historical v1 parameter sets. The current records use registry
indices 0 and 2. Historical records retain their original indices 0 and 1; they are not current
runtime presets.

The vectors were calculated independently with ethers v6 `AbiCoder`, `id`, and `keccak256`:

```text
encodedParameters = abi.encode(one tuple(uint256,uint256,uint256[],string))
parameterHash = keccak256(encodedParameters)
cryptoConfigId = keccak256(abi.encode(
    id("fhe.rs:BFV"), parameterHash, id(circuitVersion)
))
```

The string in the parameter tuple is the exact decimal encryption variance. The dynamic tuple's
leading offset is part of the hashed bytes. A registry-byte hash must not normalize those bytes.

Rust parameter, builder, and node-admission tests share this fixture. Preserve the expected answers
independently of the implementation under test. Do not regenerate the fixture automatically when a
test fails. A deliberate protocol update requires review of the changed inputs, domains, and
deployment compatibility; retain historical vectors that the indexer still supports.
