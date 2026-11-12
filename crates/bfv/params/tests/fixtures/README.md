# BFV protocol compatibility vectors

`bfv_protocol.json` contains exact ABI bytes and parameter hashes for current threshold presets,
plus historical threshold-only v5/v1 configuration IDs. The v5 records use registry indices 0 and 2;
v1 records retain their original indices 0 and 1. These IDs support historical indexing, not new
request or node admission.

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

`bfv_profiles.json` freezes the profile identities used by the coordinated cutover. They retain the
same parameter ABI encoding and introduce the first explicit identity domain (`v1`); the older
format had no domain version. The flat tuple is independently calculated with ethers v6:

```text
cryptoConfigId = keccak256(abi.encode(
    bytes32 id("interfold:bfv:crypto-config:v1"),
    bytes32 id("fhe.rs:BFV"),
    bytes32 id(protocol),
    bytes32 thresholdParameterHash,
    bytes32 dkgParameterHash,
    uint8 committeeSize,
    uint32 N,
    uint32 T,
    uint32 H,
    bytes32 id(statementVersion)
))
```

Protocol names and statement versions are identity inputs, not independently selectable request
flags. The synchronized insecure/minimum vector reserves a distinct identity without enabling its
execution or asserting proof compatibility.
