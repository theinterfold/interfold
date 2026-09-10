# Test quality and application performance review

Date: 2026-09-08

## Scope and status

This report records a repository-wide source scan and focused inspection of the suspect paths. The
reviewed checkout was `499146c971b0a4d65842a330ec9010b8dd091805`. Relevant findings were also
checked against the Avail candidate at `723bed2eeb93beb20900a444bf7c78aa2d8cff16`.

The original review did not run runtime benchmarks or a complete test suite. The findings below
record the original behavior. The implementation section records subsequent fixes and local checks.
Generated verifiers and vendored dependencies were excluded from cleanup candidates.

The main opportunities are stronger assertions, less repeated setup, and less repeated application
I/O. Test count alone does not measure useful coverage.

## Implementation — 2026-09-10

All 12 findings are implemented on `fix/test-quality-and-app-performance`, originally created from
local `main` at `ab0ef64a83e113b951c94dd45ed31e730f6838b8`. The Jolt experiment is separate on
`feat/crisp-jolt-experiment` and is not part of this change. The results below describe local
checks, not a complete CI run or a deployment.

| Finding | Change                                                                                                                                                                | Verification                                                                                                                           |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| T1      | One shared real encryption proof replaces two type-only proof tests. Separate wrapper tests check exact witness forwarding and error propagation.                     | The compiled verifier accepts the proof. Each of its five altered public inputs fails verification. Altered proof bytes fail decoding. |
| T2      | Required Rust proof and slashing targets fail on missing tools or artifacts. Ordinary runs report expensive integration tests as ignored. CI explicitly selects them. | All 8 fold tests, the correlated node proof, and 19 slashing tests pass. Seven slashing tests execute compiled contracts.              |
| T3      | All 23 governance tests use the named deployment snapshot fixture.                                                                                                    | The same assertions pass. Local suite time fell from about 8 seconds to 0.6 seconds.                                                   |
| T4      | Fast SDK tests no longer prepare circuits or load the prover. The SDK build prepares artifacts once for its CI job.                                                   | All 38 fast tests pass. The prepared proof command verifies real proofs without repeating preparation.                                 |
| T5      | Utility tests compare a known Merkle root and exact signature components. Invalid-leaf checks remain.                                                                 | All 7 utility tests pass.                                                                                                              |
| T6      | Network tests wait for observable buffer state instead of sleeping. Delivery waits have explicit bounds.                                                              | All 5 event-buffer tests pass.                                                                                                         |
| A1      | Dashboard event cursors advance incrementally. Completed state is cached, while fees and new reward events remain live.                                               | 12 dashboard tests cover shared ranges, RPC counts, terminal state, reorgs, failed chunks, cancellation, and reset.                    |
| A2      | Countdown components share one clock per RPC client. Local ticks update the display between non-overlapping chain refreshes.                                          | 3 clock tests cover shared requests, slow responses, retries, and cleanup. Contract deadlines remain authoritative.                    |
| A3      | The archive uses indexed requester positions and bounded server pages. The client fetches each page without an artificial delay.                                      | Repository, HTTP, and hook tests cover legacy migration, replay, stable cursors, pending rows, full-width IDs, errors, and retry.      |
| A4      | One effect owns each React SDK instance. Configuration values and client identities control its lifecycle.                                                            | 4 hook tests cover inline configuration, wallet changes, configuration changes, and cleanup.                                           |
| C1      | The HTTP hook dispatches the requested Axios method, rejects failures, and counts concurrent requests. Endpoint names remain stable.                                  | 9 hook tests cover methods, request options, suppressed 404 responses, rejected failures, and concurrent loading.                      |
| C2      | The unused `CircularTiles.tsx` component is removed after a reference check.                                                                                          | No application imports remain. Git retains the removed source. No bundle-size improvement is claimed.                                  |

### Proof preparation and repeated setup

The fast wrapper suite mocks only the prover boundary. It still uses real WASM encryption and
compares the witness values. It does not claim cryptographic verification. The separate
[proof suite](packages/interfold-sdk/tests/integration/encryption-proof.test.ts) generates one
wrapper proof, which requires two inner proofs. All positive and negative assertions reuse it.

Required Rust tests exposed stale fixture assumptions that the previous skip paths concealed.
Slashing tests now link the compiled evidence library and configure current E3 dependency snapshots.
A test-only bonding registry records requested penalties and lock release. These assertions test
slashing execution, not real token transfers. Existing production contracts are unchanged.

The C3 fold fixture now uses the current minimum committee shape of six slots. A full circuit build
resolved locally mixed artifact shapes. No circuit, threshold, witness format, or proof algorithm
was changed. The circuit builder and its source checks remain unchanged.

### App behavior and compatibility

The dashboard validates the previous cached block hash before a refresh and the requested head hash
before committing results. A reorg invalidates event history and cached terminal state. Failed later
chunks commit neither earlier chunks nor cached values. A repeated head needs no new log requests.
Active stages still require contract reads. Terminal fees remain live.

The archive endpoint is `POST /state/archive`. It accepts requester filters, a versioned cursor, and
a limit from 1 to 50 (default 12). It returns `items` and `next_cursor`. Requester filtering
precedes round reads. Each page reads at most `limit` round pairs, not every historical round. The
index itself remains one JSON record, so index deserialization still grows with archive size.

Schema 1 adds requester positions without changing existing IDs or their order. Startup migrates
legacy indexes once. Failed migrations do not advance the schema version. New rounds do not shift an
existing cursor. Pending rounds consume positions but produce no summary. Empty pages can still have
a next cursor. The client retains that cursor and offers another page or retry. The legacy
`/state/all` endpoint remains available.

### Local verification

The counts below are command results, not a sum of independent coverage. Durations exclude setup and
compilation unless stated otherwise. They do not establish a CI-wide speedup.

| Command                                                 | Result                                                                              |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `pnpm evm:test test/Governance/AccessAndBounds.spec.ts` | 23 passed. About 8 seconds before fixture reuse, 0.6 seconds after.                 |
| `pnpm sdk:test`                                         | 38 passed. Latest runner duration: 1.23 seconds, with no circuit preparation.       |
| `pnpm sdk:test:proofs:prepared`                         | 7 passed. Latest proof-suite duration: 6.49 seconds.                                |
| `pnpm test:web`                                         | 31 passed: React 4, dashboard 12, CRISP client 15.                                  |
| `pnpm -C examples/CRISP test:sdk tests/utils.test.ts`   | 7 passed.                                                                           |
| `cargo test -p e3-net event_buffer -j 2`                | 5 passed.                                                                           |
| `pnpm rust:test:slashing`                               | 19 passed, including 7 contract-backed tests. No ignored tests.                     |
| `pnpm rust:test:proofs`                                 | 8 fold tests and 1 correlated node test passed. No ignored tests.                   |
| `cargo test -p crisp --lib -j 2` in `examples/CRISP`    | 117 passed, 6 existing external-RPC tests ignored. Includes the archive HTTP tests. |

Root Rust checks used `CARGO_TARGET_DIR=examples/CRISP/target` and two build jobs to reuse the
working local compilation cache. `pnpm evm:build` and a full
`pnpm build:circuits --preset insecure-512 --committee minimum --skip-if-built` completed first. The
full circuit build produced all 24 circuits for one consistent pair.

Scoped ESLint, client and dashboard TypeScript checks, SDK and React declaration builds, and
`git diff --check` pass. The committee, documentation, address, and invariant checks pass. The
initial license check reported the deleted `CircularTiles.tsx` because its tracked-file scan still
included the unstaged deletion. New source files include SPDX headers.

Full `pnpm test`, the complete Noir test suite, live-RPC application benchmarks, and remote CI were
not run. The new fast web CI job does not prepare circuits. Existing prepared jobs now explicitly
run the required proof and slashing targets.

## Test quality

### T1. Expensive SDK proof tests do not verify proofs

Source: [SDK tests](packages/interfold-sdk/tests/sdk.test.ts).

The number and vector proof tests run the real proof-generation pipeline. They only check object
types and byte-array types. Neither test verifies the resulting proof or checks its public-input
binding. Each timeout is 9,999,999 milliseconds, almost 2 hours 47 minutes.

The tests provide crash detection, but their assertions do not justify treating them as proof
correctness tests.

Recommended changes:

- Keep real proof generation in a dedicated cryptographic integration suite.
- Verify each proof against the expected public inputs and verification key.
- Reject altered commitments and public inputs in negative tests.
- Test API wrapper argument forwarding separately, without generating redundant proofs.
- Set explicit, justified integration timeouts.

Acceptance: a valid proof passes, an altered binding fails, and a malformed proof object cannot
satisfy the test.

Preserve the
[cryptographic compatibility unit](agent/INVARIANTS.md#noir--barretenberg-compatibility) and all
proof-binding requirements.

### T2. Optional Rust integration tests can report success without running

Sources:

- [Fold tests](crates/zk-prover/tests/fold_accumulators_e2e_tests.rs)
- [Correlated fold tests](crates/zk-prover/tests/node_fold_correlated_e2e_tests.rs)
- [Slashing integration tests](crates/zk-prover/tests/slashing_integration_tests.rs)
- [CI workflow](.github/workflows/ci.yml)

Several tests print a skip message and return successfully when tools or artifacts are missing.
These test binaries are not among CI's explicit root integration-test targets. Other proof suites
are configured in CI, so this finding does not mean that CI runs no real proofs.

Recommended changes:

- Distinguish required integration tests from explicitly optional tests.
- Fail required jobs when a binary or artifact is missing.
- Use explicit test selection or ignored-test reporting for optional local tests.
- Check that every required integration-test target belongs to a CI job.

Acceptance: missing prerequisites cannot produce a successful required proof or slashing job. Retain
the actual tests. They protect the repository's
[compatibility and evidence requirements](agent/INVARIANTS.md#meta-invariants).

### T3. Governance tests repeat full-system deployment

Source:
[Governance access and bounds tests](packages/interfold-contracts/test/Governance/AccessAndBounds.spec.ts).

There are 23 direct calls to `deployAll()`. Each call deploys the protocol fixture before testing
ownership, limits, or configuration behavior.

Recommended change: use a named `loadFixture` snapshot fixture, as other contract suites already do.
Keep the distinct ownership and bounds assertions.

Acceptance: all assertions remain, and independent tests restore the same initial state. Measure
deployment count and suite duration before and after the change.

### T4. SDK unit tests enter circuit preparation unnecessarily

Sources: [SDK scripts](packages/interfold-sdk/package.json) and
[circuit compilation entry point](packages/interfold-sdk/scripts/compile-circuits.sh).

The SDK `pretest` script invokes circuit preparation even for event-listener tests. The build
preparation invokes it too. The script does not request the source-checked `--skip-if-built` path.

Recommended changes:

- Separate event, contract-client, and wrapper tests from cryptographic integration tests.
- Hydrate and validate the required circuit artifacts once per cryptographic job.
- Keep source, preset, committee, compiler, and verification-key consistency checks.

Acceptance: an event-only test does not invoke Nargo or Barretenberg. A cryptographic test fails
when its artifacts do not match the selected configuration.

### T5. Weak utility tests overlap stronger neighboring tests

Source: [CRISP SDK utility tests](examples/CRISP/packages/crisp-sdk/tests/utils.test.ts).

One test checks only that a generated Merkle root exists. The neighboring proof test constructs the
tree and verifies a proof against it. The existence-only test adds little coverage.

The signature-component test checks only four `Uint8Array` types, not their contents.

Recommended changes:

- Remove the existence-only test or replace it with a known-root vector.
- Check signature components against known expected values.
- Retain exact hash vectors, invalid-leaf tests, and server-format compatibility tests.

Acceptance: incorrect root or signature contents fail even when the returned types are correct.

### T6. Network tests depend on scheduling delays

Source: [Network event-buffer tests](crates/net/src/event_buffer/tests.rs).

`test_buffers_until_sync_ended` uses a 10-millisecond sleep and a 100-millisecond delivery timeout.
It also contains receives without a timeout. A regression can therefore hang the test, while a
loaded runner can miss a short delivery deadline.

This is a timing risk found in source, not a reproduced flaky failure.

Recommended changes:

- Synchronize on observable actor progress instead of assuming that a sleep is sufficient.
- Give every receive a bounded failure path.
- Keep the assertions that events remain buffered until synchronization completes.

Acceptance: the test rejects early delivery and lost delivery without depending on runner speed.
Preserve the [startup and replay ordering rules](agent/INVARIANTS.md#ordering-backpressure-effects).

## Application performance

### A1. The public dashboard repeatedly scans complete event history

Sources: [Event queries](packages/interfold-dashboard/src/lib/e3.ts) and
[polling hooks](packages/interfold-dashboard/src/lib/useE3s.ts).

The dashboard polls every 15 seconds. List refreshes scan E3 requests from the deployment block and
read stages for historical E3s. The CRISP view also scans historical ballots. Detail refreshes
repeat the request-history scan before querying the selected E3.

Recommended changes:

- Load history once and keep a cursor scoped to the chain and deployment.
- Fetch new events after the cursor.
- Cache immutable metadata and completed E3 results.
- Refresh active E3 state separately.
- Handle reorgs, overlapping ranges, duplicate events, and interrupted requests explicitly.

Acceptance: a refresh with no new events does not rescan the deployment history. Reorg and replay
tests must still produce the correct view. Preserve
[stable event identity and replay semantics](agent/INVARIANTS.md#meta-invariants).

### A2. The countdown requests a block every second

Source: [CRISP countdown](examples/CRISP/client/src/components/CountdownTime.tsx).

Each timer tick calls `getBlock()`. There is no in-flight guard, so slow requests can overlap.

Recommended change: share the latest observed chain timestamp, advance the displayed estimate
locally, and refresh chain state periodically. Label the display as an estimate when needed.

Acceptance: countdown ticks do not each require an RPC request. Transaction checks and acceptance
still use the [on-chain deadlines](agent/INVARIANTS.md#deadlines), not the browser clock.

### A3. The poll archive delays display without fetching a new page

Sources: [Archive page](examples/CRISP/client/src/pages/AllPolls/AllPolls.tsx) and
[round-state routes](examples/CRISP/server/src/server/routes/state.rs).

The archive already holds its results, then waits one second before increasing the visible slice. No
network request occurs inside that delay. The server reads all round records sequentially and
filters by requester after those reads.

Recommended changes:

- Remove the artificial one-second delay.
- Add server-side pagination and requester indexing.
- Return lightweight summaries for archive rows.

Acceptance: already loaded rows appear without the delay. Fetching one archive page does not require
reading and returning every historical round.

### A4. Inline configuration can repeatedly recreate the React SDK

Source: [React SDK hook](packages/interfold-react/src/useInterfoldSDK.ts).

The initialization callback depends on the identity of `config.contracts`. The documented inline
object changes identity on every render. With a connected wallet, initialization updates state and
can trigger another cleanup and initialization cycle.

Recommended changes:

- Key the lifecycle on stable configuration values and client identities.
- Use one initialization and cleanup effect.
- Test repeated renders with inline configuration, wallet changes, and unmounts.

Acceptance: unchanged configuration does not reconstruct the SDK or discard its event subscriptions.
The existing template memoizes its configuration, so this finding does not claim that the template
currently enters an infinite loop.

## Wrappers and unused code

### C1. The generic HTTP wrapper hides method and error behavior

Source: [CRISP HTTP hook](examples/CRISP/client/src/hooks/generic/useFetchApi.tsx).

The wrapper accepts arbitrary Axios methods, but every method except lowercase `get` becomes POST.
It logs failures and returns `undefined`. One loading flag also represents concurrent requests.
Current endpoint callers mainly use GET and POST, so unsupported-method behavior is a latent API
defect rather than a demonstrated failing request.

Recommended changes:

- Narrow the supported methods or dispatch through the matching Axios request method.
- Preserve explicit error results or rejected promises.
- Track loading per request or per query.
- Keep useful domain-specific endpoint names.

Acceptance: methods, failures, and concurrent loading states match the advertised API.

### C2. CircularTiles has no application references

Source: [CircularTiles](examples/CRISP/client/src/components/CircularTiles.tsx).

No references were found, and the component is unreachable from the CRISP application's static
import graph. Remove it after a final reference check. This reduces maintenance clutter, not a
measured bundle size or runtime cost.

## Code to retain

- Commitment mismatch, replay, ordering, duplicate-event, timeout, and recovery tests.
- Rust, Solidity, and Noir tests that independently verify the same cross-language encoding.
- Actor and effect boundaries that enforce runtime architecture.
- Named contract fixtures that provide isolated protocol state.
- The node dashboard polling wrapper, which already handles cancellation, overlapping requests, and
  background-tab polling.

## Suggested implementation order

1. Correct misleading test results and missing required integration targets.
2. Reuse contract fixtures and separate fast SDK tests from proof tests.
3. Correct the React SDK lifecycle and HTTP error behavior.
4. Remove repeated dashboard scans, countdown RPC calls, and artificial archive delays.
5. Remove confirmed dead code and redundant tests.
6. Compare test coverage, command timings, RPC counts, and application behavior before and after.

No cleanup may silently change thresholds, commitments, proof multiplicity, witness formats, event
identity, or replay behavior. Such changes require their own compatibility review and tests.

## Reference documentation

- [React: unnecessary object dependencies](https://react.dev/reference/react/useEffect#removing-unnecessary-object-dependencies)
- [Hardhat network helpers](https://hardhat.org/docs/plugins/hardhat-network-helpers)
- [Repository invariants](agent/INVARIANTS.md)
