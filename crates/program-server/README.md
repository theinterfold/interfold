# E3 program service boundary

## Purpose

`E3ProgramServerBuilder` wraps an asynchronous program runner with `/run_compute` and `/health`. The
runner may be unproved development FHE or a real OpenVM host; the HTTP service does not itself
authenticate callers or supply durable admission. Keep it behind an explicitly managed perimeter.
Health reports process availability, not proof-worker readiness, durable job ownership, or drain
state.

## Map

| Location                                             | Responsibility                                                                                      |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [`lib.rs`](src/lib.rs)                               | Builder, HTTP admission/body handling, domain validation, runner invocation, and callback delivery. |
| [`types.rs`](src/types.rs)                           | Hex-encoded request and completion/failure webhook formats.                                         |
| [`development runner`](../program-runner/src/dev.rs) | Concrete native/mock-proof consumer of the server builder.                                          |
| [`OpenVM service`](../program-runner/src/openvm.rs)  | Worker-verified project runner with explicit limits.                                                |

## Usage and job lifecycle

Pass an async `Fn(ComputeJob)` runner to `E3ProgramServer::builder`, configure host/port and
capacity/body limits, call `build()?`, then `run().await`. The runner returns
`(proof_bytes, ciphertext_bytes)`. A request first obtains capacity and validates its body/domain,
then runs in a background task and delivers a webhook; the HTTP acceptance response is not the
result. The linked runner sources show complete project integration without duplicating
cryptographic processing inside the HTTP boundary.

## Bounded admission and callback delivery

The service acquires a shared job permit **before** reading the body, so overload returns 429
without buffering another round. Default capacity is one, body limit 10 MiB, body timeout 120
seconds; excessive/stalled bodies return 413/408 and release capacity. Builder rejects zero
capacity, size, or timeout and can fail constructing its callback client. Services using
secure-sized rounds must set their own body allowance; JSON hex encoding is larger than binary
input.

Request metadata binds exact full E3/domain fields and one commitment/slot/parent per ciphertext
where provided. Slots are 20 bytes and parents fit uint40; coercing lengths changes the application
leaf. The shared computation derives roots from consumed bytes, not caller-supplied roots. See
[encrypted computation](../../docs/architecture/encrypted-computation.md).

Callbacks require HTTP(S), a host, no credentials, and no fragment. Redirects are disabled;
connections have five-second and whole requests 30-second bounds. Transient transport failures, 408,
429, and server errors retry up to five attempts with backoff; other refusals end delivery. Logs
report output sizes and status, not response bodies. These retries are not a durable outbox.

`ensure_public_callback_host` rejects internal literal IP classes and `.local`/`.internal` names
unless `ALLOW_PRIVATE_CALLBACKS` explicitly opts in. **Loopback/localhost are deliberately allowed**
even without that override. Exact localhost/127.0.0.1 can be rewritten to an operator-configured
host; that rewritten target bypasses the private-host check. This supports local/container
callbacks, not an unrestricted safe Internet-facing webhook proxy.

**Remaining risk:** hostnames are checked by name, not resolved and pinned at connect time. DNS can
resolve/rebind to private infrastructure; loopback-only admin services can also be targets. URL
filtering is not authentication, a destination allowlist, or complete SSRF protection.

## Process lifetime and proof identity

Accepted tasks retain their permit through computation/callback but have no durable job queue or
shutdown join set/cancellation token. Stop/crash can lose work or callback delivery. CRISP's durable
Avail job begins only after it accepts the output callback; contract one-shot publication prevents
duplicate results, not repeated proof costs. Preserve recovery material externally where operations
require it; do not claim accepted HTTP means recoverable completion.

The project-specific OpenVM service links that project's program and checks its worker before
serving. Native and guest policy must agree, but genuine proof identity still depends on
executable/VM/keys and deployed receipt verifiers. See
[OpenVM prover operations](../openvm-prover/README.md); explicit `program.dev` is unproved and is
not a fallback for failed production proving.

## Tests

`cargo test --locked -p e3-program-server` covers URL rules, localhost rewrites, body/permit limits,
and webhook serialization. These tests do not establish deployed authentication, DNS-safe egress,
durable callback recovery, or real OpenVM proof verification. HTTP admission tests use a local
service and synthetic runner; `types.rs` tests pin request/webhook serialization.
[AGENTS.md](AGENTS.md) contains admission/callback change constraints.
