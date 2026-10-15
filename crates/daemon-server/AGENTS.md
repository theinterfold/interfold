# e3-daemon-server

This is the local CLI control transport; command execution and node management remain caller-owned.

- Preserve loopback binding. There is no authentication or TLS, so exposing this socket remotely
  requires a separate security design, not just a configurable bind address.
- The small manual HTTP parser handles content-length framing, not general HTTP/chunked bodies. Keep
  client/server framing aligned; do not assume framework-level body/time limits exist here.
- Connections use `spawn_local` and allow non-Send handlers. Run the server in a local task context;
  changing to ordinary spawned tasks changes the callback contract.
- Discovery only checks transport reachability; it is not authenticated daemon identity or proof
  that a subsequent command will succeed. Preserve HTTP error propagation on command responses.

Run `cargo check --locked -p e3-daemon-server --tests`. For transport changes, add loopback tests
covering framing and error responses and exercise entrypoint's daemon client; do not require a live
ciphernode merely to test parsing.
