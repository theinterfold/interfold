# e3-program-server

[README.md](README.md) defines this HTTP/runner boundary and its limits. This server has no caller
authentication or durable job queue; a real proof runner does not supply either property.

- Acquire capacity before buffering a request body. Reject excessive/stalled bodies and release
  permits on every admission failure; accepted tasks retain their permit through compute/callback.
- Validate callback URL after operator localhost rewriting. Preserve explicit private-host
  filtering, loopback allowance, disabled redirects, and delivery deadlines; this is not complete
  DNS-safe SSRF protection. Do not present configurable internal-host access as an authenticated
  perimeter.
- Domain/metadata lengths are exact: silently truncating slot/parent/E3 fields changes the derived
  input root rather than repairing malformed input.
- Callback retry is process-local. Cancellation/exit can lose accepted computation or delivery, so
  keep recovery expectations separate from CRISP's durable DA jobs and contract one-shot gates.

Use the [README tests](README.md#tests) for callback/admission/serialization coverage. End-to-end
OpenVM proof identity and output publication require the service/application acceptance flow, not
these tests.
