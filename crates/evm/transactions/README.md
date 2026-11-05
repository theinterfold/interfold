# e3-evm-transactions

Owns the transaction rules that EVM senders share: receipt success, the next nonce of one account,
whether a failed broadcast left no transaction with the node, and which RPC errors a caller retries,
with the default attempts and first delay. [e3-evm-client](../client/README.md),
[e3-evm](../runtime/README.md), and the CLI use them. Each keeps its own nonce lock, retry loop,
attempt limits, and confirmation policy. Generic backoff (`retry_with_backoff`, `backoff_delay`)
stays in [e3-utils](../../utils/README.md).

- `require_successful_receipt` rejects a mined transaction whose receipt reports execution failure.
  Successful RPC submission or inclusion is not a successful transaction.
- `nonce::next_free_nonce` picks the lowest nonce, at or above the RPC pending count, that no
  reservation holds. A reservation below the pending count stays until it expires, because another
  node behind the same endpoint can lag. Only the lowest uncounted nonce is reused after expiry;
  later reservations wait behind it. The caller scopes reservations by chain and account and holds
  them for one process only.
- `nonce::broadcast_refused` frees a nonce only after a local error or an error answer other than
  "already known". After any other error the node can hold the transaction.
- `should_retry_error` matches caller-selected codes against the raw or decoded error. An empty list
  retries every error.

## Tests

Run `cargo test --locked -p e3-evm-transactions`. Inline tests cover receipt status, nonce
reservation, expiry and lagging nodes, and broadcast-refusal classification; no chain RPC is
required. The client and runtime tests cover their lock and retry wrappers.
