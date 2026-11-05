# e3-evm-transactions

Keep only the transaction rules that client, runtime, and CLI senders share. Locks, attempt limits,
confirmation waits, and recovery belong to each caller; sharing these rules does not merge their
policies.

- A nonce rule change reaches every sender. Preserve reservation of counted nonces until expiry,
  reuse of only the lowest uncounted nonce, and retention of the reservations queued behind it.
- Classifying a broadcast as refused frees its nonce, so a wrongly refused transaction reuses a live
  nonce. Count an error as refused only when it leaves nothing with the node.
- Successful RPC submission is not a successful transaction receipt.
- Depend on Alloy only. Contract bindings, providers, configuration, and other `e3-*` crates stay
  out, so the client and runtime share these rules without depending on each other.

Use the [README tests](README.md#tests); a nonce or classification change also needs the client and
runtime sender tests.
