# OpenVM host

The host runs the canonical processor and policy to derive the ciphertext and nine-word journal. It
passes the input and expected journal to a separate OpenVM worker.

The worker must generate a real EVM proof, verify the application identity and journal, and write a
verified seal. The host returns the ciphertext, SAFE commitment, and compute-proof envelope to the
HTTP service. A worker error fails the job.

See [the service instructions](../README.md) and
[the OpenVM build instructions](../openvm/README.md).
