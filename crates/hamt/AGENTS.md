# e3-hamt

This is the immutable membership-map implementation used for historical sortition snapshots.
[README.md](README.md) describes its API and structural sharing.

- Updates return a new root while earlier maps remain unchanged. Preserve Arc structural sharing; an
  in-place optimization can silently mutate request-time eligibility snapshots.
- Size changes only for a new key, not replacement. Cover collision nodes as well as ordinary leaves
  when changing insertion or lookup; equal hashes do not imply equal keys.
- Bitmap rank and child-vector order are coupled. Keep absent-bit and shared-prefix cases in
  regressions instead of checking only unrelated keys.
- `DefaultHasher` is an internal lookup choice, not a stable cryptographic commitment or durable
  trie encoding. Do not expose its shape as protocol identity.

Use the [README tests](README.md#tests); selection changes additionally need the owning sortition
tests. Keep benchmark claims separate from immutable-map correctness.
