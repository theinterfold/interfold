# e3-zk-build

This unpublished crate owns build/configuration operations, source identity, staging, and hydration.
[README.md](README.md) owns commands and side effects.

- Keep dependency direction `build -> witness -> config`; artificial samples are not build inputs.
- Use the shared build-pair policy. Reject unsupported explicit selections before tools or writes;
  wildcard selections preserve manifest order rather than inventing a Cartesian product.
- Required source files/directories/tool pins must exist. Keep framed, repository-relative source
  identities and staged generated-content support. A tooling move must update identity inputs and
  fixture roots together; do not silently skip a missing owner.
- Generated checks format an isolated library copy, never swap live files. Partial/failed builds
  remove both VK-tree anchors. Hydration retains the published hash; releases remain source-bound.
- Preserve generated provenance bytes, isolated read-only checks, argument forwarding, and tool failures.
  Do not restamp an artifact to hide a changed source identity.

Run `pnpm test:circuit-build` and `pnpm build:circuits check --committee all`. A full circuit build
or proof matrix is not incidental preparation. See
[artifact boundaries](../../../docs/architecture/circuit-artifacts.md).
