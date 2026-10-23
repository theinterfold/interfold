# BFV configuration review evidence

The
[2026-10-22 qualification record](https://github.com/theinterfold/interfold/blob/4eedc2fc707aec36fc9dcfae1ba6049437a6c14b/docs/architecture/bfv-configuration-verification.md)
belongs to snapshot `e962966e1`, before #2346 was simplified during review. It records the
real-proof checks and comparison of 300 keys/hashes with the preserved baseline; it is not
qualification of the current checker or catalogue format.

Ordinary checks now reuse the existing source/default-pair checks. Exhaustive key/verifier
rederivation is explicit qualification, not a new mandatory CI or pre-push guarantee. See the
[tooling guide](../../scripts/circuits/README.md#circuit-builder) for the distinct scopes. A new
source-bound matrix is required before claiming qualification of changed build inputs; never relabel
old stamps to reuse the earlier evidence.

The original #2197 proposal's mandatory full-matrix CI gate is intentionally outside this narrowed
revision; that acceptance criterion must be revisited rather than marked complete.

The simplification changes development metadata/checking, not parameters, domains, ABI preimages,
public-input ordering, proof multiplicity, deployed verifiers, or independent proof fixtures.
Protocol 8/generation 2 remain unchanged; compatible rolling remains a proposal for human review
under [upgrade policy](upgrades.md), not deployment authorization.

The CRISP draft still awaits a matching public release and refreshed candidate pins/metadata. The
literal historical #2195 rehearsal and <=25 recurring-file target remain unexecuted/unmeasured in
[#2197](https://github.com/theinterfold/interfold/issues/2197). No source-only check, local metadata
projection, or historical qualification record closes those acceptance gaps.
