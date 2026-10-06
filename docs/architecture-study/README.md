# Interfold architecture study

This collection supports a shared understanding of Interfold and explicit ownership of its design
choices. It records the architecture discussion, the component inventory, and the questions that
need answers from the team.

Implementation references in the architecture-study documents follow branch `main`, reviewed on
2026-10-06. Its root manifests declare version `0.18.0`. The branch and manifest version are
readable locators, not an immutable pin. The `v0.18.0` release tag points to a different snapshot.
The linked monorepo overview retains its own source reference. These references describe checked-in
code, not the versions running on deployed infrastructure.

## Documents

| Document                                              | Purpose                                                                                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| [Monorepo overview](../MONOREPO_OVERVIEW.md)          | System map, runtime interactions, E3 lifecycle, repository contents, and cross-layer dependencies.                       |
| [Architecture assessment](ARCHITECTURE_ASSESSMENT.md) | Evidence for implemented patterns, their suitability, and the distinction between component and repository boundaries.   |
| [Component inventory](COMPONENT_INVENTORY.md)         | Twenty-five architectural responsibilities, their current duties, and the questions needed to understand them.           |
| [Ownership record](OWNERSHIP_RECORD.md)               | A reusable structure for recording responsibility, interfaces, invariants, decisions, verification, and human ownership. |

## Purpose and scope

The team's goal is to regain the ability to explain, navigate, and change the system with
confidence. Each owned component needs accountable decisions about architecture, implementation,
tests, updates, and documentation.

The longer-term goal includes distinct, interdependent projects with their own rules, invariants,
and automation. The first step is to understand the current responsibilities and the contracts
between them.

These documents distinguish observed implementation from architectural judgment and open questions.
The source can establish behavior and dependencies. The team must establish human ownership and the
rationale behind past decisions.

The existing [monorepo overview](../MONOREPO_OVERVIEW.md) remains unchanged and retains its own
source reference. The study documents link to the canonical
[invariants](../../agent/invariants/00_INDEX.md) and
[flow traces](../../agent/flow-trace/00_INDEX.md). Those references retain the detailed protocol
rules.

## How the components connect

The study documents are navigation aids. The source code, contracts, circuits, and build
configuration implement the behavior.

- The [monorepo overview](../MONOREPO_OVERVIEW.md) maps the main runtimes and end-to-end flows.
- The [architecture assessment](ARCHITECTURE_ASSESSMENT.md) explains the implemented patterns and
  boundaries between components.
- The [component inventory](COMPONENT_INVENTORY.md) names responsibilities and links to their
  implementation entry points.
- The [ownership record](OWNERSHIP_RECORD.md) captures each component's connections, contracts,
  invariants, and owner.
- The [Rust architecture map](../../agent/CRATES_ARCHITECTURE.md) describes crate dependencies and
  runtime paths. The [flow traces](../../agent/flow-trace/00_INDEX.md) follow protocol interactions.
- The [invariant index](../../agent/invariants/00_INDEX.md) routes changes to constraints that must
  remain true.

To understand one component, trace both the dependencies it uses and the consumers that use it.
Follow the source imports, runtime messages, durable state, generated artifacts, and release
requirements. These connections can cross languages and repositories within the monorepo.

## Suggested reading order

1. Read the monorepo overview for the system context.
2. Read the architecture assessment for the distinction between implemented patterns and intended
   boundaries.
3. Study inventory items 1–9 to understand progression, state, recovery, and repeated effects.
4. Study the remaining components and their dependencies.
5. Complete an ownership record for each component as its behavior becomes clear.

For each component, ask what it owns, what it depends on, who depends on it, and what crosses those
boundaries.

The central question is:

> What responsibility belongs here, why does it belong here, how does it connect to its callers and
> consumers, and what evidence shows that it meets its contract?
