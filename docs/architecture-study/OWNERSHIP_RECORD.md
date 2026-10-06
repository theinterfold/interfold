# Component ownership record

Use this structure to capture understanding of one component or capability. The
[inventory](COMPONENT_INVENTORY.md) supplies the study questions. The
[assessment](ARCHITECTURE_ASSESSMENT.md) explains the architectural distinctions behind them.

This is a template. It assigns no owners and approves no design changes.

## 1. Identity and accountability

| Field                                              | Answer       |
| -------------------------------------------------- | ------------ |
| Component or capability                            | To establish |
| Related inventory items                            | To establish |
| Accountable architectural owner                    | To establish |
| Implementation and maintenance responsibility      | To establish |
| Testing, updates, and documentation responsibility | To establish |
| Collaborating component owners                     | To establish |
| Source revision examined                           | To establish |

One person can hold several responsibilities. Record the responsibility explicitly even when people
share the work. The owner remains accountable for the component's contracts and decisions across its
source directories.

## 2. Purpose and boundary

- What problem does this component solve?
- Which behavior and state does it own?
- Which behavior belongs to another component?
- Which callers or consumers need it?
- Which source files, packages, processes, and artifacts implement it?

Record these boundaries separately:

| Boundary               | Current arrangement and reason |
| ---------------------- | ------------------------------ |
| Domain and ownership   | To establish                   |
| Package and build      | To establish                   |
| Process and deployment | To establish                   |
| Repository and release | To establish                   |

## 3. Interface and dependency contracts

- What inputs does the component accept?
- What outputs, events, and errors does it produce?
- What does it guarantee to each consumer?
- What assumptions does it make about dependencies?
- Which imports and runtime dependencies are allowed?
- Which formats, orderings, identities, and units must agree across implementations?

For each important dependency, record both the consumer's expectation and the supplier's guarantee.
Include generated artifacts and runtime messages as well as source imports.

## 4. Connections to the rest of Interfold

- Which components provide inputs or events to this component?
- Which components consume its outputs, events, or decisions?
- Which components share or restore its durable state?
- Which contracts, wire formats, proofs, or generated artifacts cross its boundaries?
- How do its failures, timeouts, and recovery actions affect connected components?
- Which build, release, and deployment steps depend on these connections?

Record the connection type. A source dependency, runtime message, persisted format, proof artifact,
and deployed service are different contracts.

## 5. State and failure behavior

- Which state is authoritative, derived, temporary, or secret?
- Which state must survive a crash?
- What makes progress durable?
- Which updates must succeed together?
- What can repeat safely, and how is completion recognized?
- What happens after a timeout, cancellation, partition, or partial failure?
- What resumes after restart, and what must stop?
- Which schema or version changes invalidate existing state?

The successful path and the recovery path form one component contract.

## 6. Invariants and verification

| Guarantee    | Source of authority                            | Enforcement                                      | Evidence or open gap |
| ------------ | ---------------------------------------------- | ------------------------------------------------ | -------------------- |
| To establish | Contract, circuit, protocol rule, or interface | Implementation, test, mechanical gate, or review | To establish         |

Link to the canonical [invariant entries](../../agent/invariants/00_INDEX.md) rather than copying
their detailed rules. Record the focused verification commands and the cross-component checks needed
when the interface changes.

Distinguish these evidence states:

- **Observed:** supported by a cited implementation path.
- **Verified:** supported by a named check and its result at a stated revision.
- **Intended:** required by a design or invariant but not yet established by the available evidence.
- **Unknown:** requires investigation or team input.

## 7. Architectural decision record

### Decision

What mechanism or boundary did the team choose?

### Context

What requirements and constraints drove the choice? Which consumers, deployed data, or released
artifacts depend on it?

### Alternatives

Which alternatives did the team consider? What tradeoffs led to the selected approach?

### Consequences

What does the choice simplify? What complexity, coupling, or operational cost does it introduce?

### Status and evidence

Is the decision documented history, an inference from code, or a new proposal? Who can confirm the
rationale? Which source revision and references support the record?

### Revisit conditions

What change in requirements or evidence would justify a different decision?

## 8. Change and release obligations

- Who approves changes to this component's contract?
- Which other owners need to participate?
- Which consumers and generated artifacts must change together?
- Can versions coexist during an upgrade?
- Does the change require a coordinated release, drain, resynchronization, or governance action?
- Which documentation and operational instructions need an update?
- What does rollback mean for external effects and saved state?

## 9. Open questions

Record unanswered questions with a responsible person and the evidence needed to resolve them. Keep
proposals distinct from agreed decisions.

The record is useful when another team member can explain the component's behavior and safely assess
the effect of a proposed change.
