# Contributing to The Interfold

Thank you for your interest in contributing to the Interfold! We value your contributions in making
Interfold better.

This guide will discuss how the Interfold team handles [Commits](#commits),
[Pull Requests](#pull-requests), [Merging](#merging), [Releases](#releases), and the
[Changelog](CHANGELOG.md).

**Note:** We won't force external contributors to follow this verbatim, but following these
guidelines definitely helps us in accepting your contributions.

## Commits

We want to keep our commits small and focused. This allows for easily reviewing individual commits
and/or splitting up pull requests when they grow too big. Additionally, this allows us to merge
smaller changes quicker and release more often.

When committing, it's often useful to use the `git add -p` workflow to decide on what parts of the
changeset to stage for commit. When making the commit, write the commit message as a Conventional
Commit.

### Conventional Commits

Interfold attempts to follow the
[Conventional Commits (v1.0.0)](https://www.conventionalcommits.org/en/v1.0.0/) specification.
Following this convention will allow us to provide an automated release process that also generates
a detailed Changelog.

As described by the specification, our commit messages should be written as:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Some examples of this pattern include:

```
feat(compute-provider): Add Risc Zero as a compute provider (#123)
```

```
feat(compute-provider): Add Risc Zero as a compute provider (#123)

Introduces Risc Zero as a compute provider for Interfold, enabling one to prove correct execution of an E3's Secure Process.
```

```
feat(compute-provider): Add Risc Zero as a compute provider (#123)

Co-authored-by: Blaine <blaine@example.com>
```

The `[optional body]` can also be used to provide more Conventional Commit messages for the
Changelog:

```
feat(verification): Add support for Risc Zero compute provider (#123)

feat(compute-provider): Add Risc Zero compute provider (#123)
```

### Conventional Commits: Types

Use a type that describes the change. The accepted types and title constraints are defined in
[PR-title validation](.github/workflows/validate-commits.yml). Changelog inclusion is a separate
release-tool decision.

### Conventional Commits: Breaking Changes

Annotating **BREAKING CHANGES** is extremely important to our release process and versioning. To
mark a commit as breaking, we add the `!` character after the type, but before the colon. For
example:

```
feat!: Rename interfold start to interfold init

feat(cli)!: Enforce minimum rustc version
```

### Conventional Commits: Scopes

Scopes significantly improve the Changelog, so we want to use a scope whenever possible. If we are
only changing one part of the project, we can use the name of the crate, like `(cli)` or `(docs)`.
If a change touches multiple parts of the codebase, there might be a better scope, such as using
`(bfv)` for new features for the BFV encryption scheme.

```
feat(compute-provider): Add Risc Zero as a compute provider (#123)
```

```
feat(bfv): improve DKG performance for BFV (#123)
```

### Conventional Commits: Automated Validation

GitHub Actions validates the PR title, not each commit message. The PR title becomes the default
squash-commit title. See [the workflow](.github/workflows/validate-commits.yml) for the exact rules.
Fix a rejected title by editing the PR title; do not rewrite commit history just to satisfy this
check. Local checks use Husky (`pnpm prepare`); selecting a different `core.hooksPath` replaces
those hooks rather than adding to them.

## Pull Requests

Before you create a pull request, search for any issues related to the change you are making. If
none exist already, create an issue that thoroughly describes the problem that you are trying to
solve. These are used to inform reviewers of the original intent and should be referenced via the
pull request template.

Pull Requests should be focused on the specific change they are working towards. If prerequisite
work is required to complete the original pull request, that work should be submitted as a separate
pull request.

This strategy avoids scenarios where pull requests grow too large/out-of-scope and don't get proper
reviews—we want to avoid "LGTM, I trust you" reviews.

The easiest way to do this is to have multiple Conventional Commits while you work and then you can
cherry-pick the smaller changes into separate branches for pull requesting.

### Reviews

Team policy requires review and approval by **one** contributor with edit access before merging. Do
not assume branch protection enforces this policy. Non-breaking pull requests may be merged at any
time. Breaking pull requests will only be merged alongside a breaking release.

If your Pull Request involves changes in the docs folder, please add the `documentation` flag.

### With Breaking Changes

Breaking changes need to be documented. Please ask for help if this is a problem for any reason.

Sometimes, we don't merge pull requests with breaking changes immediately upon approval. Since a
breaking change will require to bump to the next "minor" version, we might want to land some fixes
in "patch" releases before we begin working on that next breaking version.

### Protocol compatibility

Changes to durable schemas, persisted types, event variants, gossip or sync wire formats, contract
ABIs/storage, and `crates/config/protocol-release.toml` need an explicit compatibility decision for
human review. This includes changes associated with `SCHEMA_VERSION`, `GOSSIP_WIRE_MAJOR`, and
`SYNC_WIRE_MAJOR`; changing a fixture alone does not make old data compatible.

Describe whether the upgrade is rolling, drain-and-resync, or governance. State whether
`protocol_version` or `node_generation` changes, and explain rollback. Use `!` when operators must
reset or resync. Check old-data replay, mixed-version peers, and deployed verifier compatibility
where applicable. Include compatibility-test results and unresolved limits, not only a compile
result. A migration needs explicit versioning and compatibility tests; cleanup approval does not
authorize a protocol change.

For cryptographic, circuit, key, or generated-parameter changes, identify the deployed verifier and
artifact combinations that remain supported. The detailed requirements and known gaps are in
[domain references](docs/architecture/AGENTS.md); verify relevant claims against their sources.
Human review decides the rollout; no documentation edit or optional agent review grants deployment
or publication permission.

## Merging

Once approved by the required number of contributors with edit access, the pull request can be
merged into the `main` branch. Sometimes, especially for external contributions, the final approver
may merge the pull request instead of the submitter.

We generally use "squash merging" to merge all pull requests. This will cause all commits to be
combined into one commit—another reason we want to keep pull requests small & focused.

### Squash Merging

When squash merging, we can keep intermediate Conventional Commits by adding them to the body of the
commit message; however, the GitHub UI adds a `*` character before each commit message and releaser
bots may not parse that.

When squashing, you want to update both the title of the commit to be a good Conventional Commit and
adjust the body to contain any other Conventional Commits that you want to keep (not prefixed with
`*`) and delete any extra information. We also keep any "Co-authored-by:" lines at the bottom of the
commit if the change was done by multiple authors. If "Co-authored-by:" lines appear due to accepted
PR suggestions, it's good to delete them so the author gets full credit for the change.

Our overall approach to squashing is to be mindful of the impact of each commit. The commits
populate our Changelog, so it's important to properly convey to Interfold consumers what changes
have happened. It is also a record that we and others will review in the future. Thus, we want to
attribute the change to its correct authors and provide useful information that future contributors
need.

For example, given the default squash commit message:

```
feat(verification): Add support for Risc Zero compute provider (#123)

* formatting

* feat(compute-provider): Add Risc Zero compute provider (#123)

* chore: appease linter

* fix typo
```

The person merging would remove extraneous messaging and keep only the relevant Conventional
Commits:

```
feat(verification): Add support for Risc Zero compute provider (#123)

feat(compute-provider): Add Risc Zero compute provider (#123)

```

Additional Conventional Commits can be added before squashing if they improve the Changelog or
commit history:

```
feat(verification): Add support for Risc Zero compute provider (#123)


feat(compute-provider): Add Risc Zero compute provider (#123)
chore(ci): Use correct rust version

```

### Merge Checklist

Before merging, you should mentally review these questions:

- Is continuous integration (CI) passing?
- Do you have the required amount of approvals?
- Does anyone else need to be pinged for thoughts?
- Does it have or require changes to the docs?
- Will this cause problems for our release schedule? For example: maybe a patch release still needs
  to be published.
- What details do we want to convey to users in the Changelog?

## Releases

Follow [RELEASING.md](RELEASING.md) for release preparation, tagging, artifact publication,
channels, and recovery. Human review must approve the compatibility and rollout decision before
publication; the release workflow does not rerun the full test suite or grant deployment permission.

---

_This document borrows heavily from Noir's
[CONTRIBUTING.md](https://github.com/noir-lang/noir/blob/master/CONTRIBUTING.md)_

[telegram]: https://t.me/+raYAZgrwgOw2ODJh
