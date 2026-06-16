# Contributing to The Interfold

Thank you for your interest in contributing to the Interfold! We value your contributions in making
Interfold better.

This guide will discuss how the Interfold team handles [Commits](#commits),
[Pull Requests](#pull-requests), [Merging](#merging), [Releases](#releases), and the
[Changelog](#changelog).

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

Generally, we want to only use the three primary types defined by the specification:

- `feat:` - This should be the most used type, as most work we are doing in the project are new
  features. Commits using this type will always show up in the Changelog.
- `fix:` - When fixing a bug, we should use this type. Commits using this type will always show up
  in the Changelog.
- `chore:` - The least used type, these are **not** included in the Changelog unless they are
  breaking changes. But remain useful for an understandable commit history.

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

We have automated validation in place to ensure commit messages follow the Conventional Commits
specification:

1. **GitHub Actions**: All pull requests are automatically validated. If any commit messages don't
   follow the specification, the CI will fail and provide feedback.

2. **Local Git Hook (Optional)**: Developers can optionally enable a local git hook to validate
   commit messages before they're committed:
   ```bash
   # Enable the git hook
   chmod +x .githooks/commit-msg
   git config core.hooksPath .githooks
   ```

If your commit messages don't pass validation, you can fix them using:

- `git commit --amend` to fix the last commit message
- `git rebase -i HEAD~N` to edit multiple commit messages
- Squash commits when merging the PR

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

For any repository in the Interfold repo, we require code review & approval by **one** contributor
with edit access before the changes are merged, as enforced by GitHub branch protection.
Non-breaking pull requests may be merged at any time. Breaking pull requests will only be merged
alongside a breaking release.

If your Pull Request involves changes in the docs folder, please add the `documentation` flag.

### With Breaking Changes

Breaking changes need to be documented. Please ask for help if this is a problem for any reason.

Sometimes, we don't merge pull requests with breaking changes immediately upon approval. Since a
breaking change will require to bump to the next "minor" version, we might want to land some fixes
in "patch" releases before we begin working on that next breaking version.

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

Releases are managed ad-hoc by the Interfold team, we may introduce some automation at some point in
future.

---

_This document borrows heavily from Noir's
[CONTRIBUTING.md](https://github.com/noir-lang/noir/blob/master/CONTRIBUTING.md)_

[telegram]: https://t.me/+raYAZgrwgOw2ODJh
