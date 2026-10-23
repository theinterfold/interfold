# Blueprint diff (experimental)

This folder draws the architecture change of a branch on the blueprint, and a workflow posts it on
each pull request. It is an experiment: [Turn it off](#turn-it-off) and [Remove it](#remove-it) say
how to stop it.

## Try it

```bash
node scripts/blueprint/diff/diff.mjs                    # your branch against its merge base with main
node scripts/blueprint/diff/diff.mjs v0.18.0 v0.19.0    # any two refs or folders
```

The command writes `scripts/blueprint/out/interfold-blueprint-diff.html`: the blueprint of your
branch with the change in colour. Green is new, red and dashed is removed, and yellow is changed. A
number on a box counts the changes inside it. **Before** and **After** (or `B`) switch between the
two versions, and **Changes** (or `C`) lists every change and opens its diagram.

It compares the crates and their dependencies, the actors, the messages that each actor handles, the
actor addresses that each actor holds, the contract functions and events, the circuits, and every
box and arrow of the diagrams. Each version is read with its own `scripts/blueprint`, so a change to
`LAYERS` or `CONTRACTS` counts too. It builds nothing.

## On pull requests

The `Blueprint Diff` workflow (`.github/workflows/blueprint-diff.yml`) runs on every pull request
from this repository and keeps one comment up to date: the counts, every change, and a link to the
page on GitHub Pages (`https://theinterfold.github.io/interfold/pr-<number>/<commit>/`). Each push
updates the same comment and replaces the page. `previews.mjs` stores the page on the
`blueprint-previews` branch, one folder per pull request, and Pages serves that branch. The branch
keeps no history: it holds only the latest page of each open pull request, about 2.5 MB each.

When the pull request closes, merged or not, its folder goes from the branch and from Pages, and the
comment keeps the counts and the list but says that the page was removed. A pull request without an
architecture change gets no comment. A pull request from a fork gets none: its token can neither
store the page nor post the comment.

Each run takes about 45 seconds on a GitHub-hosted runner, which costs nothing for a public
repository, and so does GitHub Pages. The time depends on the size of the code, not of the change:
it reads both versions whole.

It needs two settings: Settings → Pages → Source: **GitHub Actions**, and Settings → Environments →
`github-pages` → Deployment branches and tags: **No restriction**, because the workflow publishes
from pull requests. With that rule, anyone with push access can publish to the Pages site from any
branch.

## Accuracy

On the 40 pull requests merged from #1996 to #2236, it found all 36 changes of the kinds above and
reported none that was not real. It reads patterns in the code and compiles nothing, so it does not
see what a function does inside, events published on the bus, Solidity view, pure, internal and
private functions, interfaces and mocks, contracts and circuits that `CONTRACTS` and `CIRCUITS` do
not list, the inside of the SDK, config, CLI flags, network messages, or test code.

## Turn it off

Set the repository variable `BLUEPRINT_DIFF` to `off` (Settings → Secrets and variables → Actions →
Variables). The workflow then skips every pull request. Delete the variable to turn it back on.

## Remove it

1. Delete this folder and `.github/workflows/blueprint-diff.yml`.
2. Delete the pages: `git push origin --delete blueprint-previews`.
3. Turn off GitHub Pages: Settings → Pages → Unpublish site, then set the source to None (or
   `gh api -X DELETE repos/theinterfold/interfold/pages`).
4. Set the `github-pages` environment back to the `main` branch only, or delete it (Settings →
   Environments).
5. Remove the two pointers to this folder, in `scripts/blueprint/README.md` and `scripts/README.md`.

These stay and are safe to keep: `lib/page.mjs` (the build uses it), the `BLUEPRINT_ROOT` variable,
`members()` and the `unmapped` option in `lib/inventory.mjs`, and the `export` on `evName` in
`generate.mjs`. `build.mjs` and `check.mjs` work without this folder.

## Files

- `diff.mjs`: reads two versions, compares them, and writes the page and the comment.
- `view.js` and `view.css`: the change view on the blueprint page.
- `previews.mjs`: stores or removes the page on the `blueprint-previews` branch.
