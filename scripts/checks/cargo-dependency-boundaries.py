#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Keep application execution and the node binary from linking each other's packages.

Rules name Cargo packages, not directories, so they survive moves. An edge is a normal or build
dependency in any target table, optional or not, because a consumer can enable any feature.
Dev-dependencies build only the declaring package's tests, examples and benchmarks, so they are
exempt. See scripts/checks/README.md for the intended graph.
"""

from __future__ import annotations

import subprocess
import sys
from collections import deque
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # tomllib is stdlib only from Python 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        sys.exit(
            "check-cargo-dependency-boundaries: needs Python 3.11+ for tomllib, or the "
            f"tomli package. Running under Python {sys.version.split()[0]}."
        )

ROOT = Path(__file__).resolve().parents[2]
APPLICATION = {
    # Root workspace members.
    "e3-compute-provider",
    "e3-openvm-types",
    "e3-openvm-host",
    "e3-program-server",
    "e3-program-runner",
    # Separate workspaces: the OpenVM worker and the default template's program, runner and guest.
    "interfold-openvm-prover",
    "e3-user-program",
    "e3-user-program-runner",
    "e3-openvm-guest",
}
# Libraries application execution shares with the node. They and everything they link must stay
# free of node runtime; add one only after reviewing what it links.
SHARED = {
    "e3-bfv-client",
    "e3-fhe-params",
    "e3-zk-config",
    "e3-zk-witness",
    "e3-polynomial",
    "e3-polynomial-fhe",
    "e3-committee",
    "e3-safe",
}
# The `interfold` binary hosts the node and the project commands. Those commands run the project's
# own runner binary, so the node never links application crates.
NODE_BINARY = "e3-cli"


def linked_dependencies(data: dict[str, object]) -> list[tuple[str, object]]:
    entries: list[tuple[str, object]] = []
    # Editions before 2024 also accept the `build_dependencies` spelling.
    for key in ("dependencies", "build-dependencies", "build_dependencies"):
        table = data.get(key)
        if isinstance(table, dict):
            entries.extend(table.items())
    targets = data.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if isinstance(target, dict):
                entries.extend(linked_dependencies(target))
    return entries


def load_graph() -> dict[str, set[str]]:
    paths = subprocess.check_output(
        [
            "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
            "--", "Cargo.toml", "**/Cargo.toml",
        ],
        cwd=ROOT,
    ).decode().split("\0")
    manifests = {}
    for path in sorted({path for path in paths if path and (ROOT / path).is_file()}):
        with (ROOT / path).open("rb") as handle:
            manifests[ROOT / path] = tomllib.load(handle)

    declared: dict[str, set[str]] = {}
    for manifest, data in manifests.items():
        package = data.get("package")
        if not isinstance(package, dict):
            continue
        inherited = {}
        # Like Cargo, inherit from the root that `package.workspace` selects, else the nearest
        # ancestor workspace.
        selected = package.get("workspace")
        roots = (
            [(manifest.parent / selected).resolve()] if isinstance(selected, str) else manifest.parents
        )
        for parent in roots:
            workspace = manifests.get(parent / "Cargo.toml", {}).get("workspace")
            if isinstance(workspace, dict):
                inherited = workspace.get("dependencies", {})
                break
        names = declared.setdefault(package["name"], set())
        for key, dependency in linked_dependencies(data):
            if isinstance(dependency, dict) and dependency.get("workspace"):
                dependency = inherited.get(key, dependency)
            names.add(dependency.get("package", key) if isinstance(dependency, dict) else key)

    # Only edges between packages of this repository matter; third-party crates are not checked.
    return {name: {dep for dep in deps if dep in declared} for name, deps in declared.items()}


def crossings(graph: dict[str, set[str]], start: str, permitted) -> list[tuple[str, str]]:
    """Each non-permitted package `start` links through permitted ones, with one chain to it.

    The walk stops at a crossing, so a forbidden package's own dependencies are not reported.
    """
    via: dict[str, str | None] = {start: None}
    pending = deque([start])
    found = []
    while pending:
        current = pending.popleft()
        for dependency in sorted(graph[current]):
            if dependency in via:
                continue
            via[dependency] = current
            if permitted(dependency):
                pending.append(dependency)
                continue
            chain = [dependency]
            while chain[-1] != start:
                chain.append(via[chain[-1]])
            found.append((dependency, " -> ".join(reversed(chain))))
    return found


def main() -> int:
    graph = load_graph()
    failures = [
        f"{name} is no longer a package here; update the rule if it was renamed"
        for name in sorted(APPLICATION | SHARED | {NODE_BINARY})
        if name not in graph
    ]

    # Report the shortest chain to each crossing, which starts nearest the package declaring it.
    shortest: dict[str, str] = {}
    for root in sorted(APPLICATION & graph.keys()):
        for package, chain in crossings(graph, root, lambda name: name in APPLICATION | SHARED):
            if package not in shortest or chain.count("->") < shortest[package].count("->"):
                shortest[package] = chain
    failures += [
        f"application execution links {package}: {chain}" for package, chain in sorted(shortest.items())
    ]

    if NODE_BINARY in graph:
        for _, chain in crossings(graph, NODE_BINARY, lambda name: name not in APPLICATION):
            failures.append(f"the node binary links application execution: {chain}")

    if not failures:
        return 0

    print("check-repository: FAILED — Cargo dependency boundaries:")
    for failure in failures:
        print(f"  - {failure}")
    print(
        "  Application execution may link only its own packages and the reviewed shared libraries;"
        " the node binary may not link application execution. Fix the owning package rather than"
        " widening the lists in scripts/checks/cargo-dependency-boundaries.py."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
