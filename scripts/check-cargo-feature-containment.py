#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Check that the proof-skip Cargo feature cannot enter a production build."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # tomllib is stdlib only from Python 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        sys.exit(
            "check-cargo-feature-containment: needs Python 3.11+ for tomllib, or the "
            f"tomli package. Running under Python {sys.version.split()[0]}."
        )

TARGET = "test-only-skip-proof-aggregation"
ROOT = Path(__file__).resolve().parent.parent
ALLOWED_ENABLER = Path("crates/tests/Cargo.toml")


def reaches_target(features: dict[str, list[str]]) -> bool:
    pending = list(features.get("default", []))
    visited: set[str] = set()

    while pending:
        item = pending.pop()
        normalized = item.removeprefix("dep:")
        if normalized == TARGET or normalized.endswith(f"/{TARGET}"):
            return True
        if normalized in visited:
            continue
        visited.add(normalized)
        pending.extend(features.get(normalized, []))

    return False


def dependency_tables(data: dict[str, object]) -> list[dict[str, object]]:
    tables: list[dict[str, object]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = data.get(key)
        if isinstance(table, dict):
            tables.append(table)

    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        table = workspace.get("dependencies")
        if isinstance(table, dict):
            tables.append(table)

    target_tables = data.get("target")
    if isinstance(target_tables, dict):
        for target in target_tables.values():
            if isinstance(target, dict):
                tables.extend(dependency_tables(target))

    return tables


def enabled_on_dependency(data: dict[str, object]) -> bool:
    for table in dependency_tables(data):
        for dependency in table.values():
            if not isinstance(dependency, dict):
                continue
            configured = dependency.get("features", [])
            if isinstance(configured, list) and TARGET in configured:
                return True
    return False


def main() -> int:
    failures: list[str] = []
    manifests = [ROOT / "Cargo.toml", *sorted((ROOT / "crates").rglob("Cargo.toml"))]

    for manifest in manifests:
        with manifest.open("rb") as handle:
            data = tomllib.load(handle)
        relative = manifest.relative_to(ROOT)

        features = data.get("features", {})
        if isinstance(features, dict) and reaches_target(features):
            failures.append(f"{relative}: default features reach {TARGET}")

        if relative != ALLOWED_ENABLER and enabled_on_dependency(data):
            failures.append(f"{relative}: enables {TARGET} on a dependency")

    if not failures:
        return 0

    print(f"check-invariants: FAILED — {TARGET} escaped test-only containment:")
    for failure in failures:
        print(f"  - {failure}")
    print("  Production binaries must reject skip_proof_aggregation (agent/invariants/02_CRYPTO_CIRCUITS.md, C-02).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
