#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Keep proof skipping and artificial ZK samples out of production dependencies."""

from __future__ import annotations

import subprocess
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
ROOT = Path(__file__).resolve().parents[2]
ALLOWED_ENABLER = Path("crates/tests/Cargo.toml")
SAMPLES = "e3-zk-samples"
# Unpublished development-tool crates that link samples as a normal dependency because
# their executable itself, not only their tests, prepares artificial material.
SAMPLES_RUNTIME_OWNERS = {
    Path("crates/zk/benchmarks/Cargo.toml"): "e3-zk-benchmarks",
}
BENCHMARK_OWNER = "e3-zk-benchmarks"


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


def production_dependency_tables(data: dict[str, object]) -> list[dict[str, object]]:
    tables = [
        data[key]
        for key in ("dependencies", "build-dependencies")
        if isinstance(data.get(key), dict)
    ]
    for target in data.get("target", {}).values():
        if isinstance(target, dict):
            tables.extend(production_dependency_tables(target))
    return tables


def main() -> int:
    failures: list[str] = []
    manifest_paths = subprocess.check_output(
        [
            "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
            "--", "Cargo.toml", "**/Cargo.toml",
        ],
        cwd=ROOT,
    ).decode().split("\0")
    manifests = sorted({ROOT / path for path in manifest_paths if path and (ROOT / path).is_file()})
    manifest_data = {}
    for manifest in manifests:
        with manifest.open("rb") as handle:
            manifest_data[manifest] = tomllib.load(handle)

    for manifest, data in manifest_data.items():
        relative = manifest.relative_to(ROOT)
        workspace_dependencies = {}
        for parent in manifest.parents:
            workspace = manifest_data.get(parent / "Cargo.toml", {}).get("workspace")
            if isinstance(workspace, dict):
                workspace_dependencies = workspace.get("dependencies", {})
                break

        features = data.get("features", {})
        if isinstance(features, dict) and reaches_target(features):
            failures.append(f"{relative}: default features reach {TARGET}")

        if relative != ALLOWED_ENABLER and enabled_on_dependency(data):
            failures.append(f"{relative}: enables {TARGET} on a dependency")

        owner = data.get("package", {}).get("name")
        if owner == SAMPLES and data["package"].get("publish") is not False:
            failures.append(f"{relative}: {SAMPLES} must remain unpublished")
        runtime_owner = SAMPLES_RUNTIME_OWNERS.get(relative)
        for table in production_dependency_tables(data):
            for name, dependency in table.items():
                if isinstance(dependency, dict) and dependency.get("workspace"):
                    dependency = workspace_dependencies.get(name, dependency)
                package = dependency.get("package", name) if isinstance(dependency, dict) else name
                if package == SAMPLES and runtime_owner is None:
                    failures.append(f"{relative}: {SAMPLES} is only allowed in dev-dependencies")
                if package == BENCHMARK_OWNER:
                    failures.append(
                        f"{relative}: {BENCHMARK_OWNER} is a development tool; no package may depend on it"
                    )
        if runtime_owner is not None and (
            owner != runtime_owner or data["package"].get("publish") is not False
        ):
            failures.append(
                f"{relative}: sample runtime use requires the unpublished {runtime_owner} package"
            )

    if not failures:
        return 0

    print("check-repository: FAILED — Cargo development-only containment:")
    for failure in failures:
        print(f"  - {failure}")
    print(
        "  Only crates/tests can enable proof skipping. ZK samples require dev-dependencies,"
        " except in the unpublished development benchmark owner."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
