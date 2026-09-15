#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY.

"""Check that the ciphernode Docker cache stage includes every workspace crate."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 and earlier
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    with (ROOT / "Cargo.toml").open("rb") as cargo_file:
        members = tomllib.load(cargo_file)["workspace"]["members"]

    dockerfile = (ROOT / "crates" / "Dockerfile").read_text()
    copied_manifests = set(
        re.findall(r"^COPY\s+(crates/[^\s]+/Cargo\.toml)\s+", dockerfile, re.MULTILINE)
    )
    required_manifests = {
        f"{member}/Cargo.toml" for member in members if member.startswith("crates/")
    }
    missing = sorted(required_manifests - copied_manifests)

    if missing:
        print("check-invariants: FAILED — crates/Dockerfile omits workspace manifests:")
        for manifest in missing:
            print(f"  {manifest}")
        print("  Add each manifest to the dependency-cache COPY stage.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
