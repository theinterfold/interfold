#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

"""Convert a complete share-computation witness into one chunk witness."""

import json
import sys
import tomllib


def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, str)):
        return json.dumps(str(value))
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        items = (f"{key} = {toml_value(item)}" for key, item in value.items())
        return "{ " + ", ".join(items) + " }"
    raise TypeError(f"Unsupported TOML value: {value!r}")


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "Usage: extract_share_computation_chunk.py "
            "<source.toml> <output.toml> <circuit-path> <chunk-size>"
        )

    source_path, output_path, circuit_path, chunk_size_text = sys.argv[1:]
    chunk_size = int(chunk_size_text)
    with open(source_path, "rb") as source:
        witness = tomllib.load(source)

    if circuit_path.endswith("sk_share_computation_chunk"):
        secret_chunk = {
            "coefficients": witness["sk_secret"]["coefficients"][:chunk_size]
        }
    else:
        secret_chunk = [
            {"coefficients": row["coefficients"][:chunk_size]}
            for row in witness["e_sm_secret"]
        ]

    output = {
        "chunk_idx": "0",
        "secret_chunk": secret_chunk,
        "y_chunk": witness["y"][:chunk_size],
    }
    with open(output_path, "w", encoding="utf-8") as target:
        for name, value in output.items():
            target.write(f"{name} = {toml_value(value)}\n")


if __name__ == "__main__":
    main()
