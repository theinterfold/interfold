#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

"""Record and compare a stopped node's persisted files across an upgrade.

  state_inventory.py snapshot <out.json> [--baseline <before.json>] <dir> [<dir> ...]
  state_inventory.py compare <before.json> <after.json>

`compare` fails when the candidate:
  - removed or changed the existing bytes of an event-log segment (`*.log`); with `--baseline`,
    the snapshot hashes each segment's first `size` bytes from the baseline so `compare` can
    check that the old content is still a prefix,
  - removed or changed an event blob (a file named by its 64-hex-digit content hash), or a key file.
It also fails when the baseline recorded no event-log segment, which means the state directories
were wrong. Other files can change by normal writes, so a change to one of them is only reported:
Sled segments, and event-log indexes (`*.index`, `*.idx`), which are derived from the segments and
shrink when a segment rolls over and its unused preallocation is truncated.
"""

import hashlib
import json
import os
import re
import sys

SEGMENT_SUFFIX = ".log"
BLOB_NAME = re.compile(r"^[0-9a-f]{64}$")
# Files that must stay byte-identical: node identity and secrets.
KEY_NAMES = ("key", "keyfile", "net_keypair", "wallet", "password")


def sha256(path, limit=None):
    digest = hashlib.sha256()
    remaining = limit
    with open(path, "rb") as file:
        while remaining is None or remaining > 0:
            size = 1 << 20 if remaining is None else min(1 << 20, remaining)
            chunk = file.read(size)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest()


def is_segment(path):
    return path.endswith(SEGMENT_SUFFIX)


def must_stay_identical(path):
    name = os.path.basename(path)
    return BLOB_NAME.match(name) is not None or any(part in name.lower() for part in KEY_NAMES)


def snapshot(out, roots, baseline=None):
    files = {}
    for root in roots:
        for directory, _, names in os.walk(root):
            for name in names:
                path = os.path.join(directory, name)
                if not os.path.isfile(path):
                    continue
                size = os.path.getsize(path)
                entry = {"size": size}
                if must_stay_identical(path) or is_segment(path):
                    entry["sha256"] = sha256(path)
                old = (baseline or {}).get(path)
                if old is not None and is_segment(path) and size >= old["size"]:
                    entry["prefix_sha256"] = sha256(path, old["size"])
                files[path] = entry
    with open(out, "w") as file:
        json.dump(files, file, indent=1, sort_keys=True)
    print(f"recorded {len(files)} file(s) under {' '.join(roots)}")


def compare(before, after):
    """Return (failures, notes) for two inventories."""
    failures, notes = [], []
    if not any(is_segment(path) for path in before):
        failures.append("the baseline recorded no event-log segment; check the state directories")
    for path, old in sorted(before.items()):
        new = after.get(path)
        segment = is_segment(path)
        identical = must_stay_identical(path)
        if new is None:
            (failures if segment or identical else notes).append(f"removed: {path}")
        elif identical and old.get("sha256") != new.get("sha256"):
            failures.append(f"content changed: {path}")
        elif segment and new["size"] < old["size"]:
            failures.append(f"event-log segment shrank {old['size']} -> {new['size']}: {path}")
        elif segment and new.get("prefix_sha256") != old.get("sha256"):
            failures.append(f"event-log segment rewrote existing bytes: {path}")
        elif new["size"] != old["size"]:
            notes.append(f"size {old['size']} -> {new['size']}: {path}")
    added = sorted(set(after) - set(before))
    if added:
        notes.append(f"{len(added)} new file(s)")
    return failures, notes


def main(argv):
    if len(argv) >= 3 and argv[1] == "snapshot":
        out, rest = argv[2], argv[3:]
        baseline = None
        if len(rest) >= 2 and rest[0] == "--baseline":
            with open(rest[1]) as file:
                baseline = json.load(file)
            rest = rest[2:]
        if not rest:
            sys.exit(__doc__)
        snapshot(out, rest, baseline)
    elif len(argv) == 4 and argv[1] == "compare":
        with open(argv[2]) as file:
            before = json.load(file)
        with open(argv[3]) as file:
            after = json.load(file)
        failures, notes = compare(before, after)
        for note in notes:
            print(f"  note: {note}")
        for failure in failures:
            print(f"  FAIL: {failure}")
        if failures:
            sys.exit(1)
        print(f"no persisted state lost ({len(before)} file(s) checked)")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
