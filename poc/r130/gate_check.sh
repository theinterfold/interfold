#!/usr/bin/env bash
cd /home/dev/interfold-research/interfold
H=$(git show HEAD:crates/zk-prover/tests/bootstrap_fixtures_r130.rs | head -1)
echo "HEAD-first-line=[$H]"
./scripts/check-license-headers.sh >/dev/null 2>&1 && echo LIC-STILL-GREEN || echo LIC-STILL-FAIL
./scripts/check-doc-sync.sh > /tmp/docsync.log 2>&1; echo "doc-sync rc=$?"; head -8 /tmp/docsync.log
git status --porcelain