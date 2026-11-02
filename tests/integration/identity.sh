#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# The base scenario under a required identity policy: a mock verifier verifies every bond owner
# before the request, and the round must still decrypt.
#
# The run goes to a file, not a pipe: a process left behind on failure would hold a pipe open.
LOG="$(mktemp)"
tail -n +1 -f "$LOG" &
TAIL_PID=$!
trap 'kill "$TAIL_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT
status=0
IDENTITY_GATE=true "$THIS_DIR/base.sh" > "$LOG" 2>&1 || status=$?
sleep 1
kill "$TAIL_PID" 2>/dev/null || true
if [ "$status" -ne 0 ]; then
  exit "$status"
fi

# Five nodes also fit the normal owner shortlist (N plus a buffer), so a decrypted round alone does
# not show that the nodes read the policy. Each node logs this marker when it ranks the operators
# that eligibilityAt finds active (all five owners are verified).
for n in 1 2 3 4 5; do
  if ! grep -q "\[cn$n\].*sortition_identity_policy_eligible_shortlist" "$LOG"; then
    echo "cn$n did not rank the eligible operators under the identity policy" >&2
    exit 1
  fi
done
echo "Every node ranked the eligible operators under the identity policy"
