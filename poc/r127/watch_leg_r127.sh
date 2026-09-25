#!/usr/bin/env bash
# r127 leg watcher: appends a status line every 120s until the unit exits.
cd /home/dev/interfold-research/interfold
OUT=poc/r127/status/leg-4c-watch.log
for i in $(seq 1 120); do
  st=$(systemctl --user is-active r127r78leg.service 2>/dev/null)
  cpu=$(systemctl --user status r127r78leg.service --no-pager 2>/dev/null | grep -oE 'CPU: [0-9]+[:m][ 0-9.]*')
  r78=$(journalctl --user -u r127r78leg.service --no-pager 2>/dev/null | grep -acE 'R78-|running 1 test|test result|panicked|error\[')
  comp=$(ps -eo comm --no-headers 2>/dev/null | grep -acE 'nargo2|rustc')
  echo "t=$(date -u +%H:%M:%S) unit=$st $cpu r78lines=$r78 compile_procs=$comp" >> "$OUT"
  if [ "$st" != "active" ]; then echo "EXITED rc=$st" >> "$OUT"; break; fi
  sleep 120
done