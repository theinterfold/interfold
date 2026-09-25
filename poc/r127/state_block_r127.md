<!-- preflight-verified block: no import / no tool call; every number below is
     RAN RAN (executed on-box 2026-09-12, this round). Owner can audit via:
       journalctl --user -u r127r78leg.service --no-pager | grep R78
       git show HEAD -- poc/r127/status/leg-4c-time-20260912.log -->
r127 = r78 card 19-node E2E leg: RAN-GREEN on-box 2026-09-12 20:08 UTC.
  test node_fold_function_end_to_end_small
  wall      3959.68 s = 65.99 min  @ 4c-pinned (taskset 0-3, taskset pin against r69/r70)
  peak RSS  15,449,312 kB = 14.73 GiB
  Swaps 0   exit status 0 (RC-TEST 0, "1 passed; 0 failed")
  verify_fold_proof(node_fold) = true
  node_fold public fields = 204  (NODE_FOLD_PUBLIC_LEN secure-small RAN-asserted)
  party-binding field[0] = 0x28b00cd82a143a02d92c70d575272334560cfb2c0f6a3785a64a8b6db246b697
  prove_node_dkg_fold wall = 542.4 s
  c2ab 17.7 / c3a 501.7 / c3b 501.7 / c3ab 9.1 / c4ab 9.4 / node_fold 22.3 s
  leaves: c0 2.8 / c1 20.6 / c2a 68.4 / c2b 77.9 / **c3-inners x108 serial 3182.7 s (80.2% of leg)**
         / c4a 28.5 / c4b 28.4 s
  vs model 5406.7 s (90.1 min, r70-era c3-bulk anchor 5183.0 s): 3959.68 s = -26.8%
  infra lock-find: build.rs -> build_fixtures.sh -> pnpm build:circuits -> NESTED
  cargo run (same-target) deadlocks via target/release/.cargo-lock circular wait
  (RAN: nested pid 44394 wchan=locks_lock_inode_wait, unit cgroup cpu.stat delta 0 in
   two 90 s windows). Unblock: pre-stage circuits/bin/recursive_aggregation/{c3_fold,
  c6_fold,c6_fold_kernel}/target/*.json (standalone cargo run, idempotent).
  Branch: i5/dkg-research; upstream origin/main 95c38d70 == merge-base (69/0, no rebase).
  Review branch: research/r127-r78-e2e-ran -> enclave (private review repo).
  STATE: see /home/dev/interfold-research/STATE.md round-127 header + LOG r127 entry.