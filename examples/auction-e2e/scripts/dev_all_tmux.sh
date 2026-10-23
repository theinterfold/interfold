#!/usr/bin/env bash
set -e

SESSION_NAME="interfold-splits"

# Check if tmux is available
if command -v tmux &> /dev/null; then
    echo "tmux found - using tmux session..."
    # Kill existing session if it exists
    tmux kill-session -t "$SESSION_NAME" &> /dev/null || true
    
    echo "Creating new session '$SESSION_NAME'..."
    # Create new session
    tmux new-session -d -s "$SESSION_NAME"
    tmux select-pane -t 1
    tmux split-window -h
    tmux split-window -h
    tmux select-layout even-horizontal
    tmux select-pane -t 1
    tmux split-window -v
    tmux select-pane -t 3
    tmux split-window -v
    tmux select-pane -t 5
    tmux split-window -v
    tmux select-layout tiled
    tmux send-keys -t 1 'clear' C-m
    tmux send-keys -t 2 'clear' C-m
    tmux send-keys -t 3 'clear' C-m
    tmux send-keys -t 4 'clear' C-m
    tmux send-keys -t 5 'clear' C-m
    tmux send-keys -t 6 'clear' C-m
    tmux send-keys -t 1 'pnpm dev:evm' C-m
    sleep 1
    tmux send-keys -t 2 'pnpm dev:ciphernodes' C-m
    sleep 1
    tmux send-keys -t 3 'pnpm dev:server' C-m
    sleep 1
    tmux send-keys -t 4 'pnpm dev:program' C-m
    sleep 1
    tmux send-keys -t 5 'pnpm dev:frontend' C-m
    sleep 1
    tmux send-keys -t 6 'pnpm wait-on tcp:localhost:8545 && node ./scripts/anvil-automine.mjs' C-m
    
    tmux attach-session -t "$SESSION_NAME"
else
  echo "This script requires tmux to be installed.\n\n https://github.com/tmux/tmux/wiki/Installing"
fi
