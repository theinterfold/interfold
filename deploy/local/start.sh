#!/usr/bin/env bash
# =============================================================================
# CRISP Development Launcher — VS Code terminals per service
# =============================================================================
#
# Primary (recommended):
#   Ctrl+Shift+P → "Tasks: Run Task" → "CRISP: Start All"
#   Opens 9 VS Code terminals: Anvil, Deploy+Setup, cn1-cn5, Program, Server, Client.
#   Each terminal handles its own waiting — no manual ordering needed.
#
# Tmux fallback:
#   bash deploy/local/start.sh            # 9 tmux windows
#
# Usage:
#   bash deploy/local/start.sh            # tmux mode
#   bash deploy/local/start.sh --vscode   # print VS Code instructions
#   bash deploy/local/start.sh --help
# =============================================================================

set -euo pipefail

# ── Resolve paths ───────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRISP_ROOT="$REPO_ROOT/examples/CRISP"
TMUX_SESSION="crisp-dev"
READYFILE="$CRISP_ROOT/.interfold/ready"

# ── Node configuration ──────────────────────────────────────────────────────
# Anvil test accounts #1–#5 (deterministic from the standard mnemonic)
NODE_IDS=(cn1 cn2 cn3 cn4 cn5)
NODE_KEYS=(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
)
NODE_ADDRS=(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
    "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
)

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }

# ── Helpers ─────────────────────────────────────────────────────────────────
command_exists() { command -v "$1" >/dev/null 2>&1; }

wait_for_port() {
    local host="${1:-localhost}" port="$2" label="${3:-$port}" max="${4:-60}"
    local attempt=1
    info "Waiting for $label ($host:$port)..."
    while [ $attempt -le $max ]; do
        if curl -s "http://$host:$port" >/dev/null 2>&1; then
            ok "$label is ready"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    err "$label did not start after ${max}s"
    return 1
}

# ── Dependency checks ───────────────────────────────────────────────────────
check_deps() {
    step "Checking dependencies..."
    local missing=()

    for cmd in pnpm anvil; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing dependencies: ${missing[*]}"
        err "Please install them and re-run."
        exit 1
    fi
    ok "Core dependencies found (pnpm, anvil)"

    # cargo is only needed if we have to install the interfold CLI.
    # check_deps runs before install_interfold, so only warn here.
    if ! command_exists cargo; then
        warn "cargo not found — interfold CLI must be pre-installed (e.g. 'which interfold')"
    fi

    if ! command_exists tmux; then
        warn "tmux not found — will print VS Code task instructions instead."
        warn "Install tmux for the best experience: sudo apt install tmux"
        return 1
    fi
    ok "tmux found"
    return 0
}

# ── Install interfold CLI ─────────────────────────────────────────────────────
install_interfold() {
    if command_exists interfold; then
        info "interfold CLI already installed ($(which interfold))"
        return 0
    fi
    if ! command_exists cargo; then
        err "interfold CLI not found and cargo is not available to install it."
        err "Install Rust (https://rustup.rs) or pre-install the interfold binary."
        exit 1
    fi
    step "Installing interfold CLI..."
    cd "$REPO_ROOT"
    cargo install --locked --path ./crates/cli --bin interfold -f
    ok "interfold CLI installed"
}

# ── Clean previous state ────────────────────────────────────────────────────
clean_state() {
    step "Cleaning previous dev state..."
    rm -rf "$CRISP_ROOT/.interfold/data"
    rm -rf "$CRISP_ROOT/.interfold/config"
    rm -rf "$CRISP_ROOT/server/database"
    rm -f "$READYFILE"
    ok "Dev state cleaned"
}

# ── Deploy contracts + ciphernode registration ──────────────────────────────
deploy_contracts() {
    step "Deploying contracts..."
    cd "$CRISP_ROOT"
    bash scripts/crisp_deploy.sh
    ok "Contracts deployed"
}

# ── Wallet setup + noir keys + ciphernode registration ──────────────────────
setup_nodes() {
    step "Setting up wallets and ciphernodes..."

    # 1. Import wallet keys
    for i in "${!NODE_IDS[@]}"; do
        info "Importing wallet for ${NODE_IDS[$i]}..."
        interfold wallet set --name "${NODE_IDS[$i]}" --private-key "${NODE_KEYS[$i]}"
    done

    # 2. Generate ZK keys (noir setup)
    info "Running interfold noir setup..."
    interfold noir setup

    # 3. Register all ciphernodes in the on-chain registry
    for i in "${!NODE_IDS[@]}"; do
        info "Registering ${NODE_IDS[$i]} (${NODE_ADDRS[$i]}) in ciphernode registry..."
        pnpm ciphernode:add --ciphernode-address "${NODE_ADDRS[$i]}" --network "localhost"
    done

    # 4. Signal ready for client
    echo 1 > "$READYFILE"
    ok "All 5 ciphernodes registered and ready"
}

# ── Tmux launcher ───────────────────────────────────────────────────────────
launch_tmux() {
    # Kill existing session if present
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        warn "tmux session '$TMUX_SESSION' already exists — killing it"
        tmux kill-session -t "$TMUX_SESSION"
        sleep 1
    fi

    step "Creating tmux session: $TMUX_SESSION"

    # ── Window 0: Anvil ─────────────────────────────────────────────────
    tmux new-session -d -s "$TMUX_SESSION" -n "anvil" -c "$CRISP_ROOT" \
        "anvil --host 0.0.0.0 --chain-id 31337 --block-time 1 --mnemonic 'test test test test test test test test test test test junk'"
    info "Window 0: anvil"

    # ── Wait for anvil, deploy, setup wallets + register ciphernodes ────
    wait_for_port localhost 8545 "Anvil" 60
    deploy_contracts
    setup_nodes
    # Create the signal file that run_service.sh expects (used by VS Code tasks).
    # This keeps tmux mode compatible with the VS Code runner if someone switches.
    touch /tmp/crisp-dev-daemon-ready
    ok "Signal file created: /tmp/crisp-dev-daemon-ready"
    # ── Start the swarm daemon (no nodes yet — we start each individually)
    step "Starting swarm daemon (detached, all nodes excluded)..."
    interfold nodes up --detach --exclude cn1,cn2,cn3,cn4,cn5
    sleep 3
    ok "Swarm daemon running"

    # ── Windows 1-5: Individual ciphernodes ─────────────────────────────
    local win=1
    for id in "${NODE_IDS[@]}"; do
        tmux new-window -t "$TMUX_SESSION" -n "$id" -c "$CRISP_ROOT" \
            "interfold nodes start $id; echo '[${id} exited — press Enter to close]'; read"
        info "Window $win: $id"
        win=$((win + 1))
    done

    # ── Window 6: Program Server ────────────────────────────────────────
    tmux new-window -t "$TMUX_SESSION" -n "program" -c "$CRISP_ROOT" \
        "bash scripts/dev_program.sh; echo '[program exited — press Enter to close]'; read"
    info "Window $win: program server"

    # ── Window 7: Server ────────────────────────────────────────────────
    tmux new-window -t "$TMUX_SESSION" -n "server" -c "$CRISP_ROOT" \
        "bash scripts/dev_server.sh; echo '[server exited — press Enter to close]'; read"
    info "Window $((win + 1)): server"

    # ── Window 8: Client ────────────────────────────────────────────────
    tmux new-window -t "$TMUX_SESSION" -n "client" -c "$CRISP_ROOT" \
        "bash scripts/dev_client.sh; echo '[client exited — press Enter to close]'; read"
    info "Window $((win + 2)): client"

    # ── Select window 0 (anvil) and attach ──────────────────────────────
    tmux select-window -t "$TMUX_SESSION:anvil"

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}All services launched in tmux session '${TMUX_SESSION}'${NC}     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${YELLOW}Windows:${NC}                                                    ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 0 → Anvil                                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 1 → cn1                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 2 → cn2                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 3 → cn3                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 4 → cn4                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 5 → cn5                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 6 → Program Server                                 ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 7 → Server                                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}    Ctrl+B 8 → Client                                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${YELLOW}Detach:${NC} Ctrl+B D                                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${YELLOW}Reattach:${NC} tmux attach -t ${TMUX_SESSION}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${YELLOW}Kill all:${NC} tmux kill-session -t ${TMUX_SESSION}                  ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    tmux attach -t "$TMUX_SESSION"
}

# ── VS Code fallback ───────────────────────────────────────────────────────
launch_vscode_instructions() {
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC}  ${CYAN}VS Code Tasks — Run each in order (separate terminals)${NC}     ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${YELLOW}1.${NC} Ctrl+Shift+P → \"Tasks: Run Task\"                         ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${YELLOW}2.${NC} Run tasks in this order:                                   ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     a) CRISP: Anvil                                           ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     b) CRISP: Deploy + Setup                                  ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     c) CRISP: cn1                                             ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     d) CRISP: cn2                                             ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     e) CRISP: cn3                                             ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     f) CRISP: cn4                                             ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     g) CRISP: cn5                                             ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     h) CRISP: Program Server                                  ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     i) CRISP: Server                                          ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}     j) CRISP: Client                                          ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Each task opens in a new terminal tab.                       ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Rename tabs with F2 for clarity.                             ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}     ${GREEN}🚀 CRISP Development Environment Launcher${NC}                   ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Parse flags
    case "${1:-}" in
        --help|-h)
            echo "Usage: bash deploy/local/start.sh [--vscode|--help]"
            echo ""
            echo "  (default)   Launch services in tmux windows"
            echo "  --vscode    Print instructions for VS Code task-based launch"
            echo "  --help      Show this help"
            exit 0
            ;;
        --vscode)
            launch_vscode_instructions
            exit 0
            ;;
    esac

    check_deps && HAS_TMUX=true || HAS_TMUX=false

    install_interfold
    clean_state

    if $HAS_TMUX; then
        launch_tmux
    else
        warn "tmux not available — falling back to VS Code task instructions"
        launch_vscode_instructions
    fi
}

main "$@" 