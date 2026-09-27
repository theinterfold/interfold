#!/bin/bash
# Tests for crates/ciphernode-entrypoint.sh: which state location the container uses.
#
# A mock `interfold` resolves paths the way crates/config/src/paths_engine.rs does:
# - an absolute key_file or db_file in the config wins;
# - otherwise E3_CONFIG_DIR / E3_DATA_DIR, when set;
# - otherwise the legacy directory beside the config file ($CONFIG_DIR/.interfold).
# The mock records the E3_* variables that the final command sees, so each case can assert the
# location the node would use.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ENTRYPOINT="$ROOT_DIR/crates/ciphernode-entrypoint.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

make_mock_interfold() {
    local bin_dir=$1
    mkdir -p "$bin_dir"
    cat > "$bin_dir/interfold" <<'MOCK'
#!/bin/bash
set -Eeuo pipefail
name=_default
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
        --name) name="${args[$((i + 1))]}" ;;
        --name=*) name="${args[$i]#--name=}" ;;
    esac
done
legacy="$CONFIG_DIR/.interfold"
config_dir="${E3_CONFIG_DIR:-$legacy/config}"
data_dir="${E3_DATA_DIR:-$legacy/data}"
key_file="${MOCK_KEY_FILE:-$config_dir/$name/key}"
db_file="${MOCK_DB_FILE:-$data_dir/$name/db}"
case "${1:-} ${2:-}" in
    "config get")
        # The real command creates the log directory and can print log lines first.
        mkdir -p "$data_dir/$name"
        echo "INFO loading config"
        case "$3" in
            key_file) echo "$key_file" ;;
            db_file) echo "$db_file" ;;
            *) exit 2 ;;
        esac
        ;;
    "password set")
        cat > /dev/null
        mkdir -p "$(dirname "$key_file")"
        : > "$key_file"
        ;;
    "wallet get") [ -e "$db_file" ] ;;
    "wallet set")
        cat > /dev/null
        mkdir -p "$db_file"
        ;;
    *)
        printf '%s|%s|%s\n' "${E3_CONFIG_DIR:-unset}" "${E3_DATA_DIR:-unset}" "$*" > "$RESULT_FILE"
        ;;
esac
MOCK
    chmod +x "$bin_dir/interfold"
}

# Run the entrypoint for one case. Extra arguments go to the entrypoint.
run_case() {
    local dir=$1
    shift
    make_mock_interfold "$dir/bin"
    mkdir -p "$dir/config" "$dir/data" "$dir/secrets"
    : > "$dir/config/config.yaml"
    printf '%s\n' '{"password":"pw","private_key":"0x1111111111111111111111111111111111111111111111111111111111111111"}' \
        > "$dir/secrets/secrets.json"
    rm -f "$dir/result"
    local secrets_file="$dir/secrets/secrets.json"
    sed "s#/run/secrets/secrets.json#$secrets_file#" "$ENTRYPOINT" > "$dir/entrypoint.sh"
    env PATH="$dir/bin:$PATH" \
        CONFIG_DIR="$dir/config" \
        DATA_DIR="$dir/data" \
        E3_CONFIG_DIR="$dir/data/config" \
        E3_DATA_DIR="$dir/data/data" \
        RESULT_FILE="$dir/result" \
        MOCK_KEY_FILE="${MOCK_KEY_FILE:-}" \
        MOCK_DB_FILE="${MOCK_DB_FILE:-}" \
        bash "$dir/entrypoint.sh" "$@" > "$dir/output" 2>&1
}

# Assert that the final command ran with the volume variables set, or with them unset.
expect_location() {
    local dir=$1 expected=$2 result
    [ -f "$dir/result" ] || fail "$(basename "$dir"): the node did not start: $(cat "$dir/output")"
    result=$(cut -d'|' -f1-2 < "$dir/result")
    case "$expected" in
        volume) [ "$result" = "$dir/data/config|$dir/data/data" ] ;;
        own) [ "$result" = "unset|unset" ] ;;
    esac || fail "$(basename "$dir"): expected the $expected location, got $result: $(cat "$dir/output")"
}

# A new node with the default config keeps its state on the volume.
case_dir="$TEST_ROOT/new-node"
run_case "$case_dir"
expect_location "$case_dir" volume

# State from an earlier image beside the config file stays there.
case_dir="$TEST_ROOT/legacy-state"
mkdir -p "$case_dir/config/.interfold/config/_default" "$case_dir/config/.interfold/data/_default/db"
: > "$case_dir/config/.interfold/config/_default/key"
run_case "$case_dir"
expect_location "$case_dir" own

# State on the volume stays there.
case_dir="$TEST_ROOT/volume-state"
mkdir -p "$case_dir/data/config/_default" "$case_dir/data/data/_default/db"
: > "$case_dir/data/config/_default/key"
run_case "$case_dir"
expect_location "$case_dir" volume

# State at both locations stops the container.
case_dir="$TEST_ROOT/both"
mkdir -p "$case_dir/config/.interfold/data/_default/db" "$case_dir/data/data/_default/db"
if run_case "$case_dir"; then
    fail "both: the entrypoint started with state at two locations"
fi
grep -q "Node state exists at two locations" "$case_dir/output" || fail "both: no error message"

# config.yaml sets an absolute key file on the volume, and the database is on the volume. The
# database path still depends on E3_DATA_DIR, so the volume must stay in use.
case_dir="$TEST_ROOT/absolute-key-on-volume"
mkdir -p "$case_dir/data/config/_default" "$case_dir/data/data/_default/db"
: > "$case_dir/data/config/_default/key"
MOCK_KEY_FILE="$case_dir/data/config/_default/key" run_case "$case_dir"
expect_location "$case_dir" volume

# config.yaml sets an absolute key file beside the config file, and the database is there too.
# The shared key file must not look like state at two locations.
case_dir="$TEST_ROOT/absolute-key-legacy"
mkdir -p "$case_dir/config/.interfold/config/_default" "$case_dir/config/.interfold/data/_default/db"
: > "$case_dir/config/.interfold/config/_default/key"
MOCK_KEY_FILE="$case_dir/config/.interfold/config/_default/key" run_case "$case_dir"
expect_location "$case_dir" own

# config.yaml sets both paths, so the variables change nothing.
case_dir="$TEST_ROOT/both-paths-set"
MOCK_KEY_FILE="$case_dir/elsewhere/key" MOCK_DB_FILE="$case_dir/elsewhere/db" run_case "$case_dir"
expect_location "$case_dir" own

# A named node: the probes must look at that profile's paths.
case_dir="$TEST_ROOT/named-node"
mkdir -p "$case_dir/config/.interfold/config/cn1" "$case_dir/config/.interfold/data/cn1/db"
: > "$case_dir/config/.interfold/config/cn1/key"
run_case "$case_dir" start --name cn1 --config "$case_dir/config/config.yaml"
expect_location "$case_dir" own
grep -q "start --name cn1" "$case_dir/result" || fail "named-node: the command was not passed through"

case_dir="$TEST_ROOT/named-node-equals"
mkdir -p "$case_dir/data/data/cn2/db"
run_case "$case_dir" start --name=cn2 --config "$case_dir/config/config.yaml"
expect_location "$case_dir" volume

echo "ciphernode-entrypoint.sh: all cases passed"
