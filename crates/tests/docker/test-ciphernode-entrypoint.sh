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
printf '%s\n' "$*" >> "${CALLS_FILE:-/dev/null}"
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
    env -u E3_CONFIG_DIR -u E3_DATA_DIR \
        PATH="$dir/bin:$PATH" \
        CONFIG_DIR="$dir/config" \
        DATA_DIR="$dir/data" \
        ${CASE_E3_CONFIG_DIR:+E3_CONFIG_DIR="$CASE_E3_CONFIG_DIR"} \
        ${CASE_E3_DATA_DIR:+E3_DATA_DIR="$CASE_E3_DATA_DIR"} \
        RESULT_FILE="$dir/result" \
        CALLS_FILE="$dir/calls" \
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

# A start with arguments gets the password and wallet setup, so a fresh `start --bootstrap` with
# mounted secrets works when the automatic credentials are off. Without `--config` the start gets
# the container's config file, the one the setup used.
case_dir="$TEST_ROOT/argument-start"
run_case "$case_dir" start --bootstrap
expect_location "$case_dir" volume
grep -q "Setting password" "$case_dir/output" || fail "argument-start: the password was not set"
grep -q "Setting wallet key" "$case_dir/output" || fail "argument-start: the wallet key was not set"
grep -q "start --bootstrap --config=$case_dir/config/config.yaml" "$case_dir/result" \
    || fail "argument-start: the command was not passed through with the container's config file"
grep -q "password set --config=$case_dir/config/config.yaml" "$case_dir/calls" \
    || fail "argument-start: the setup did not use the container's config file"
[ ! -e "$case_dir/secrets/secrets.json" ] || fail "argument-start: the secrets file was kept"
[ -e "$case_dir/data/config/_default/key" ] || fail "argument-start: the default profile has no key"

# The setup provisions the profile that the start names, not `_default`, and a global option in
# front of the command still selects the setup.
case_dir="$TEST_ROOT/argument-start-named"
run_case "$case_dir" --name=cn1 -v start --config "$case_dir/config/config.yaml"
expect_location "$case_dir" volume
grep -q "Setting password" "$case_dir/output" || fail "argument-start-named: the password was not set"
[ -e "$case_dir/data/config/cn1/key" ] || fail "argument-start-named: the named profile has no key"
[ ! -e "$case_dir/data/config/_default/key" ] || fail "argument-start-named: the default profile was provisioned"
grep -q -- "--name=cn1 -v start --config $case_dir/config/config.yaml" "$case_dir/result" \
    || fail "argument-start-named: the command was changed"

# The named profile's wallet is provisioned too, not `_default`'s.
[ -e "$case_dir/data/data/cn1/db" ] || fail "argument-start-named: the named profile has no wallet"
[ ! -e "$case_dir/data/data/_default/db" ] || fail "argument-start-named: the default wallet was provisioned"

# A help request never provisions anything, also inside a cluster of short options.
case_dir="$TEST_ROOT/start-help"
run_case "$case_dir" start --help
if grep -q "Setting password" "$case_dir/output"; then
    fail "start-help: a help request set the password"
fi
[ -e "$case_dir/secrets/secrets.json" ] || fail "start-help: the secrets file was consumed"
case_dir="$TEST_ROOT/start-help-cluster"
run_case "$case_dir" start -vh
if grep -q "Setting password" "$case_dir/output"; then
    fail "start-help-cluster: a clustered help request set the password"
fi
[ -e "$case_dir/secrets/secrets.json" ] || fail "start-help-cluster: the secrets file was consumed"

# An explicit config file in any of clap's short forms is used for the setup and is not appended
# a second time.
for form in attached equals cluster; do
    case_dir="$TEST_ROOT/explicit-config-$form"
    mkdir -p "$case_dir/config"
    : > "$case_dir/config/custom.yaml"
    case "$form" in
        attached) run_case "$case_dir" start "-c$case_dir/config/custom.yaml" ;;
        equals) run_case "$case_dir" start "-c=$case_dir/config/custom.yaml" ;;
        cluster) run_case "$case_dir" -vc "$case_dir/config/custom.yaml" start ;;
    esac
    expect_location "$case_dir" volume
    grep -q "Setting password" "$case_dir/output" || fail "explicit-config-$form: the password was not set"
    if grep -q -- "--config" "$case_dir/result"; then
        fail "explicit-config-$form: a second config option was appended: $(cat "$case_dir/result")"
    fi
    grep -q "custom.yaml" "$case_dir/result" || fail "explicit-config-$form: the explicit config was lost"
    grep -q "password set --config=$case_dir/config/custom.yaml" "$case_dir/calls" \
        || fail "explicit-config-$form: the setup did not use the explicit config file"
done

# A config file whose name starts with a hyphen stays a value, and the default config goes before a
# `--` terminator.
case_dir="$TEST_ROOT/hyphen-config"
mkdir -p "$case_dir/config"
: > "$case_dir/config/-custom.yaml"
( cd "$case_dir/config" && run_case "$case_dir" start -c=-custom.yaml )
grep -q "password set --config=-custom.yaml" "$case_dir/calls" \
    || fail "hyphen-config: the setup lost the hyphen-leading config file: $(cat "$case_dir/calls")"
case_dir="$TEST_ROOT/terminator"
run_case "$case_dir" start --
grep -q "start --config=$case_dir/config/config.yaml --$" "$case_dir/result" \
    || fail "terminator: the config was not placed before --: $(cat "$case_dir/result")"

# Other commands still run without the setup.
case_dir="$TEST_ROOT/other-command"
run_case "$case_dir" node validate --config "$case_dir/config/config.yaml"
grep -q "node validate" "$case_dir/result" || fail "other-command: the command was not passed through"
if grep -q "Setting password" "$case_dir/output"; then
    fail "other-command: a command other than start set the password"
fi
[ -e "$case_dir/secrets/secrets.json" ] || fail "other-command: the secrets file was consumed"

case_dir="$TEST_ROOT/named-node-equals"
mkdir -p "$case_dir/data/data/cn2/db"
run_case "$case_dir" start --name=cn2 --config "$case_dir/config/config.yaml"
expect_location "$case_dir" volume

# The container sets its own directories: the entrypoint keeps them and does not probe.
case_dir="$TEST_ROOT/own-directories"
mkdir -p "$case_dir/custom"
CASE_E3_CONFIG_DIR="$case_dir/custom/config" CASE_E3_DATA_DIR="$case_dir/custom/data" run_case "$case_dir"
result=$(cut -d'|' -f1-2 < "$case_dir/result")
[ "$result" = "$case_dir/custom/config|$case_dir/custom/data" ] ||
    fail "own-directories: expected the container's directories, got $result"

# The image does not set the variables, so running the binary directly is unaffected.
grep -q '^ENV E3_' "$ROOT_DIR/crates/Dockerfile" &&
    fail "the image must not set E3_CONFIG_DIR or E3_DATA_DIR: they would apply to --entrypoint interfold"

echo "ciphernode-entrypoint.sh: all cases passed"
