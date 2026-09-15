#!/usr/bin/env bash
# Shared CRISP local dev configuration. Source from setup.sh / crisp_deploy.sh.

_crisp_dev_config_root() {
  (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
}

load_crisp_dev_config() {
  CRISP_ROOT="$(_crisp_dev_config_root)"
  REPO_ROOT="$(cd "${CRISP_ROOT}/../.." && pwd)"

  local cfg="${CRISP_ROOT}/crisp.dev.env"
  if [[ ! -f "$cfg" ]]; then
    cp "${CRISP_ROOT}/crisp.dev.env.example" "$cfg"
    echo "Created ${cfg} from crisp.dev.env.example"
  fi

  set -a
  # shellcheck disable=SC1090
  source "$cfg"
  set +a

  CRISP_BFV_PRESET="${CRISP_BFV_PRESET:-insecure}"
  CRISP_SKIP_PROOF_AGGREGATION="${CRISP_SKIP_PROOF_AGGREGATION:-true}"

  case "$CRISP_BFV_PRESET" in
    insecure)
      CRISP_E3_PARAM_SET=0
      ;;
    secure-8192)
      CRISP_E3_PARAM_SET=1
      ;;
    secure-16384)
      CRISP_E3_PARAM_SET=2
      ;;
    *)
      echo "Invalid CRISP_BFV_PRESET='${CRISP_BFV_PRESET}' (use insecure, secure-8192, or secure-16384)" >&2
      exit 1
      ;;
  esac

  case "$CRISP_SKIP_PROOF_AGGREGATION" in
    true | false) ;;
    *)
      echo "Invalid CRISP_SKIP_PROOF_AGGREGATION='${CRISP_SKIP_PROOF_AGGREGATION}' (use true or false)" >&2
      exit 1
      ;;
  esac

  if [[ "$CRISP_SKIP_PROOF_AGGREGATION" == "true" ]]; then
    unset ENABLE_ZK_VERIFICATION
  else
    export ENABLE_ZK_VERIFICATION=true
  fi
  export E3_NODES__CN1__SKIP_PROOF_AGGREGATION="$CRISP_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN2__SKIP_PROOF_AGGREGATION="$CRISP_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN3__SKIP_PROOF_AGGREGATION="$CRISP_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN4__SKIP_PROOF_AGGREGATION="$CRISP_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN5__SKIP_PROOF_AGGREGATION="$CRISP_SKIP_PROOF_AGGREGATION"

  export CRISP_BFV_PRESET CRISP_E3_PARAM_SET CRISP_SKIP_PROOF_AGGREGATION CRISP_ROOT REPO_ROOT
}

apply_crisp_dev_config_to_server_env() {
  local server_env="${CRISP_ROOT}/server/.env"
  if [[ ! -f "$server_env" ]]; then
    cp "${CRISP_ROOT}/server/.env.example" "$server_env"
  fi

  if grep -q '^E3_PARAM_SET=' "$server_env"; then
    sed -i.bak "s/^E3_PARAM_SET=.*/E3_PARAM_SET=${CRISP_E3_PARAM_SET}/" "$server_env"
    rm -f "${server_env}.bak"
  else
    printf '\n# 0=InsecureThreshold512, 1=SecureThreshold8192\nE3_PARAM_SET=%s\n' \
      "${CRISP_E3_PARAM_SET}" >> "$server_env"
  fi
}

build_interfold_circuits_at_setup() {
  if [[ "$CRISP_SKIP_PROOF_AGGREGATION" == "true" ]]; then
    echo "Skipping recursive proof-aggregation circuit build for the CRISP dev profile."
    return 0
  fi
  local committee="${CRISP_COMMITTEE:-minimum}"
  echo "Building interfold circuits (preset=${CRISP_BFV_PRESET}, committee=${committee})..."
  (
    cd "${REPO_ROOT}" &&
      pnpm build:circuits \
        --preset "${CRISP_BFV_PRESET}" \
        --committee "${committee}" \
        --skip-if-built
  )
}

sync_interfold_circuit_artifacts() {
  local committee="${CRISP_COMMITTEE:-minimum}"
  local src="${REPO_ROOT}/dist/circuits/${CRISP_BFV_PRESET}/${committee}"
  local dst="${CRISP_ROOT}/.interfold/noir/circuits/${CRISP_BFV_PRESET}/${committee}"

  if [[ ! -f "${src}/recursive/dkg/pk/pk.json" ]]; then
    echo "No built circuits at ${src}; run pnpm dev:setup first. Using interfold noir setup release layout."
    return 0
  fi

  echo "Syncing circuits ${CRISP_BFV_PRESET}/${committee} → ${dst}"
  mkdir -p "$(dirname "${dst}")"
  rm -rf "${dst}"
  cp -R "${src}" "$(dirname "${dst}")/"
}

print_crisp_dev_config_summary() {
  cat <<EOF

CRISP dev profile (${CRISP_ROOT}/crisp.dev.env):
  CRISP_BFV_PRESET=${CRISP_BFV_PRESET}
  E3_PARAM_SET=${CRISP_E3_PARAM_SET}
  CRISP_SKIP_PROOF_AGGREGATION=${CRISP_SKIP_PROOF_AGGREGATION}
  ENABLE_ZK_VERIFICATION=${ENABLE_ZK_VERIFICATION:-false} (used at deploy via dev:up)
  ciphernode skip flag=${CRISP_SKIP_PROOF_AGGREGATION}
  Contract addresses synced by dev:up (deploy → server/.env, client/.env, interfold.config.yaml)

EOF
}
