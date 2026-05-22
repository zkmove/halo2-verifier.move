#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SUI_ROOT="${SUI_ROOT:-/Users/ssyuan/work/project/zkmove_sui}"
ZKMOVE_ROOT="${ZKMOVE_ROOT:-/Users/ssyuan/work/project/zkmove}"
SUI_BIN="${SUI_BIN:-${SUI_ROOT}/target/debug/sui}"

API_PACKAGE_DIR="${API_PACKAGE_DIR:-${ROOT_DIR}/packages/api-sui}"
CONFIDENTIAL_ASSET_DIR="${CONFIDENTIAL_ASSET_DIR:-${ZKMOVE_ROOT}/examples/confidential-asset/on-chain-sui}"
DARK_FOREST_DIR="${DARK_FOREST_DIR:-${ZKMOVE_ROOT}/examples/dark-forest/on-chain-sui}"

WORK_DIR="${WORK_DIR:-/private/tmp/zkmove-sui-localnet-e2e}"
NETWORK_DIR="${WORK_DIR}/network"
LOG_DIR="${WORK_DIR}/logs"
CLIENT_CONFIG="${SUI_CLIENT_CONFIG:-${NETWORK_DIR}/client.yaml}"
PUBFILE="${WORK_DIR}/Pub.local.toml"
PACKAGE_WORK_DIR="${WORK_DIR}/packages"
API_PUBLISH_DIR=""
CONFIDENTIAL_ASSET_PUBLISH_DIR=""
DARK_FOREST_PUBLISH_DIR=""

RPC_HOST="${RPC_HOST:-127.0.0.1}"
RPC_PORT="${RPC_PORT:-9000}"
FAUCET_PORT="${FAUCET_PORT:-9123}"
RPC_URL="${RPC_URL:-http://${RPC_HOST}:${RPC_PORT}}"
FAUCET_URL="${FAUCET_URL:-http://${RPC_HOST}:${FAUCET_PORT}/gas}"

GAS_BUDGET="${GAS_BUDGET:-1000000000}"
CHUNK_SIZE="${CHUNK_SIZE:-15360}"
BUILD_ENV="${BUILD_ENV:-localnet}"
KEEP_LOCALNET="${KEEP_LOCALNET:-0}"
USE_EXISTING_LOCALNET="${USE_EXISTING_LOCALNET:-0}"
USE_FAUCET="${USE_FAUCET:-1}"
USE_EXPLICIT_GAS="${USE_EXPLICIT_GAS:-1}"
SENDER_ADDRESS="${SENDER_ADDRESS:-}"
TEST_ADDRESS_ALIAS="${TEST_ADDRESS_ALIAS:-e2e-$$}"
RUN_CONFIDENTIAL_ASSET="${RUN_CONFIDENTIAL_ASSET:-1}"
RUN_DARK_FOREST="${RUN_DARK_FOREST:-1}"

LOCALNET_PID=""
LOCALNET_CHAIN_ID=""
ACTIVE_ADDRESS=""
GAS_INDEX=0
GAS_COINS=()
TX_GAS_ARGS=()

log() {
  printf '[localnet-e2e] %s\n' "$*" >&2
}

die() {
  printf '[localnet-e2e] ERROR: %s\n' "$*" >&2
  exit 1
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  if [[ -n "${LOCALNET_PID}" && "${KEEP_LOCALNET}" != "1" ]]; then
    log "Stopping localnet pid ${LOCALNET_PID}"
    kill "${LOCALNET_PID}" >/dev/null 2>&1 || true
    wait "${LOCALNET_PID}" >/dev/null 2>&1 || true
  elif [[ -n "${LOCALNET_PID}" ]]; then
    log "Keeping localnet running: pid ${LOCALNET_PID}"
  fi
}

trap cleanup EXIT

client() {
  "${SUI_BIN}" client --client.config "${CLIENT_CONFIG}" "$@"
}

client_json() {
  "${SUI_BIN}" client --client.config "${CLIENT_CONFIG}" --json -q "$@"
}

tx_succeeded() {
  jq -e '.effects.status.status == "success"' >/dev/null
}

require_success() {
  local json_file="$1"
  local label="$2"
  if ! jq empty "${json_file}" >/dev/null 2>&1; then
    log "${label} did not return JSON; full output follows"
    cat "${json_file}" >&2
    exit 1
  fi
  if ! tx_succeeded <"${json_file}"; then
    log "${label} failed; full JSON follows"
    cat "${json_file}" >&2
    exit 1
  fi
}

published_package_id() {
  jq -r 'first(.objectChanges[]? | select(.type == "published") | .packageId) // empty'
}

created_object_id() {
  local suffix="$1"
  jq -r --arg suffix "${suffix}" '
    first(
      .objectChanges[]?
      | select(.type == "created")
      | select((.objectType // "") | endswith($suffix))
      | .objectId
    ) // empty
  '
}

created_object_id_contains() {
  local needle="$1"
  jq -r --arg needle "${needle}" '
    first(
      .objectChanges[]?
      | select(.type == "created")
      | select((.objectType // "") | contains($needle))
      | .objectId
    ) // empty
  '
}

run_json_to_file() {
  local out="$1"
  shift
  "$@" >"${out}"
}

is_rebuild_error() {
  grep -Eiq 'needs to be rebuilt|unavailable for consumption|current version' "$@" 2>/dev/null
}

refresh_gas_pool() {
  local owner="$1"
  local min_balance="${2:-100000000}"
  local gas_json="${WORK_DIR}/gas.${owner}.json"

  client_json gas "${owner}" >"${gas_json}"
  GAS_COINS=()
  while IFS= read -r coin_id; do
    [[ -n "${coin_id}" ]] && GAS_COINS+=("${coin_id}")
  done < <(
    jq -r --argjson min_balance "${min_balance}" '
      [
        .. | objects
        | select((.coinObjectId? // .gasCoinId?) != null)
        | select((((.balance? // .mistBalance?) // "0") | tonumber) >= $min_balance)
        | (.coinObjectId? // .gasCoinId?)
      ]
      | unique
      | .[]
    ' "${gas_json}"
  )

  if [[ "${#GAS_COINS[@]}" -eq 0 ]]; then
    log "No usable gas coin found for ${owner}; gas JSON follows"
    cat "${gas_json}" >&2
    die "no gas coin with balance >= ${min_balance}"
  fi
}

prepare_gas_args() {
  TX_GAS_ARGS=()
  if [[ "${USE_EXPLICIT_GAS}" != "1" ]]; then
    return
  fi

  refresh_gas_pool "${ACTIVE_ADDRESS}"
  local idx=$((GAS_INDEX % ${#GAS_COINS[@]}))
  local gas_id="${GAS_COINS[$idx]}"
  GAS_INDEX=$((GAS_INDEX + 1))
  log "Using gas coin ${gas_id} ($((idx + 1))/${#GAS_COINS[@]})"
  TX_GAS_ARGS=(--gas "${gas_id}")
}

copy_package() {
  local src="$1"
  local dst="$2"

  mkdir -p "${dst}"
  (
    cd "${src}"
    tar --exclude build --exclude Move.lock -cf - .
  ) | (
    cd "${dst}"
    tar -xf -
  )
}

rewrite_move_toml_deps() {
  local move_toml="$1"
  local verifier_api_dir="${2:-}"
  local package_name="${3:-}"
  python3 - "${move_toml}" "${SUI_ROOT}" "${verifier_api_dir}" "${BUILD_ENV}" "${LOCALNET_CHAIN_ID}" "${package_name}" <<'PY'
import re
import sys
path, sui_root, verifier_api, build_env, chain_id, package_name = sys.argv[1:7]
text = open(path, "r", encoding="utf-8").read()
std_dep = f'std = {{ local = "{sui_root}/crates/sui-framework/packages/move-stdlib" }}'
lower_sui_dep = f'sui = {{ local = "{sui_root}/crates/sui-framework/packages/sui-framework" }}'

def replace_section(src, header, body):
    pattern = rf'(?ms)^\[{re.escape(header)}\]\n.*?(?=^\[|\Z)'
    replacement = f'[{header}]\n{body.rstrip()}\n\n'
    if re.search(pattern, src):
        return re.sub(pattern, replacement, src, count=1)
    return src.rstrip() + "\n\n" + replacement

def remove_section(src, header):
    pattern = rf'(?ms)^\[{re.escape(header)}\]\n.*?(?=^\[|\Z)'
    return re.sub(pattern, "", src, count=1)

if package_name:
    text = re.sub(r'^name\s*=\s*"[^"]*"', f'name = "{package_name}"', text, count=1, flags=re.MULTILINE)
    if not re.search(r'^implicit-dependencies\s*=', text, flags=re.MULTILINE):
        if re.search(r'^edition\s*=', text, flags=re.MULTILINE):
            text = re.sub(r'^(edition\s*=\s*"[^"]*"\s*)$', r'\1\nimplicit-dependencies = false', text, count=1, flags=re.MULTILINE)
        else:
            text = re.sub(r'(\[package\]\n)', r'\1implicit-dependencies = false\n', text, count=1)
    verifier_dep = f'verifier_api = {{ local = "{verifier_api}" }}'
    deps = "\n".join([std_dep, lower_sui_dep, verifier_dep])
    text = replace_section(text, "dependencies", deps)
    text = remove_section(text, "addresses")
else:
    sui_dep = f'Sui = {{ local = "{sui_root}/crates/sui-framework/packages/sui-framework", override = true }}'
    text = re.sub(r'^Sui\s*=\s*\{[^\n]*\}', sui_dep, text, flags=re.MULTILINE)
    text = re.sub(r'^std\s*=\s*\{[^\n]*\}', std_dep, text, flags=re.MULTILINE)
    text = re.sub(r'^sui\s*=\s*\{[^\n]*\}', lower_sui_dep, text, flags=re.MULTILINE)
    if verifier_api:
        verifier_dep = f'verifier-api = {{ local = "{verifier_api}" }}'
        text = re.sub(r'^verifier-api\s*=\s*\{[^\n]*\}', verifier_dep, text, flags=re.MULTILINE)

env_line = f'{build_env} = "{chain_id}"'
if "[environments]" in text:
    pattern = rf'^{re.escape(build_env)}\s*=\s*"[^"]*"\s*$'
    if re.search(pattern, text, flags=re.MULTILINE):
        text = re.sub(pattern, env_line, text, flags=re.MULTILINE)
    else:
        text = re.sub(r'(\[environments\]\n)', rf'\1{env_line}\n', text, count=1)
else:
    text = text.rstrip() + f'\n\n[environments]\n{env_line}\n'
open(path, "w", encoding="utf-8").write(text)
PY
}

prepare_package_copies() {
  log "Preparing temporary package copies"
  rm -rf "${PACKAGE_WORK_DIR}"
  mkdir -p "${PACKAGE_WORK_DIR}"

  API_PUBLISH_DIR="${PACKAGE_WORK_DIR}/api-sui"
  CONFIDENTIAL_ASSET_PUBLISH_DIR="${PACKAGE_WORK_DIR}/confidential-asset-on-chain-sui"
  DARK_FOREST_PUBLISH_DIR="${PACKAGE_WORK_DIR}/dark-forest-on-chain-sui"

  copy_package "${API_PACKAGE_DIR}" "${API_PUBLISH_DIR}"
  copy_package "${CONFIDENTIAL_ASSET_DIR}" "${CONFIDENTIAL_ASSET_PUBLISH_DIR}"
  copy_package "${DARK_FOREST_DIR}" "${DARK_FOREST_PUBLISH_DIR}"

  rewrite_move_toml_deps "${API_PUBLISH_DIR}/Move.toml"
  rewrite_move_toml_deps "${CONFIDENTIAL_ASSET_PUBLISH_DIR}/Move.toml" "${API_PUBLISH_DIR}" confidential_asset_sui
  rewrite_move_toml_deps "${DARK_FOREST_PUBLISH_DIR}/Move.toml" "${API_PUBLISH_DIR}" dark_forest_sui
}

publish_package() {
  local package_dir="$1"
  local label="$2"
  local out="${WORK_DIR}/${label}.publish.json"
  local err="${out}.err"
  local ok=0

  log "Publishing ${label}"
  for attempt in 1 2 3; do
    prepare_gas_args
    if client_json test-publish \
      --build-env "${BUILD_ENV}" \
      --pubfile-path "${PUBFILE}" \
      --skip-dependency-verification \
      "${TX_GAS_ARGS[@]}" \
      --gas-budget "${GAS_BUDGET}" \
      "${package_dir}" >"${out}" 2>"${err}"; then
      ok=1
      break
    fi
    if is_rebuild_error "${out}" "${err}"; then
      log "Stale gas object while publishing ${label}; rebuilding transaction (attempt ${attempt}/3)"
      sleep 1
      continue
    fi
    cat "${err}" >&2 || true
    cat "${out}" >&2 || true
    exit 1
  done
  [[ "${ok}" == "1" ]] || die "publishing ${label} failed after gas refresh retries"
  require_success "${out}" "publish ${label}"

  local package_id
  package_id="$(published_package_id <"${out}")"
  [[ -n "${package_id}" ]] || die "could not parse package id for ${label}"
  printf '%s\n' "${package_id}"
}

call_json() {
  local out="$1"
  local package="$2"
  local module="$3"
  local function="$4"
  shift 4
  local err="${out}.err"
  local ok=0

  for attempt in 1 2 3; do
    prepare_gas_args
    if client_json call \
      --package "${package}" \
      --module "${module}" \
      --function "${function}" \
      "${TX_GAS_ARGS[@]}" \
      --gas-budget "${GAS_BUDGET}" \
      "$@" >"${out}" 2>"${err}"; then
      ok=1
      break
    fi
    if is_rebuild_error "${out}" "${err}"; then
      log "Stale gas object in ${module}::${function}; rebuilding transaction (attempt ${attempt}/3)"
      sleep 1
      continue
    fi
    cat "${err}" >&2 || true
    cat "${out}" >&2 || true
    exit 1
  done
  [[ "${ok}" == "1" ]] || die "${module}::${function} failed after gas refresh retries"
  require_success "${out}" "${module}::${function}"
}

extract_hex_fixture() {
  local function_name="$1"
  python3 - "$API_PACKAGE_DIR/tests/verifier_api_sui_tests.move" "${function_name}" <<'PY'
import re
import sys
path, name = sys.argv[1], sys.argv[2]
text = open(path, "r", encoding="utf-8").read()
match = re.search(rf"fun\s+{re.escape(name)}\s*\([^)]*\)\s*:[^{{]+{{\s*x\"([0-9a-fA-F]+)\"", text)
if not match:
    raise SystemExit(f"fixture not found: {name}")
print(match.group(1).lower())
PY
}

hex_to_json_array() {
  python3 - "$1" <<'PY'
import sys
data = bytes.fromhex(sys.argv[1])
print("[" + ",".join(str(b) for b in data) + "]")
PY
}

hex_digest_json_array() {
  python3 - "$1" <<'PY'
import hashlib
import sys
data = bytes.fromhex(sys.argv[1])
digest = hashlib.blake2b(data, digest_size=32).digest()
print("[" + ",".join(str(b) for b in digest) + "]")
PY
}

hex_chunk_json_arrays() {
  python3 - "$1" "${CHUNK_SIZE}" <<'PY'
import sys
data = bytes.fromhex(sys.argv[1])
chunk_size = int(sys.argv[2])
for offset in range(0, len(data), chunk_size):
    chunk = data[offset:offset + chunk_size]
    print("[" + ",".join(str(b) for b in chunk) + "]")
PY
}

public_inputs_json() {
  python3 - "$1" <<'PY'
import sys
scalar = list(bytes.fromhex(sys.argv[1]))
inner = "[" + ",".join(str(b) for b in scalar) + "]"
print("[[" + ",".join([inner, inner, inner]) + "]]")
PY
}

wait_for_rpc() {
  log "Waiting for localnet RPC at ${RPC_URL}"
  for _ in $(seq 1 90); do
    if [[ -n "${LOCALNET_PID}" ]] && ! kill -0 "${LOCALNET_PID}" >/dev/null 2>&1; then
      die "localnet exited before RPC became ready; see ${LOG_DIR}/localnet.log"
    fi

    local response
    response="$(curl -sS \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"sui_getChainIdentifier","params":[]}' \
      "${RPC_URL}" 2>/dev/null || true)"
    if jq -e '.result' >/dev/null 2>&1 <<<"${response}"; then
      LOCALNET_CHAIN_ID="$(jq -r '.result' <<<"${response}")"
      return
    fi
    sleep 1
  done
  die "localnet RPC did not become ready; see ${LOG_DIR}/localnet.log"
}

wait_for_balance() {
  local address="$1"
  log "Waiting for funded balance"
  for _ in $(seq 1 60); do
    if client_json balance "${address}" 2>/dev/null \
      | jq -e 'any(.. | objects; ((.balance? // "0") | tonumber) > 0)' >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "address is not funded: ${address}"
}

request_faucet() {
  local address="$1"
  local out="${WORK_DIR}/faucet.json"

  log "Requesting faucet funds"
  for _ in $(seq 1 60); do
    if client_json faucet --address "${address}" --url "${FAUCET_URL}" >"${out}" 2>"${WORK_DIR}/faucet.err"; then
      return
    fi
    if [[ -n "${LOCALNET_PID}" ]] && ! kill -0 "${LOCALNET_PID}" >/dev/null 2>&1; then
      log "faucet request failed; last error follows"
      cat "${WORK_DIR}/faucet.err" >&2 || true
      die "localnet exited before faucet became ready; see ${LOG_DIR}/localnet.log"
    fi
    sleep 1
  done

  log "faucet request failed; last error follows"
  cat "${WORK_DIR}/faucet.err" >&2 || true
  die "faucet did not become ready at ${FAUCET_URL}"
}

start_localnet() {
  mkdir -p "${NETWORK_DIR}" "${LOG_DIR}"

  if [[ "${USE_EXISTING_LOCALNET}" == "1" ]]; then
    log "Using existing localnet at ${RPC_URL}"
  else
    log "Starting fresh Sui localnet"
    local start_args=(
      start
      --force-regenesis \
      --fullnode-rpc-port "${RPC_PORT}"
    )
    if [[ "${USE_FAUCET}" == "1" ]]; then
      start_args+=(--with-faucet="${RPC_HOST}:${FAUCET_PORT}")
    fi
    SUI_CONFIG_DIR="${NETWORK_DIR}" "${SUI_BIN}" "${start_args[@]}" \
      >"${LOG_DIR}/localnet.log" 2>&1 &
    LOCALNET_PID="$!"
  fi

  wait_for_rpc
  if ! client switch --env localnet >/dev/null 2>&1; then
    client -y new-env --alias localnet --rpc "${RPC_URL}" >/dev/null
    client switch --env localnet >/dev/null
  fi

  local address
  if [[ -n "${SENDER_ADDRESS}" ]]; then
    client switch --address "${SENDER_ADDRESS}" >/dev/null
    address="${SENDER_ADDRESS}"
  elif [[ "${USE_FAUCET}" == "1" ]]; then
    local address_json
    address_json="$(client_json new-address ed25519 "${TEST_ADDRESS_ALIAS}")"
    address="$(jq -r '.address // empty' <<<"${address_json}")"
    [[ -n "${address}" ]] || die "could not create local e2e address"
    client switch --address "${address}" >/dev/null
  else
    address="$(client active-address 2>/dev/null | tail -n 1 | tr -d '[:space:]')"
  fi
  [[ -n "${address}" ]] || die "could not read active localnet address from ${CLIENT_CONFIG}"
  if [[ "${USE_FAUCET}" == "1" ]]; then
    request_faucet "${address}"
  fi
  wait_for_balance "${address}"
  log "Active address: ${address}"
  log "Build env: ${BUILD_ENV} (${LOCALNET_CHAIN_ID})"
  ACTIVE_ADDRESS="${address}"
  refresh_gas_pool "${ACTIVE_ADDRESS}"
  log "Gas pool ready: ${#GAS_COINS[@]} coin(s)"
}

publish_builder() {
  local api_package="$1"
  local function="$2"
  local label="$3"
  local out="${WORK_DIR}/${label}.builder.json"

  call_json "${out}" "${api_package}" artifact_builder "${function}"
  local builder_id
  builder_id="$(created_object_id "::artifact_builder::ArtifactBuilder" <"${out}")"
  [[ -n "${builder_id}" ]] || die "could not parse ${label} builder object id"
  printf '%s\n' "${builder_id}"
}

append_chunks() {
  local api_package="$1"
  local builder_id="$2"
  local artifact_hex="$3"
  local label="$4"
  local idx=0

  while IFS= read -r chunk_json; do
    idx=$((idx + 1))
    local out="${WORK_DIR}/${label}.append.${idx}.json"
    log "Appending ${label} chunk ${idx}"
    call_json "${out}" "${api_package}" artifact_builder append_chunk \
      --args "${builder_id}" "${chunk_json}"
  done < <(hex_chunk_json_arrays "${artifact_hex}")
}

finalize_artifact() {
  local api_package="$1"
  local builder_id="$2"
  local artifact_hex="$3"
  local function="$4"
  local object_suffix="$5"
  local label="$6"
  local out="${WORK_DIR}/${label}.finalize.json"
  local digest_json

  digest_json="$(hex_digest_json_array "${artifact_hex}")"
  log "Finalizing ${label}"
  call_json "${out}" "${api_package}" artifact_builder "${function}" \
    --args "${builder_id}" "${digest_json}"

  local object_id
  object_id="$(created_object_id "${object_suffix}" <"${out}")"
  [[ -n "${object_id}" ]] || die "could not parse finalized ${label} object id"
  printf '%s\n' "${object_id}"
}

upload_artifact() {
  local api_package="$1"
  local artifact_hex="$2"
  local builder_function="$3"
  local finalize_function="$4"
  local object_suffix="$5"
  local label="$6"

  local builder_id
  builder_id="$(publish_builder "${api_package}" "${builder_function}" "${label}")"
  append_chunks "${api_package}" "${builder_id}" "${artifact_hex}" "${label}"
  finalize_artifact "${api_package}" "${builder_id}" "${artifact_hex}" "${finalize_function}" "${object_suffix}" "${label}"
}

run_confidential_asset() {
  local package_id="$1"
  local params_obj="$2"
  local vk_obj="$3"
  local circuit_obj="$4"
  local public_inputs="$5"
  local proof="$6"

  log "Running confidential-asset e2e"
  local cap_out store_out mint_out cap_obj store_obj
  cap_out="${WORK_DIR}/confidential.mint_cap.json"
  store_out="${WORK_DIR}/confidential.store.json"
  mint_out="${WORK_DIR}/confidential.mint.json"

  call_json "${cap_out}" "${package_id}" token publish_mint_cap
  cap_obj="$(created_object_id_contains "::token::MintCap" <"${cap_out}")"
  [[ -n "${cap_obj}" ]] || die "could not parse MintCap object id"

  call_json "${store_out}" "${package_id}" token register_to_sender
  store_obj="$(created_object_id_contains "::token::Store" <"${store_out}")"
  [[ -n "${store_obj}" ]] || die "could not parse Store object id"

  call_json "${mint_out}" "${package_id}" token mint_from_bytes \
    --args \
    "${cap_obj}" \
    "${store_obj}" \
    "${params_obj}" \
    "${vk_obj}" \
    "${circuit_obj}" \
    "1" \
    "${public_inputs}" \
    "${proof}"
  log "confidential-asset mint_from_bytes succeeded"
}

run_dark_forest() {
  local package_id="$1"
  local params_obj="$2"
  local vk_obj="$3"
  local circuit_obj="$4"
  local public_inputs="$5"
  local proof="$6"

  log "Running dark-forest e2e"
  local game_out planet_out game_obj
  game_out="${WORK_DIR}/dark_forest.game.json"
  planet_out="${WORK_DIR}/dark_forest.create_planet.json"

  call_json "${game_out}" "${package_id}" game new_game_to_sender
  game_obj="$(created_object_id_contains "::game::Game" <"${game_out}")"
  [[ -n "${game_obj}" ]] || die "could not parse Game object id"

  call_json "${planet_out}" "${package_id}" game create_planet_from_bytes \
    --args \
    "${game_obj}" \
    "${params_obj}" \
    "${vk_obj}" \
    "${circuit_obj}" \
    "1" \
    "${public_inputs}" \
    "${proof}"
  log "dark-forest create_planet_from_bytes succeeded"
}

main() {
  require_bin jq
  require_bin python3
  require_bin curl
  [[ -x "${SUI_BIN}" ]] || die "SUI binary not found or not executable: ${SUI_BIN}"
  [[ -d "${API_PACKAGE_DIR}" ]] || die "API package dir not found: ${API_PACKAGE_DIR}"
  [[ -d "${CONFIDENTIAL_ASSET_DIR}" ]] || die "confidential asset package dir not found: ${CONFIDENTIAL_ASSET_DIR}"
  [[ -d "${DARK_FOREST_DIR}" ]] || die "dark forest package dir not found: ${DARK_FOREST_DIR}"

  rm -rf "${WORK_DIR}"
  mkdir -p "${WORK_DIR}" "${LOG_DIR}"

  start_localnet
  prepare_package_copies

  local params_hex vk_hex circuit_hex scalar_hex proof_hex
  params_hex="$(extract_hex_fixture params)"
  vk_hex="$(extract_hex_fixture vk)"
  circuit_hex="$(extract_hex_fixture circuit_info)"
  scalar_hex="$(extract_hex_fixture public_input_scalar)"
  proof_hex="$(extract_hex_fixture proof)"

  local proof_json public_inputs
  proof_json="$(hex_to_json_array "${proof_hex}")"
  public_inputs="$(public_inputs_json "${scalar_hex}")"

  local api_package params_obj vk_obj circuit_obj
  api_package="$(publish_package "${API_PUBLISH_DIR}" "verifier_api")"
  log "verifier-api package: ${api_package}"

  params_obj="$(upload_artifact "${api_package}" "${params_hex}" publish_params_builder finalize_params_to_sender "::serialized_params_store::SerializedParams" params)"
  vk_obj="$(upload_artifact "${api_package}" "${vk_hex}" publish_vk_builder finalize_vk_to_sender "::native_verifier::SerializedVK" vk)"
  circuit_obj="$(upload_artifact "${api_package}" "${circuit_hex}" publish_circuit_info_builder finalize_circuit_info_to_sender "::native_verifier::SerializedCircuit" circuit)"

  log "SerializedParams object: ${params_obj}"
  log "SerializedVK object: ${vk_obj}"
  log "SerializedCircuit object: ${circuit_obj}"

  if [[ "${RUN_CONFIDENTIAL_ASSET}" == "1" ]]; then
    local confidential_package
    confidential_package="$(publish_package "${CONFIDENTIAL_ASSET_PUBLISH_DIR}" "confidential_asset_sui")"
    log "confidential-asset package: ${confidential_package}"
    run_confidential_asset "${confidential_package}" "${params_obj}" "${vk_obj}" "${circuit_obj}" "${public_inputs}" "${proof_json}"
  fi

  if [[ "${RUN_DARK_FOREST}" == "1" ]]; then
    local dark_forest_package
    dark_forest_package="$(publish_package "${DARK_FOREST_PUBLISH_DIR}" "dark_forest_sui")"
    log "dark-forest package: ${dark_forest_package}"
    run_dark_forest "${dark_forest_package}" "${params_obj}" "${vk_obj}" "${circuit_obj}" "${public_inputs}" "${proof_json}"
  fi

  log "E2E completed successfully"
  log "Artifacts and transaction JSON: ${WORK_DIR}"
}

main "$@"
