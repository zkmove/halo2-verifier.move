#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SUI_BIN="${SUI_BIN:-sui}"
SUI_CLIENT_CONFIG="${SUI_CLIENT_CONFIG:-}"
VERIFIER_API_PACKAGE="${VERIFIER_API_PACKAGE:-}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${ROOT_DIR}/txns/sui-artifacts}"
PARAMS_TXN="${PARAMS_TXN:-}"
VK_TXN="${VK_TXN:-}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/txns/sui-artifacts-upload}"
ENV_FILE="${ENV_FILE:-}"
GAS_BUDGET="${GAS_BUDGET:-1000000000}"
CHUNK_SIZE="${CHUNK_SIZE:-15360}"

log() {
  printf '[upload-sui-artifacts] %s\n' "$*" >&2
}

die() {
  printf '[upload-sui-artifacts] ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Upload Sui verifier artifacts from generated zkmove JSON descriptors.

Required:
  --verifier-api-package <package-id>
      The published verifier_api package id on the target Sui network.

Inputs:
  --artifacts-dir <dir>
      Directory containing:
        *-publish-params-native.txn
        *-publish-vk-native.txn
      Default: $ARTIFACTS_DIR or <halo2-verifier.move>/txns/sui-artifacts

  --params-txn <file>
      Explicit params publish descriptor. Defaults to the only
      *-publish-params-native.txn under --artifacts-dir.

  --vk-txn <file>
      Explicit VK publish descriptor. Defaults to the only
      *-publish-vk-native.txn under --artifacts-dir.

Options:
  --out-dir <dir>
      Directory for transaction JSON outputs.
      Default: $OUT_DIR or <halo2-verifier.move>/txns/sui-artifacts-upload

  --env-file <file>
      File that receives exported PARAMS_OBJECT_ID and VK_OBJECT_ID.
      Default: $ENV_FILE or <out-dir>/sui-artifact-objects.env

  --sui-bin <path>
      Sui CLI binary. Default: $SUI_BIN or sui.

  --client-config <file>
      Optional Sui client config file. Also supported via SUI_CLIENT_CONFIG.

  --gas-budget <mist>
      Gas budget for every Sui call. Default: 1000000000.

  --chunk-size <bytes>
      Upload chunk size for byte-array pure arguments. Default: 15360.

Example:
  export VERIFIER_API_PACKAGE=0x...
  scripts/upload_sui_artifacts.sh \
    --artifacts-dir txns/sui-artifacts \
    --out-dir txns/sui-artifacts-upload

  source txns/sui-artifacts-upload/sui-artifact-objects.env
EOF
}

arg_value() {
  [[ $# -ge 2 ]] || die "$1 requires a value"
  [[ -n "$2" && "$2" != --* ]] || die "$1 requires a value"
  printf '%s\n' "$2"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verifier-api-package)
      VERIFIER_API_PACKAGE="$(arg_value "$@")"
      shift 2
      ;;
    --artifacts-dir)
      ARTIFACTS_DIR="$(arg_value "$@")"
      shift 2
      ;;
    --params-txn)
      PARAMS_TXN="$(arg_value "$@")"
      shift 2
      ;;
    --vk-txn)
      VK_TXN="$(arg_value "$@")"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$(arg_value "$@")"
      shift 2
      ;;
    --env-file)
      ENV_FILE="$(arg_value "$@")"
      shift 2
      ;;
    --sui-bin)
      SUI_BIN="$(arg_value "$@")"
      shift 2
      ;;
    --client-config)
      SUI_CLIENT_CONFIG="$(arg_value "$@")"
      shift 2
      ;;
    --gas-budget)
      GAS_BUDGET="$(arg_value "$@")"
      shift 2
      ;;
    --chunk-size)
      CHUNK_SIZE="$(arg_value "$@")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

ENV_FILE="${ENV_FILE:-${OUT_DIR}/sui-artifact-objects.env}"

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

resolve_single_file() {
  local dir="$1"
  local name_pattern="$2"
  local label="$3"
  local matches=()
  local candidate

  while IFS= read -r -d '' candidate; do
    matches+=("${candidate}")
  done < <(find "${dir}" -maxdepth 1 -type f -name "${name_pattern}" -print0)

  if [[ "${#matches[@]}" -eq 0 ]]; then
    die "could not find ${label}; expected ${dir}/${name_pattern}"
  fi
  if [[ "${#matches[@]}" -gt 1 ]]; then
    printf '[upload-sui-artifacts] Multiple %s candidates found:\n' "${label}" >&2
    printf '  %s\n' "${matches[@]}" >&2
    die "pass --${label}-txn explicitly"
  fi

  printf '%s\n' "${matches[0]}"
}

json_byte_arg_hex() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path = sys.argv[1]
index = int(sys.argv[2])
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

args = payload.get("args")
if not isinstance(args, list) or index >= len(args):
    raise SystemExit(f"{path}: missing args[{index}]")

values = args[index]
if not isinstance(values, list):
    raise SystemExit(f"{path}: args[{index}] is not a byte array")

out = bytearray()
for i, value in enumerate(values):
    if not isinstance(value, int) or value < 0 or value > 255:
        raise SystemExit(f"{path}: args[{index}][{i}] is not a byte")
    out.append(value)

print(bytes(out).hex())
PY
}

hex_digest_json_array() {
  python3 - "$1" <<'PY'
import hashlib
import sys

hex_text = sys.argv[1].strip()
data = bytes.fromhex(hex_text)
digest = hashlib.blake2b(data, digest_size=32).digest()
print("[" + ",".join(str(b) for b in digest) + "]")
PY
}

hex_chunk_json_arrays() {
  python3 - "$1" "$2" <<'PY'
import sys

chunk_size = int(sys.argv[1])
if chunk_size <= 0:
    raise SystemExit("chunk size must be positive")

hex_text = sys.argv[2].strip()
data = bytes.fromhex(hex_text)
for offset in range(0, len(data), chunk_size):
    chunk = data[offset:offset + chunk_size]
    print("[" + ",".join(str(b) for b in chunk) + "]")
PY
}

tx_succeeded() {
  jq -e '
    (.effects.status.status? == "success")
    or (.effects.status? == "success")
  ' >/dev/null
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

check_tx_json() {
  local label="$1"
  local out="$2"

  if ! jq empty "${out}" >/dev/null 2>&1; then
    log "${label} did not return JSON; full output follows"
    cat "${out}" >&2
    exit 1
  fi
  if ! tx_succeeded <"${out}"; then
    log "${label} failed; full JSON follows"
    cat "${out}" >&2
    exit 1
  fi
}

sui_client_json() {
  if [[ -n "${SUI_CLIENT_CONFIG}" ]]; then
    "${SUI_BIN}" client --client.config "${SUI_CLIENT_CONFIG}" --json -q "$@"
  else
    "${SUI_BIN}" client --json -q "$@"
  fi
}

call_json() {
  local out="$1"
  local package="$2"
  local module="$3"
  local function="$4"
  shift 4

  sui_client_json call \
    --package "${package}" \
    --module "${module}" \
    --function "${function}" \
    --gas-budget "${GAS_BUDGET}" \
    "$@" >"${out}"
  check_tx_json "${module}::${function}" "${out}"
}

publish_builder() {
  local function="$1"
  local label="$2"
  local out="${OUT_DIR}/${label}.builder.json"

  log "Creating ${label} builder"
  call_json "${out}" "${VERIFIER_API_PACKAGE}" artifact_builder "${function}"

  local builder_id
  builder_id="$(created_object_id "::artifact_builder::ArtifactBuilder" <"${out}")"
  [[ -n "${builder_id}" ]] || die "could not parse ${label} builder object id from ${out}"
  printf '%s\n' "${builder_id}"
}

append_chunks() {
  local builder_id="$1"
  local artifact_hex="$2"
  local label="$3"
  local idx=0
  local chunk_json

  while IFS= read -r chunk_json; do
    [[ -n "${chunk_json}" ]] || continue
    idx=$((idx + 1))
    local out="${OUT_DIR}/${label}.append.${idx}.json"
    log "Appending ${label} chunk ${idx}"
    call_json "${out}" "${VERIFIER_API_PACKAGE}" artifact_builder append_chunk \
      --args "${builder_id}" "${chunk_json}"
  done < <(hex_chunk_json_arrays "${CHUNK_SIZE}" "${artifact_hex}")

  [[ "${idx}" -gt 0 ]] || die "${label} artifact is empty"
}

finalize_params() {
  local builder_id="$1"
  local params_hex="$2"
  local out="${OUT_DIR}/params.finalize.json"
  local digest_json

  digest_json="$(hex_digest_json_array "${params_hex}")"
  log "Finalizing params"
  call_json "${out}" "${VERIFIER_API_PACKAGE}" artifact_builder finalize_params_to_sender \
    --args "${builder_id}" "${digest_json}"

  local object_id
  object_id="$(created_object_id "::serialized_params_store::SerializedParams" <"${out}")"
  [[ -n "${object_id}" ]] || die "could not parse SerializedParams object id from ${out}"
  printf '%s\n' "${object_id}"
}

finalize_vk() {
  local vk_builder_id="$1"
  local circuit_builder_id="$2"
  local vk_hex="$3"
  local circuit_hex="$4"
  local out="${OUT_DIR}/vk.finalize.json"
  local vk_digest_json
  local circuit_digest_json

  vk_digest_json="$(hex_digest_json_array "${vk_hex}")"
  circuit_digest_json="$(hex_digest_json_array "${circuit_hex}")"
  log "Finalizing vk + circuit info"
  call_json "${out}" "${VERIFIER_API_PACKAGE}" artifact_builder finalize_vk_to_sender \
    --args \
      "${vk_builder_id}" \
      "${circuit_builder_id}" \
      "${vk_digest_json}" \
      "${circuit_digest_json}"

  local object_id
  object_id="$(created_object_id "::native_verifier::SerializedVK" <"${out}")"
  [[ -n "${object_id}" ]] || die "could not parse SerializedVK object id from ${out}"
  printf '%s\n' "${object_id}"
}

main() {
  require_bin jq
  require_bin python3
  require_bin find
  [[ -n "${VERIFIER_API_PACKAGE}" ]] || die "missing --verifier-api-package or VERIFIER_API_PACKAGE"
  [[ -d "${ARTIFACTS_DIR}" ]] || die "artifacts dir not found: ${ARTIFACTS_DIR}"
  [[ "${CHUNK_SIZE}" =~ ^[0-9]+$ ]] || die "chunk size must be an integer"
  [[ "${GAS_BUDGET}" =~ ^[0-9]+$ ]] || die "gas budget must be an integer"

  if [[ "${SUI_BIN}" == */* ]]; then
    [[ -x "${SUI_BIN}" ]] || die "Sui binary not found or not executable: ${SUI_BIN}"
  else
    require_bin "${SUI_BIN}"
  fi

  PARAMS_TXN="${PARAMS_TXN:-$(resolve_single_file "${ARTIFACTS_DIR}" '*-publish-params-native.txn' params)}"
  VK_TXN="${VK_TXN:-$(resolve_single_file "${ARTIFACTS_DIR}" '*-publish-vk-native.txn' vk)}"
  [[ -f "${PARAMS_TXN}" ]] || die "params txn not found: ${PARAMS_TXN}"
  [[ -f "${VK_TXN}" ]] || die "vk txn not found: ${VK_TXN}"

  mkdir -p "${OUT_DIR}" "$(dirname "${ENV_FILE}")"

  log "Params descriptor: ${PARAMS_TXN}"
  log "VK descriptor: ${VK_TXN}"
  log "Output dir: ${OUT_DIR}"

  local params_hex vk_hex circuit_hex
  params_hex="$(json_byte_arg_hex "${PARAMS_TXN}" 2)"
  vk_hex="$(json_byte_arg_hex "${VK_TXN}" 0)"
  circuit_hex="$(json_byte_arg_hex "${VK_TXN}" 1)"

  log "Extracted params bytes: $(( ${#params_hex} / 2 ))"
  log "Extracted vk bytes: $(( ${#vk_hex} / 2 ))"
  log "Extracted circuit-info bytes: $(( ${#circuit_hex} / 2 ))"

  local params_builder vk_builder circuit_builder
  params_builder="$(publish_builder publish_params_builder params)"
  vk_builder="$(publish_builder publish_vk_builder vk)"
  circuit_builder="$(publish_builder publish_circuit_info_builder circuit)"

  append_chunks "${params_builder}" "${params_hex}" params
  append_chunks "${vk_builder}" "${vk_hex}" vk
  append_chunks "${circuit_builder}" "${circuit_hex}" circuit

  local params_object_id vk_object_id
  params_object_id="$(finalize_params "${params_builder}" "${params_hex}")"
  vk_object_id="$(finalize_vk "${vk_builder}" "${circuit_builder}" "${vk_hex}" "${circuit_hex}")"

  cat >"${ENV_FILE}" <<EOF
export VERIFIER_API_PACKAGE=${VERIFIER_API_PACKAGE}
export PARAMS_OBJECT_ID=${params_object_id}
export VK_OBJECT_ID=${vk_object_id}
EOF

  log "SerializedParams object: ${params_object_id}"
  log "SerializedVK object: ${vk_object_id}"
  log "Wrote env file: ${ENV_FILE}"
  printf 'PARAMS_OBJECT_ID=%s\n' "${params_object_id}"
  printf 'VK_OBJECT_ID=%s\n' "${vk_object_id}"
}

main "$@"
