#!/usr/bin/env bash
set -euo pipefail

# Make sure the local network is running and the specified profile is configured before running this script.
# With this script, all modules will be published under the default address of the specified profile.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${PROFILE:?set PROFILE}"

if ! command -v aptos >/dev/null 2>&1; then
  echo "Missing aptos CLI in PATH"
  echo "Install it or add it to PATH before running this script."
  exit 1
fi

APTOS_ARGS=(--profile "${PROFILE}")
CONFIG_PATH="${SCRIPT_DIR}/.aptos/config.yaml"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Missing Aptos config: ${CONFIG_PATH}"
  echo "Run: aptos init --profile ${PROFILE} --network local"
  exit 1
fi
if ! awk -v profile="${PROFILE}:" '$1 == profile { found = 1 } END { exit !found }' "${CONFIG_PATH}"; then
  echo "Profile '${PROFILE}' not found in ${CONFIG_PATH}"
  echo "Run: aptos init --profile ${PROFILE} --network local"
  exit 1
fi

cd "${SCRIPT_DIR}"

echo "==> publish move packages"
(cd "${SCRIPT_DIR}/packages/common" && aptos move publish "${APTOS_ARGS[@]}" --named-addresses halo2_common="${PROFILE}" --experiments spec-check=off)
(cd "${SCRIPT_DIR}/packages/verifier" && aptos move publish "${APTOS_ARGS[@]}" --named-addresses halo2_common="${PROFILE}",halo2_verifier="${PROFILE}" --experiments spec-check=off)
(cd "${SCRIPT_DIR}/packages/api" && aptos move publish "${APTOS_ARGS[@]}" --named-addresses halo2_common="${PROFILE}",halo2_verifier="${PROFILE}",verifier_api="${PROFILE}" --experiments spec-check=off)

echo "done"
