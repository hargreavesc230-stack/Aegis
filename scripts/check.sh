#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="${ROOT_DIR}/target/aegis-smoke"

cd "${ROOT_DIR}"

echo "Checking Rust toolchain..."
command -v cargo >/dev/null 2>&1 || { echo "cargo not found in PATH."; exit 1; }
command -v rustc >/dev/null 2>&1 || { echo "rustc not found in PATH."; exit 1; }

echo
echo "Phase 1 - Build and static checks..."
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test

echo "Running fuzz-lite smoke tests..."
cargo run -p aegis-fuzzlite -- --iters 200 --max-len 4096

echo
echo "Phase 2 - Happy-path integration..."
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}"

INPUT_FILE="${TMP_DIR}/input.bin"
META_FILE="${TMP_DIR}/meta.bin"
PACK_FILE="${TMP_DIR}/packed.aegis"
UNPACK_FILE="${TMP_DIR}/unpacked.bin"
KEY_FILE="${TMP_DIR}/test.key"
KEY_FILE_2="${TMP_DIR}/test2.key"
KEY_FILE_3="${TMP_DIR}/test3.key"
KEY_FILE_WRONG="${TMP_DIR}/wrong.key"
PUB_KEY_FILE="${TMP_DIR}/recipient.pub"
PRIV_KEY_FILE="${TMP_DIR}/recipient.priv"
PUB_KEY_FILE_2="${TMP_DIR}/recipient2.pub"
PRIV_KEY_FILE_2="${TMP_DIR}/recipient2.priv"
ENC_FILE="${TMP_DIR}/encrypted.aegis"
DEC_FILE="${TMP_DIR}/decrypted.bin"
DEC_FILE_2="${TMP_DIR}/decrypted2.bin"
DEC_FILE_3="${TMP_DIR}/decrypted3.bin"
DEC_FILE_PUB="${TMP_DIR}/decrypted_pub.bin"
DEC_META="${TMP_DIR}/decrypted_meta.bin"
WRONG_DEC_FILE="${TMP_DIR}/wrong_dec.bin"
PW_ENC_FILE="${TMP_DIR}/pw_encrypted.aegis"
PW_DEC_FILE="${TMP_DIR}/pw_decrypted.bin"
ROTATED_FILE="${TMP_DIR}/rotated.aegis"

printf "mock-data" > "${INPUT_FILE}"
printf "mock-meta" > "${META_FILE}"

cargo run -p aegis-cli -- pack "${INPUT_FILE}" "${PACK_FILE}" --metadata "${META_FILE}"
cargo run -p aegis-cli -- inspect "${PACK_FILE}"
cargo run -p aegis-cli -- unpack "${PACK_FILE}" "${UNPACK_FILE}"
cmp "${INPUT_FILE}" "${UNPACK_FILE}"

echo "Generating key files..."
cargo run -p aegis-cli -- keygen "${KEY_FILE}"
cargo run -p aegis-cli -- keygen "${KEY_FILE_2}"
cargo run -p aegis-cli -- keygen "${KEY_FILE_3}"

echo "Generating public/private keypairs..."
cargo run -p aegis-cli -- keygen --public "${PUB_KEY_FILE}" --private "${PRIV_KEY_FILE}"
cargo run -p aegis-cli -- keygen --public "${PUB_KEY_FILE_2}" --private "${PRIV_KEY_FILE_2}"

echo "Encrypting payload (multi-recipient + metadata)..."
AEGIS_PASSWORD=mock-pass-123 AEGIS_PASSWORD_CONFIRM=mock-pass-123 \
  cargo run -p aegis-cli -- enc "${INPUT_FILE}" "${ENC_FILE}" --metadata "${META_FILE}" \
  --recipient-key "${KEY_FILE}" --recipient-key "${KEY_FILE_2}" --recipient-password \
  --recipient-pubkey "${PUB_KEY_FILE}" --allow-mixed-recipients

echo "Decrypting payload (recipient 1)..."
cargo run -p aegis-cli -- dec "${ENC_FILE}" "${DEC_FILE}" --recipient-key "${KEY_FILE}" \
  --metadata "${DEC_META}"
cmp "${INPUT_FILE}" "${DEC_FILE}"
cmp "${META_FILE}" "${DEC_META}"

echo "Verifying container..."
cargo run -p aegis-cli -- verify "${ENC_FILE}" --recipient-key "${KEY_FILE}"

echo "Decrypting payload (recipient 2)..."
cargo run -p aegis-cli -- dec "${ENC_FILE}" "${DEC_FILE_2}" --recipient-key "${KEY_FILE_2}"
cmp "${INPUT_FILE}" "${DEC_FILE_2}"

echo "Decrypting payload (password recipient)..."
AEGIS_PASSWORD=mock-pass-123 AEGIS_PASSWORD_CONFIRM=mock-pass-123 \
  cargo run -p aegis-cli -- dec "${ENC_FILE}" "${DEC_FILE_3}" --recipient-password
cmp "${INPUT_FILE}" "${DEC_FILE_3}"

echo "Decrypting payload (public key recipient)..."
cargo run -p aegis-cli -- dec "${ENC_FILE}" "${DEC_FILE_PUB}" --private-key "${PRIV_KEY_FILE}"
cmp "${INPUT_FILE}" "${DEC_FILE_PUB}"

echo "Listing recipients..."
cargo run -p aegis-cli -- list-recipients "${ENC_FILE}"

echo "Rotating recipients..."
cargo run -p aegis-cli -- rotate "${ENC_FILE}" --output "${ROTATED_FILE}" \
  --auth-key "${KEY_FILE_2}" --add-recipient-key "${KEY_FILE_3}" \
  --add-recipient-pubkey "${PUB_KEY_FILE_2}" --remove-recipient 1 --allow-mixed-recipients

echo "Verifying removed recipient fails..."
set +e
cargo run -p aegis-cli -- dec "${ROTATED_FILE}" "${WRONG_DEC_FILE}" --recipient-key "${KEY_FILE}"
CODE=$?
set -e
if [[ "${CODE}" -ne 5 ]]; then
  echo "expected crypto error exit code 5, got ${CODE}"
  exit 1
fi
rm -f "${WRONG_DEC_FILE}" "${WRONG_DEC_FILE%.bin}.tmp"

echo "Verifying new recipient works..."
rm -f "${DEC_FILE}"
cargo run -p aegis-cli -- dec "${ROTATED_FILE}" "${DEC_FILE}" --recipient-key "${KEY_FILE_3}"
cmp "${INPUT_FILE}" "${DEC_FILE}"

echo "Verifying rotated public key recipient works..."
rm -f "${DEC_FILE_PUB}"
cargo run -p aegis-cli -- dec "${ROTATED_FILE}" "${DEC_FILE_PUB}" --private-key "${PRIV_KEY_FILE_2}"
cmp "${INPUT_FILE}" "${DEC_FILE_PUB}"

echo "Verifying existing recipient works..."
rm -f "${DEC_FILE_2}"
cargo run -p aegis-cli -- dec "${ROTATED_FILE}" "${DEC_FILE_2}" --recipient-key "${KEY_FILE_2}"
cmp "${INPUT_FILE}" "${DEC_FILE_2}"

echo "Verifying password recipient works after rotation..."
AEGIS_PASSWORD=mock-pass-123 AEGIS_PASSWORD_CONFIRM=mock-pass-123 \
  cargo run -p aegis-cli -- dec "${ROTATED_FILE}" "${DEC_FILE_3}" --recipient-password
cmp "${INPUT_FILE}" "${DEC_FILE_3}"

echo "Testing password-only encryption..."
AEGIS_PASSWORD=mock-pass-123 AEGIS_PASSWORD_CONFIRM=mock-pass-123 \
  cargo run -p aegis-cli -- enc "${INPUT_FILE}" "${PW_ENC_FILE}" --recipient-password
AEGIS_PASSWORD=mock-pass-123 AEGIS_PASSWORD_CONFIRM=mock-pass-123 \
  cargo run -p aegis-cli -- dec "${PW_ENC_FILE}" "${PW_DEC_FILE}" --recipient-password
cmp "${INPUT_FILE}" "${PW_DEC_FILE}"

echo
echo "Phase 3 - Cleanup verification..."
if ls "${TMP_DIR}"/*.tmp >/dev/null 2>&1; then
  echo "unexpected temp files in ${TMP_DIR}"
  exit 1
fi

rm -rf "${TMP_DIR}"
echo
echo "All checks passed."
