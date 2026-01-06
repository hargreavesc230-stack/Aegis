#!/usr/bin/env bash
set -euo pipefail

# Prereqs: Rust toolchain (cargo) and sha256sum or shasum for hashing.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH." >&2
  exit 1
fi

os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch_name="$(uname -m)"
case "${arch_name}" in
  x86_64) arch_name="x86_64" ;;
  aarch64) arch_name="arm64" ;;
  arm64) arch_name="arm64" ;;
esac

out_dir="${DIST_DIR}/${os_name}-${arch_name}"

hash_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" > "${file}.sha256"
  else
    shasum -a 256 "$file" > "${file}.sha256"
  fi
}

echo "Cleaning prior outputs..."
rm -rf "${DIST_DIR}"
cargo clean

echo "Building release binaries..."
cargo build --release --locked -p aegis-cli -p aegis-fuzzlite

mkdir -p "${out_dir}"
cp "${ROOT_DIR}/target/release/aegis-cli" "${out_dir}/aegis-cli-${os_name}-${arch_name}"
cp "${ROOT_DIR}/target/release/aegis-fuzzlite" "${out_dir}/aegis-fuzzlite-${os_name}-${arch_name}"

hash_file "${out_dir}/aegis-cli-${os_name}-${arch_name}"
hash_file "${out_dir}/aegis-fuzzlite-${os_name}-${arch_name}"

echo "Cleaning build artifacts..."
cargo clean

echo
echo "Release artifacts written to ${out_dir}"
