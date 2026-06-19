#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT/build/test_native"
mkdir -p "$OUTPUT_DIR"

cc -shared -fPIC -O2 \
  "$ROOT/test/native/zeroization_shim.c" \
  -o "$OUTPUT_DIR/libplugin_crypto_test_shim.so"

echo "$OUTPUT_DIR/libplugin_crypto_test_shim.so"
