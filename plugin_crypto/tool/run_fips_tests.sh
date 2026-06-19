#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIPS_DIR="${PLUGIN_CRYPTO_FIPS_DIR:-$ROOT/native/linux/x86_64_fips}"
PROVIDER_DIR="$FIPS_DIR/providers"

if [[ ! -f "$FIPS_DIR/libcrypto.so.4" ]]; then
  echo "FIPS native library unavailable: $FIPS_DIR/libcrypto.so.4" >&2
  exit 77
fi
if [[ ! -f "$PROVIDER_DIR/openssl.cnf" ]]; then
  echo "FIPS OpenSSL configuration unavailable: $PROVIDER_DIR/openssl.cnf" >&2
  exit 77
fi

export PLUGIN_CRYPTO_NATIVE_DIR="$FIPS_DIR"
export LD_LIBRARY_PATH="$FIPS_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="$PROVIDER_DIR/openssl.cnf"
export OPENSSL_MODULES="$PROVIDER_DIR"

cd "$ROOT"
flutter test test/zone22_pq_key_creation_flow_test.dart --reporter expanded
flutter test test/zone35_fips186_4_validation_test.dart --reporter expanded
