#!/usr/bin/env bash
# =============================================================================
# PluginCrypto — One-Click Reproducibility Script
# =============================================================================
#
# Reproduces ALL test results documented in the technical evidence report.
# Runs every test suite in the correct order with the correct environment.
#
# Phases:
#   1. Linux unit tests       (plugin_crypto/)
#   2. Metrics pipeline        (--tags metrics --run-skipped)
#   3. Linux integration tests (tcc_test_app/integration_test/)
#   4. Android integration     (8 test files on connected device)
#   5. FIPS/PQ tests           (tool/run_fips_tests.sh)
#   6. Coverage analysis       (lcov summary if available)
#
# Usage:
#   ./tool/reproduce_all.sh                  # full reproducibility run
#   ./tool/reproduce_all.sh --skip-android    # skip Android phase
#   ./tool/reproduce_all.sh --help            # show this help
#   ./tool/reproduce_all.sh -h               # show this help
#
# Output:
#   Terminal: color-coded progress (green=pass, red=fail, yellow=skip)
#   File:     tool/reports/reproducibility_report_YYYYMMDD_HHMMSS.md
#
# Environment (auto-exported):
#   LD_LIBRARY_PATH   -> plugin_crypto/native/linux/x86_64
#   OPENSSL_CONF      -> plugin_crypto/native/linux/x86_64_fips/providers/openssl.cnf
#   TCC_METRICS_OUTPUT -> plugin_crypto/tcc_metrics_report.json
# =============================================================================

set -euo pipefail

# ── Color definitions ───────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  DIM='\033[2m'
  NC='\033[0m' # No Color
else
  GREEN='' RED='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
fi

# ── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_CRYPTO="$PROJECT_ROOT/plugin_crypto"
TCC_TEST_APP="$PROJECT_ROOT/tcc_test_app"
NATIVE_LINUX="$PLUGIN_CRYPTO/native/linux/x86_64"
NATIVE_FIPS="$PLUGIN_CRYPTO/native/linux/x86_64_fips"
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$REPORT_DIR/reproducibility_report_$TIMESTAMP.md"

# ── Global state ────────────────────────────────────────────────────────────
SKIP_ANDROID=false
START_EPOCH=$(date +%s)
PHASE_TIMES=()
PHASE_RESULTS=()
ANDROID_DEVICE=""
ANDROID_FILES=()

# ── Help ────────────────────────────────────────────────────────────────────
show_help() {
  # Extract the top comment block: from line 2 to the closing "# =====" before "set -euo"
  awk 'NR==1{next} /^set -euo pipefail/{exit} {sub(/^# ?/,""); print}' "$0"
  exit 0
}

# ── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-android)
      SKIP_ANDROID=true
      shift
      ;;
    -h|--help)
      show_help
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      echo "Use --help for usage information."
      exit 1
      ;;
  esac
done

# ── Ensure report directory exists ──────────────────────────────────────────
mkdir -p "$REPORT_DIR"

# ═════════════════════════════════════════════════════════════════════════════
# Helper functions
# ═════════════════════════════════════════════════════════════════════════════

# Print a color-coded status line.
# Usage: status <label> <result>
#   result: PASS | FAIL | SKIP | WARN | INFO
status() {
  local label="$1" result="$2"
  case "$result" in
    PASS) printf "  ${GREEN}[PASS]${NC} %s\n" "$label" ;;
    FAIL) printf "  ${RED}[FAIL]${NC} %s\n" "$label" ;;
    SKIP) printf "  ${YELLOW}[SKIP]${NC} %s\n" "$label" ;;
    WARN) printf "  ${YELLOW}[WARN]${NC} %s\n" "$label" ;;
    INFO) printf "  ${CYAN}[INFO]${NC} %s\n" "$label" ;;
    *)    printf "  %s\n" "$label" ;;
  esac
}

# Print a phase header.
phase_header() {
  local num="$1" title="$2"
  echo ""
  echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${CYAN}  Phase $num: $title${NC}"
  echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
}

# Parse flutter test output to extract pass/fail/skip counts.
# Handles both compact and expanded reporters.
# Compact reporter uses \r (carriage return) to overwrite status lines;
# we split on \r first to get the final status update.
parse_test_summary() {
  local logfile="$1"
  local -n _passed=$2
  local -n _skipped=$3
  local -n _failed=$4
  _passed=0; _skipped=0; _failed=0

  # Replace \r with newlines so each status update is on its own line,
  # then find the last line matching the summary pattern.
  local summary
  summary="$(tr '\r' '\n' < "$logfile" | grep -E '[0-9][0-9]:[0-9][0-9] \+[0-9]+.*~[0-9]+.*\-[0-9]+' | tail -1 || true)"
  if [[ -n "$summary" ]]; then
    _passed="$(echo "$summary" | sed -n 's/.*+\([0-9]\{1,\}\).*/\1/p' | head -1)"
    _skipped="$(echo "$summary" | sed -n 's/.*~\([0-9]\{1,\}\).*/\1/p' | head -1)"
    _failed="$(echo "$summary" | sed -n 's/.*-\([0-9]\{1,\}\).*/\1/p' | head -1)"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Prerequisite checks
# ═════════════════════════════════════════════════════════════════════════════

check_prerequisites() {
  echo -e "${BOLD}=== Checking prerequisites ===${NC}"
  echo ""

  local all_ok=true

  # Flutter
  if command -v flutter &>/dev/null; then
    local fver
    fver="$(flutter --version 2>/dev/null | head -1 || echo "unknown")"
    status "flutter: $fver" PASS
  else
    status "flutter: not found in PATH" FAIL
    all_ok=false
  fi

  # GCC (needed for native FFI compilation)
  if command -v gcc &>/dev/null; then
    local gver
    gver="$(gcc --version 2>/dev/null | head -1 || echo "unknown")"
    status "gcc: $gver" PASS
  else
    status "gcc: not found" WARN
  fi

  # lcov (optional)
  if command -v lcov &>/dev/null; then
    local lver
    lver="$(lcov --version 2>/dev/null | head -1 || echo "unknown")"
    status "lcov: $lver" PASS
  else
    status "lcov: not found (coverage summary will be skipped)" WARN
  fi

  # Native libraries
  if [[ -f "$NATIVE_LINUX/libcrypto.so.4" ]]; then
    status "OpenSSL libcrypto.so.4: $NATIVE_LINUX" PASS
  elif [[ -f "$NATIVE_LINUX/libcrypto.so" ]]; then
    status "OpenSSL libcrypto.so: $NATIVE_LINUX" PASS
  else
    status "OpenSSL libraries: not found at $NATIVE_LINUX" FAIL
    all_ok=false
  fi

  # FIPS directory
  if [[ -f "$NATIVE_FIPS/libcrypto.so.4" && -f "$NATIVE_FIPS/openssl" ]]; then
    status "FIPS directory: $NATIVE_FIPS" PASS
  else
    status "FIPS directory: not found or incomplete at $NATIVE_FIPS (Phase 5 will fail)" WARN
  fi

  # LD_LIBRARY_PATH check (informational)
  if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    status "LD_LIBRARY_PATH is set: $LD_LIBRARY_PATH" INFO
  else
    status "LD_LIBRARY_PATH is empty (will be set automatically)" INFO
  fi

  # ADB (for Android phase)
  if ! $SKIP_ANDROID; then
    if command -v adb &>/dev/null; then
      local aver
      aver="$(adb version 2>/dev/null | head -1 || echo "unknown")"
      status "adb: $aver" PASS
    else
      # Check for Windows ADB via /mnt/c/ path
      if [[ -f "/mnt/c/Users/hiper/AppData/Local/Android/Sdk/platform-tools/adb.exe" ]]; then
        status "adb: not in PATH, but found Windows ADB at /mnt/c/..." WARN
        status "   Add to PATH or use --skip-android" INFO
      else
        status "adb: not found (Android phase will require --skip-android)" WARN
        SKIP_ANDROID=true
      fi
    fi
  fi

  echo ""
  if ! $all_ok; then
    echo -e "${RED}Prerequisite check FAILED. Fix the issues above before running.${NC}"
    exit 1
  fi
  echo -e "${GREEN}All required prerequisites satisfied.${NC}"
}

# ═════════════════════════════════════════════════════════════════════════════
# Android device detection
# ═════════════════════════════════════════════════════════════════════════════

detect_android_device() {
  if $SKIP_ANDROID; then
    return 1
  fi

  echo -e "${BOLD}=== Android device detection ===${NC}"
  echo ""

  local adb_bin="adb"
  if ! command -v adb &>/dev/null; then
    # Try Windows ADB path under WSL
    if [[ -f "/mnt/c/Users/hiper/AppData/Local/Android/Sdk/platform-tools/adb.exe" ]]; then
      adb_bin="/mnt/c/Users/hiper/AppData/Local/Android/Sdk/platform-tools/adb.exe"
      status "Using Windows ADB: $adb_bin" INFO
    else
      status "adb not found — cannot run Android phase" WARN
      SKIP_ANDROID=true
      return 1
    fi
  fi

  # List connected devices
  local devices
  devices="$("$adb_bin" devices 2>/dev/null || true)"
  local device_count
  device_count="$(echo "$devices" | grep -v '^$' | grep -v 'List of devices' | grep 'device$' | wc -l)"

  if [[ "$device_count" -eq 0 ]]; then
    status "No Android device/emulator connected" WARN
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  1. Connect a device via USB and enable USB debugging"
    echo "  2. Start an Android emulator (AVD)"
    echo "  3. Re-run with --skip-android to skip this phase"
    echo ""
    echo -n "Skip Android phase and continue? [Y/n]: "
    read -r answer
    if [[ "$answer" =~ ^[Nn] ]]; then
      echo "Aborting."
      exit 1
    fi
    SKIP_ANDROID=true
    return 1
  fi

  ANDROID_DEVICE="$(echo "$devices" | grep 'device$' | head -1 | awk '{print $1}')"
  echo -e "${GREEN}Android device detected: $ANDROID_DEVICE${NC}"

  # Get device info
  local model brand android_ver
  model="$("$adb_bin" -s "$ANDROID_DEVICE" shell getprop ro.product.model 2>/dev/null | tr -d '\r' || echo "unknown")"
  brand="$("$adb_bin" -s "$ANDROID_DEVICE" shell getprop ro.product.brand 2>/dev/null | tr -d '\r' || echo "unknown")"
  android_ver="$("$adb_bin" -s "$ANDROID_DEVICE" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r' || echo "unknown")"
  local abi
  abi="$("$adb_bin" -s "$ANDROID_DEVICE" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' || echo "unknown")"

  status "Device: $brand $model (Android $android_ver, $abi)" INFO
  echo ""
  return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Environment setup
# ═════════════════════════════════════════════════════════════════════════════

setup_environment() {
  echo -e "${BOLD}=== Environment setup ===${NC}"
  echo ""

  export LD_LIBRARY_PATH="${NATIVE_LINUX}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  status "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" INFO

  export TCC_METRICS_OUTPUT="$PLUGIN_CRYPTO/tcc_metrics_report.json"
  status "TCC_METRICS_OUTPUT=$TCC_METRICS_OUTPUT" INFO

  # OPENSSL_CONF for FIPS phase — set here so it's available when needed
  if [[ -f "$NATIVE_FIPS/providers/openssl.cnf" ]]; then
    export OPENSSL_CONF="$NATIVE_FIPS/providers/openssl.cnf"
    status "OPENSSL_CONF=$OPENSSL_CONF" INFO
  else
    status "OPENSSL_CONF: FIPS openssl.cnf not found (Phase 5 may fail)" WARN
  fi

  echo ""

  # System info for the report
  UNAME_A="$(uname -a 2>/dev/null || echo "unknown")"
  HOSTNAME="$(hostname 2>/dev/null || echo "unknown")"
  KERNEL="$(uname -r 2>/dev/null || echo "unknown")"
  ARCH="$(uname -m 2>/dev/null || echo "unknown")"
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1: Linux unit tests
# ═════════════════════════════════════════════════════════════════════════════

phase1_linux_unit_tests() {
  phase_header 1 "Linux Unit Tests (plugin_crypto/)"
  echo "Running standard test suite with compact reporter..."
  echo ""

  local log="$REPORT_DIR/phase1_unit_${TIMESTAMP}.log"
  local t0
  t0=$(date +%s%N)

  set +e
  cd "$PLUGIN_CRYPTO"
  flutter test --reporter compact > "$log" 2>&1
  local rc=$?
  set -e

  local t1 elapsed_ms
  t1=$(date +%s%N)
  elapsed_ms=$(( (t1 - t0) / 1000000 ))
  local elapsed_str
  if (( elapsed_ms >= 60000 )); then
    elapsed_str="$(( elapsed_ms / 60000 ))m $(( (elapsed_ms % 60000) / 1000 ))s"
  elif (( elapsed_ms >= 1000 )); then
    elapsed_str="$(( elapsed_ms / 1000 )).$(( (elapsed_ms % 1000) / 100 ))s"
  else
    elapsed_str="${elapsed_ms}ms"
  fi

  PHASE_TIMES+=("$elapsed_str")

  local passed skipped failed
  parse_test_summary "$log" passed skipped failed
  PHASE1_PASSED="$passed"
  PHASE1_SKIPPED="$skipped"
  PHASE1_FAILED="$failed"
  PHASE1_TOTAL=$(( passed + skipped + failed ))
  PHASE1_TIME="$elapsed_str"

  if [[ "$rc" -eq 0 ]]; then
    echo -e "${GREEN}Phase 1: PASS${NC}  (+$passed ~$skipped -$failed in $elapsed_str)"
    PHASE_RESULTS+=("PASS")
    PHASE1_RC=0
  else
    echo -e "${RED}Phase 1: FAIL${NC}  (+$passed ~$skipped -$failed in $elapsed_str, exit=$rc)"
    PHASE_RESULTS+=("FAIL")
    PHASE1_RC=$rc
  fi

  return $rc
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2: Metrics pipeline
# ═════════════════════════════════════════════════════════════════════════════

phase2_metrics() {
  phase_header 2 "Metrics Pipeline"

  echo "Running metrics-tagged tests with --run-skipped..."
  echo "TCC_METRICS_OUTPUT=$TCC_METRICS_OUTPUT"
  echo ""

  local log="$REPORT_DIR/phase2_metrics_${TIMESTAMP}.log"
  local t0
  t0=$(date +%s%N)

  set +e
  cd "$PLUGIN_CRYPTO"
  flutter test --reporter compact --tags metrics --run-skipped > "$log" 2>&1
  local rc=$?
  set -e

  local t1 elapsed_ms
  t1=$(date +%s%N)
  elapsed_ms=$(( (t1 - t0) / 1000000 ))
  local elapsed_str
  if (( elapsed_ms >= 60000 )); then
    elapsed_str="$(( elapsed_ms / 60000 ))m $(( (elapsed_ms % 60000) / 1000 ))s"
  elif (( elapsed_ms >= 1000 )); then
    elapsed_str="$(( elapsed_ms / 1000 )).$(( (elapsed_ms % 1000) / 100 ))s"
  else
    elapsed_str="${elapsed_ms}ms"
  fi

  PHASE_TIMES+=("$elapsed_str")

  local passed skipped failed
  parse_test_summary "$log" passed skipped failed
  PHASE2_PASSED="$passed"
  PHASE2_SKIPPED="$skipped"
  PHASE2_FAILED="$failed"
  PHASE2_TOTAL=$(( passed + skipped + failed ))
  PHASE2_TIME="$elapsed_str"

  if [[ "$rc" -eq 0 ]]; then
    echo -e "${GREEN}Phase 2: PASS${NC}  (+$passed ~$skipped -$failed in $elapsed_str)"
    PHASE_RESULTS+=("PASS")
    PHASE2_RC=0
  else
    echo -e "${RED}Phase 2: FAIL${NC}  (+$passed ~$skipped -$failed in $elapsed_str, exit=$rc)"
    PHASE_RESULTS+=("FAIL")
    PHASE2_RC=$rc
  fi

  # Validate JSON output
  if [[ -f "$TCC_METRICS_OUTPUT" ]]; then
    if command -v python3 &>/dev/null; then
      if python3 -m json.tool "$TCC_METRICS_OUTPUT" > /dev/null 2>&1; then
        echo -e "${GREEN}  Metrics JSON: valid${NC}"
      else
        echo -e "${RED}  Metrics JSON: INVALID${NC}"
      fi
    fi
  else
    echo -e "${YELLOW}  Metrics JSON: not found (TCC_METRICS_OUTPUT path may be incorrect)${NC}"
  fi

  return $rc
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3: Linux integration tests
# ═════════════════════════════════════════════════════════════════════════════

phase3_linux_integration() {
  phase_header 3 "Linux Integration Tests (tcc_test_app/)"

  echo "Running integration tests on Linux host..."
  echo ""

  local log="$REPORT_DIR/phase3_integration_${TIMESTAMP}.log"
  local t0
  t0=$(date +%s%N)

  set +e
  cd "$TCC_TEST_APP"
  flutter test integration_test/ --reporter compact > "$log" 2>&1
  local rc=$?
  set -e

  local t1 elapsed_ms
  t1=$(date +%s%N)
  elapsed_ms=$(( (t1 - t0) / 1000000 ))
  local elapsed_str
  if (( elapsed_ms >= 60000 )); then
    elapsed_str="$(( elapsed_ms / 60000 ))m $(( (elapsed_ms % 60000) / 1000 ))s"
  elif (( elapsed_ms >= 1000 )); then
    elapsed_str="$(( elapsed_ms / 1000 )).$(( (elapsed_ms % 1000) / 100 ))s"
  else
    elapsed_str="${elapsed_ms}ms"
  fi

  PHASE_TIMES+=("$elapsed_str")

  local passed skipped failed
  parse_test_summary "$log" passed skipped failed
  PHASE3_PASSED="$passed"
  PHASE3_SKIPPED="$skipped"
  PHASE3_FAILED="$failed"
  PHASE3_TOTAL=$(( passed + skipped + failed ))
  PHASE3_TIME="$elapsed_str"

  if [[ "$rc" -eq 0 ]]; then
    echo -e "${GREEN}Phase 3: PASS${NC}  (+$passed ~$skipped -$failed in $elapsed_str)"
    PHASE_RESULTS+=("PASS")
    PHASE3_RC=0
  else
    echo -e "${RED}Phase 3: FAIL${NC}  (+$passed ~$skipped -$failed in $elapsed_str, exit=$rc)"
    PHASE_RESULTS+=("FAIL")
    PHASE3_RC=$rc
  fi

  return $rc
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 4: Android integration tests
# ═════════════════════════════════════════════════════════════════════════════

phase4_android_integration() {
  phase_header 4 "Android Integration Tests"

  if $SKIP_ANDROID; then
    echo -e "${YELLOW}Android phase skipped (--skip-android or no device).${NC}"
    PHASE_TIMES+=("skipped")
    PHASE_RESULTS+=("SKIP")
    PHASE4_TOTAL=0
    PHASE4_PASSED=0
    PHASE4_SKIPPED=0
    PHASE4_FAILED=0
    PHASE4_TIME="skipped"
    return 0
  fi

  # Android integration test files (from technical evidence report Table 5.3.1)
  local test_files=(
    "crypto_integration_test.dart"
    "crypto_flows_integration_test.dart"
    "crypto_e2e_adversarial_test.dart"
    "crypto_e2e_hash_pipeline_test.dart"
    "crypto_e2e_pipeline_test.dart"
    "crypto_e2e_pki_pipeline_test.dart"
    "crypto_e2e_pq_test.dart"
    "crypto_e2e_pq_fips_test.dart"
  )

  local total_passed=0 total_skipped=0 total_failed=0
  local t0
  t0=$(date +%s%N)
  local all_passed=true

  for test_file in "${test_files[@]}"; do
    local base_name="${test_file%.dart}"
    echo -e "${CYAN}--- Android: $test_file ---${NC}"

    local log="$REPORT_DIR/phase4_android_${base_name}_${TIMESTAMP}.log"
    local ft0
    ft0=$(date +%s%N)

    set +e
    cd "$TCC_TEST_APP"
    flutter test "integration_test/$test_file" --reporter compact > "$log" 2>&1
    local frc=$?
    set -e

    local ft1 fms
    ft1=$(date +%s%N)
    fms=$(( (ft1 - ft0) / 1000000 ))

    local fpassed fskipped ffailed
    parse_test_summary "$log" fpassed fskipped ffailed
    total_passed=$(( total_passed + fpassed ))
    total_skipped=$(( total_skipped + fskipped ))
    total_failed=$(( total_failed + ffailed ))

    if [[ "$frc" -eq 0 ]]; then
      echo -e "  ${GREEN}PASS${NC}  +$fpassed ~$fskipped -$ffailed  ($(( fms / 1000 ))s)"
    else
      echo -e "  ${RED}FAIL${NC}  +$fpassed ~$fskipped -$ffailed  ($(( fms / 1000 ))s, exit=$frc)"
      all_passed=false
    fi
  done

  local t1 elapsed_ms
  t1=$(date +%s%N)
  elapsed_ms=$(( (t1 - t0) / 1000000 ))
  local elapsed_str
  if (( elapsed_ms >= 60000 )); then
    elapsed_str="$(( elapsed_ms / 60000 ))m $(( (elapsed_ms % 60000) / 1000 ))s"
  elif (( elapsed_ms >= 1000 )); then
    elapsed_str="$(( elapsed_ms / 1000 )).$(( (elapsed_ms % 1000) / 100 ))s"
  else
    elapsed_str="${elapsed_ms}ms"
  fi

  PHASE_TIMES+=("$elapsed_str")
  PHASE4_TOTAL=$(( total_passed + total_skipped + total_failed ))
  PHASE4_PASSED="$total_passed"
  PHASE4_SKIPPED="$total_skipped"
  PHASE4_FAILED="$total_failed"
  PHASE4_TIME="$elapsed_str"

  if $all_passed; then
    echo ""
    echo -e "${GREEN}Phase 4: PASS${NC}  (+$total_passed ~$total_skipped -$total_failed across ${#test_files[@]} files in $elapsed_str)"
    PHASE_RESULTS+=("PASS")
    PHASE4_RC=0
  else
    echo ""
    echo -e "${RED}Phase 4: FAIL${NC}  (+$total_passed ~$total_skipped -$total_failed across ${#test_files[@]} files in $elapsed_str)"
    PHASE_RESULTS+=("FAIL")
    PHASE4_RC=1
  fi

  return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 5: FIPS/PQ tests
# ═════════════════════════════════════════════════════════════════════════════

phase5_fips_pq() {
  phase_header 5 "FIPS/PQ Tests"

  local fips_script="$PLUGIN_CRYPTO/tool/run_fips_tests.sh"

  if [[ ! -f "$fips_script" ]]; then
    echo -e "${RED}FIPS test script not found: $fips_script${NC}"
    PHASE_TIMES+=("skipped")
    PHASE_RESULTS+=("SKIP")
    PHASE5_TOTAL=0
    PHASE5_PASSED=0
    PHASE5_SKIPPED=0
    PHASE5_FAILED=0
    PHASE5_TIME="skipped"
    return 1
  fi

  if [[ ! -f "$NATIVE_FIPS/libcrypto.so.4" ]]; then
    echo -e "${YELLOW}FIPS libraries not found at $NATIVE_FIPS — skipping FIPS/PQ phase.${NC}"
    PHASE_TIMES+=("skipped")
    PHASE_RESULTS+=("SKIP")
    PHASE5_TOTAL=0
    PHASE5_PASSED=0
    PHASE5_SKIPPED=0
    PHASE5_FAILED=0
    PHASE5_TIME="skipped"
    return 0
  fi

  echo "Running FIPS/PQ tests via run_fips_tests.sh..."
  echo "FIPS_DIR=$NATIVE_FIPS"
  echo ""

  local log="$REPORT_DIR/phase5_fips_${TIMESTAMP}.log"
  local t0
  t0=$(date +%s%N)

  # The run_fips_tests.sh script itself handles environment setup.
  # We call it with --zone22 and --zone35 (the default with no args).
  set +e
  cd "$PLUGIN_CRYPTO"
  bash "$fips_script" > "$log" 2>&1
  local rc=$?
  set -e

  local t1 elapsed_ms
  t1=$(date +%s%N)
  elapsed_ms=$(( (t1 - t0) / 1000000 ))
  local elapsed_str
  if (( elapsed_ms >= 60000 )); then
    elapsed_str="$(( elapsed_ms / 60000 ))m $(( (elapsed_ms % 60000) / 1000 ))s"
  elif (( elapsed_ms >= 1000 )); then
    elapsed_str="$(( elapsed_ms / 1000 )).$(( (elapsed_ms % 1000) / 100 ))s"
  else
    elapsed_str="${elapsed_ms}ms"
  fi

  PHASE_TIMES+=("$elapsed_str")

  # Parse the expanded reporter output (run_fips_tests.sh uses default reporter)
  local passed skipped failed
  parse_test_summary "$log" passed skipped failed

  # The FIPS script runs two separate flutter test invocations; aggregate them.
  # If the first parse yields zero, try to extract from all summary lines.
  if [[ "$passed" -eq 0 && "$skipped" -eq 0 && "$failed" -eq 0 ]]; then
    # Aggregate all summary lines (handle both compact and expanded reporters)
    passed=0; skipped=0; failed=0
    local p s f
    while IFS= read -r line; do
      p="$(echo "$line" | sed -n 's/.*+\([0-9]\{1,\}\).*/\1/p' | head -1)"
      s="$(echo "$line" | sed -n 's/.*~\([0-9]\{1,\}\).*/\1/p' | head -1)"
      f="$(echo "$line" | sed -n 's/.*-\([0-9]\{1,\}\).*/\1/p' | head -1)"
      passed=$(( passed + ${p:-0} ))
      skipped=$(( skipped + ${s:-0} ))
      failed=$(( failed + ${f:-0} ))
    done < <(tr '\r' '\n' < "$log" | grep -E '[0-9][0-9]:[0-9][0-9] \+[0-9]+' || true)
  fi

  PHASE5_PASSED="$passed"
  PHASE5_SKIPPED="$skipped"
  PHASE5_FAILED="$failed"
  PHASE5_TOTAL=$(( passed + skipped + failed ))
  PHASE5_TIME="$elapsed_str"

  if [[ "$rc" -eq 0 ]]; then
    echo -e "${GREEN}Phase 5: PASS${NC}  (+$passed ~$skipped -$failed in $elapsed_str)"
    PHASE_RESULTS+=("PASS")
    PHASE5_RC=0
  else
    echo -e "${RED}Phase 5: FAIL${NC}  (+$passed ~$skipped -$failed in $elapsed_str, exit=$rc)"
    PHASE_RESULTS+=("FAIL")
    PHASE5_RC=$rc
  fi

  return $rc
}

# ═════════════════════════════════════════════════════════════════════════════
# Phase 6: Coverage analysis
# ═════════════════════════════════════════════════════════════════════════════

phase6_coverage() {
  phase_header 6 "Coverage Analysis"

  if ! command -v lcov &>/dev/null; then
    echo -e "${YELLOW}lcov not available — skipping coverage phase.${NC}"
    echo "Install lcov with: sudo apt install lcov"
    PHASE_TIMES+=("skipped")
    PHASE_RESULTS+=("SKIP")
    PHASE6_TIME="skipped"
    return 0
  fi

  echo "Generating coverage data..."
  echo ""

  local log="$REPORT_DIR/phase6_coverage_${TIMESTAMP}.log"
  local t0
  t0=$(date +%s%N)

  set +e
  cd "$PLUGIN_CRYPTO"
  flutter test --coverage > "$log" 2>&1
  local rc=$?
  set -e

  local t1 elapsed_ms
  t1=$(date +%s%N)
  elapsed_ms=$(( (t1 - t0) / 1000000 ))
  local elapsed_str
  if (( elapsed_ms >= 60000 )); then
    elapsed_str="$(( elapsed_ms / 60000 ))m $(( (elapsed_ms % 60000) / 1000 ))s"
  elif (( elapsed_ms >= 1000 )); then
    elapsed_str="$(( elapsed_ms / 1000 )).$(( (elapsed_ms % 1000) / 100 ))s"
  else
    elapsed_str="${elapsed_ms}ms"
  fi

  PHASE_TIMES+=("$elapsed_str")
  PHASE6_TIME="$elapsed_str"

  # Run lcov summary
  local lcov_file="$PLUGIN_CRYPTO/coverage/lcov.info"
  local lcov_summary=""
  if [[ -f "$lcov_file" ]]; then
    echo "" >> "$log"
    echo "=== lcov summary ===" >> "$log"
    set +e
    lcov --summary "$lcov_file" >> "$log" 2>&1 || true
    # Also capture a shorter summary
    lcov_summary="$(lcov --summary "$lcov_file" 2>/dev/null | grep -E 'lines|functions' | head -5 || true)"
    set -e
  else
    echo -e "${YELLOW}  lcov.info not generated.${NC}"
  fi

  if [[ "$rc" -eq 0 ]]; then
    echo -e "${GREEN}Phase 6: PASS${NC}  (coverage generated in $elapsed_str)"
    PHASE_RESULTS+=("PASS")
    PHASE6_RC=0
  else
    echo -e "${RED}Phase 6: FAIL${NC}  (exit=$rc)"
    PHASE_RESULTS+=("FAIL")
    PHASE6_RC=$rc
  fi

  # Print lcov summary if available
  if [[ -n "$lcov_summary" ]]; then
    echo ""
    echo "$lcov_summary"
  fi

  return $rc
}

# ═════════════════════════════════════════════════════════════════════════════
# Generate summary report
# ═════════════════════════════════════════════════════════════════════════════

generate_report() {
  local end_epoch total_elapsed
  end_epoch=$(date +%s)
  total_elapsed=$(( end_epoch - START_EPOCH ))
  local total_elapsed_str
  if (( total_elapsed >= 3600 )); then
    total_elapsed_str="$(( total_elapsed / 3600 ))h $(( (total_elapsed % 3600) / 60 ))m $(( total_elapsed % 60 ))s"
  elif (( total_elapsed >= 60 )); then
    total_elapsed_str="$(( total_elapsed / 60 ))m $(( total_elapsed % 60 ))s"
  else
    total_elapsed_str="${total_elapsed}s"
  fi

  # Aggregate totals
  local grand_total=0 grand_passed=0 grand_skipped=0 grand_failed=0
  grand_total=$(( ${PHASE1_TOTAL:-0} + ${PHASE2_TOTAL:-0} + ${PHASE3_TOTAL:-0} + ${PHASE4_TOTAL:-0} + ${PHASE5_TOTAL:-0} ))
  grand_passed=$(( ${PHASE1_PASSED:-0} + ${PHASE2_PASSED:-0} + ${PHASE3_PASSED:-0} + ${PHASE4_PASSED:-0} + ${PHASE5_PASSED:-0} ))
  grand_skipped=$(( ${PHASE1_SKIPPED:-0} + ${PHASE2_SKIPPED:-0} + ${PHASE3_SKIPPED:-0} + ${PHASE4_SKIPPED:-0} + ${PHASE5_SKIPPED:-0} ))
  grand_failed=$(( ${PHASE1_FAILED:-0} + ${PHASE2_FAILED:-0} + ${PHASE3_FAILED:-0} + ${PHASE4_FAILED:-0} + ${PHASE5_FAILED:-0} ))

  local overall_result="PASS"
  for r in "${PHASE_RESULTS[@]}"; do
    if [[ "$r" == "FAIL" ]]; then
      overall_result="FAIL (some phases failed)"
      break
    fi
  done

  # Build device info string
  local device_info="N/A"
  if [[ -n "${ANDROID_DEVICE:-}" ]]; then
    device_info="$ANDROID_DEVICE"
  fi

  local fips_available="No"
  if [[ -f "$NATIVE_FIPS/libcrypto.so.4" ]]; then
    fips_available="Yes"
  fi

  # Write markdown report
  cat > "$REPORT_FILE" <<REPORT_EOF
# PluginCrypto — Reproducibility Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Host:** ${HOSTNAME}
**Kernel:** ${KERNEL}
**Architecture:** ${ARCH}
**Uname:** \`${UNAME_A}\`

---

## System Information

| Property | Value |
|----------|-------|
| Host | \`${HOSTNAME}\` |
| Kernel | ${KERNEL} |
| Architecture | ${ARCH} |
| FIPS build available | ${fips_available} |
| Android device | ${device_info} |
| Total elapsed | ${total_elapsed_str} |

---

## Phase Results

| Phase | Description | Status | Passed | Skipped | Failed | Total | Time |
|-------|-------------|--------|--------|---------|--------|-------|------|
| 1 | Linux Unit Tests | ${PHASE_RESULTS[0]:-N/A} | ${PHASE1_PASSED:-0} | ${PHASE1_SKIPPED:-0} | ${PHASE1_FAILED:-0} | ${PHASE1_TOTAL:-0} | ${PHASE1_TIME:-N/A} |
| 2 | Metrics Pipeline | ${PHASE_RESULTS[1]:-N/A} | ${PHASE2_PASSED:-0} | ${PHASE2_SKIPPED:-0} | ${PHASE2_FAILED:-0} | ${PHASE2_TOTAL:-0} | ${PHASE2_TIME:-N/A} |
| 3 | Linux Integration Tests | ${PHASE_RESULTS[2]:-N/A} | ${PHASE3_PASSED:-0} | ${PHASE3_SKIPPED:-0} | ${PHASE3_FAILED:-0} | ${PHASE3_TOTAL:-0} | ${PHASE3_TIME:-N/A} |
| 4 | Android Integration Tests | ${PHASE_RESULTS[3]:-N/A} | ${PHASE4_PASSED:-0} | ${PHASE4_SKIPPED:-0} | ${PHASE4_FAILED:-0} | ${PHASE4_TOTAL:-0} | ${PHASE4_TIME:-N/A} |
| 5 | FIPS/PQ Tests | ${PHASE_RESULTS[4]:-N/A} | ${PHASE5_PASSED:-0} | ${PHASE5_SKIPPED:-0} | ${PHASE5_FAILED:-0} | ${PHASE5_TOTAL:-0} | ${PHASE5_TIME:-N/A} |
| 6 | Coverage Analysis | ${PHASE_RESULTS[5]:-N/A} | — | — | — | — | ${PHASE6_TIME:-N/A} |

## Aggregate Totals

| Metric | Count |
|--------|-------|
| **Total tests executed** | **${grand_total}** |
| Passed | ${grand_passed} |
| Skipped | ${grand_skipped} |
| Failed | ${grand_failed} |
| **Overall result** | **${overall_result}** |

## Log Files

All detailed test logs are available in: \`${REPORT_DIR}/\`

| Phase | Log File |
|-------|----------|
| 1 | \`phase1_unit_${TIMESTAMP}.log\` |
| 2 | \`phase2_metrics_${TIMESTAMP}.log\` |
| 3 | \`phase3_integration_${TIMESTAMP}.log\` |
| 4 | \`phase4_android_*_${TIMESTAMP}.log\` (8 files) |
| 5 | \`phase5_fips_${TIMESTAMP}.log\` |
| 6 | \`phase6_coverage_${TIMESTAMP}.log\` |

## Environment

\`\`\`
LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}
OPENSSL_CONF=${OPENSSL_CONF:-}
TCC_METRICS_OUTPUT=${TCC_METRICS_OUTPUT:-}
\`\`\`

---

*Report generated by \`tool/reproduce_all.sh\`*
REPORT_EOF

  # Print summary to terminal
  echo ""
  echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${CYAN}  Reproducibility Report${NC}"
  echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  Total tests:  ${BOLD}${grand_total}${NC}"
  echo -e "  Passed:       ${GREEN}${grand_passed}${NC}"
  echo -e "  Skipped:      ${YELLOW}${grand_skipped}${NC}"
  echo -e "  Failed:       ${RED}${grand_failed}${NC}"
  echo -e "  Overall:      ${BOLD}${overall_result}${NC}"
  echo -e "  Total time:   ${total_elapsed_str}"
  echo ""
  echo -e "  Report:       ${BOLD}$REPORT_FILE${NC}"
  echo -e "  Logs:         ${DIM}$REPORT_DIR/${NC}"
  echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

main() {
  echo -e "${BOLD}${CYAN}"
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║     PluginCrypto — One-Click Reproducibility Script          ║"
  echo "║     Technical Evidence Report — Full Test Reproduction        ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo "Report: $REPORT_FILE"
  echo ""

  # Phase 0: Prerequisites and setup
  check_prerequisites
  detect_android_device
  setup_environment

  # Phase 1: Linux unit tests
  phase1_linux_unit_tests || true

  # Phase 2: Metrics pipeline
  phase2_metrics || true

  # Phase 3: Linux integration tests
  phase3_linux_integration || true

  # Phase 4: Android integration tests
  phase4_android_integration || true

  # Phase 5: FIPS/PQ tests
  phase5_fips_pq || true

  # Phase 6: Coverage analysis
  phase6_coverage || true

  # Generate summary report
  generate_report

  # Final exit code: fail if any non-skipped phase failed
  local final_rc=0
  for r in "${PHASE_RESULTS[@]}"; do
    if [[ "$r" == "FAIL" ]]; then
      final_rc=1
      break
    fi
  done

  if [[ "$final_rc" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All phases completed successfully.${NC}"
  else
    echo -e "${RED}${BOLD}One or more phases had failures. See report for details.${NC}"
  fi

  exit $final_rc
}

main "$@"
