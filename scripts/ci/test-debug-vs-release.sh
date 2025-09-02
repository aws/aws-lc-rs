#!/usr/bin/env bash
# Script to investigate debug vs release SIGTRAP behavior in tvOS simulator
# This helps understand why debug builds fail with SIGTRAP while release might succeed

set -e

# Configuration
TARGET="${1:-aarch64-apple-tvos-sim}"
TIMEOUT_SECONDS=30
TEST_PACKAGE="aws-lc-rs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function log_section() {
    echo ""
    echo "================================================================="
    echo "  $1"
    echo "================================================================="
}

function check_prerequisites() {
    log_section "Checking Prerequisites"
    
    # Check if target is available
    if ! rustc --print target-list | grep -q "^${TARGET}$"; then
        log_error "Target ${TARGET} not supported by rustc"
        log_info "Available tvOS targets:"
        rustc --print target-list | grep tvos || echo "  None found"
        exit 1
    fi
    
    # Check if nightly is available
    if ! command -v rustup >/dev/null 2>&1; then
        log_error "rustup not found"
        exit 1
    fi
    
    if ! rustup toolchain list | grep -q nightly; then
        log_warning "Nightly toolchain not installed, installing..."
        rustup install nightly
    fi
    
    # Try to install target
    log_info "Attempting to install target: ${TARGET}"
    if rustup +nightly target add "${TARGET}" 2>/dev/null; then
        log_success "Target ${TARGET} installed successfully"
    else
        log_error "Failed to install target ${TARGET}"
        log_info "This script will test compilation only"
    fi
}

function build_and_analyze() {
    local build_type="$1"  # "debug" or "release"
    local extra_flags="$2"
    
    log_section "Building ${build_type} version"
    
    local cargo_flags="--features bindgen,unstable -p ${TEST_PACKAGE} --target ${TARGET}"
    if [[ "$build_type" == "release" ]]; then
        cargo_flags="--release $cargo_flags"
    fi
    
    log_info "Cargo command: cargo +nightly build -Z build-std $cargo_flags $extra_flags"
    
    if timeout $TIMEOUT_SECONDS cargo +nightly build -Z build-std $cargo_flags $extra_flags; then
        log_success "${build_type} build completed successfully"
        return 0
    else
        local exit_code=$?
        log_error "${build_type} build failed with exit code: $exit_code"
        return $exit_code
    fi
}

function compile_tests() {
    local build_type="$1"  # "debug" or "release"
    
    log_section "Compiling ${build_type} tests"
    
    local cargo_flags="--features bindgen,unstable -p ${TEST_PACKAGE} --lib --target ${TARGET} --no-run"
    if [[ "$build_type" == "release" ]]; then
        cargo_flags="--release $cargo_flags"
    fi
    
    log_info "Cargo command: cargo +nightly test -Z build-std $cargo_flags"
    
    if timeout $TIMEOUT_SECONDS cargo +nightly test -Z build-std $cargo_flags; then
        log_success "${build_type} test compilation completed successfully"
        return 0
    else
        local exit_code=$?
        log_error "${build_type} test compilation failed with exit code: $exit_code"
        return $exit_code
    fi
}

function attempt_test_execution() {
    local build_type="$1"  # "debug" or "release"
    
    log_section "Attempting ${build_type} test execution"
    
    local cargo_flags="--features bindgen,unstable -p ${TEST_PACKAGE} --lib --target ${TARGET}"
    if [[ "$build_type" == "release" ]]; then
        cargo_flags="--release $cargo_flags"
    fi
    
    log_info "Cargo command: cargo +nightly test -Z build-std $cargo_flags"
    log_warning "This may fail with SIGTRAP - that's expected for simulator targets"
    
    local output
    local exit_code=0
    
    # Capture both stdout and stderr
    output=$(timeout $TIMEOUT_SECONDS cargo +nightly test -Z build-std $cargo_flags 2>&1) || exit_code=$?
    
    # Analyze the results
    case $exit_code in
        0)
            log_success "${build_type} tests executed successfully!"
            echo "$output" | tail -5
            ;;
        124)
            log_warning "${build_type} tests timed out after ${TIMEOUT_SECONDS} seconds"
            ;;
        133)
            log_warning "${build_type} tests failed with SIGTRAP (signal 5)"
            log_info "This indicates runtime incompatibility with simulator environment"
            ;;
        *)
            log_error "${build_type} tests failed with exit code: $exit_code"
            ;;
    esac
    
    # Look for specific error patterns
    if echo "$output" | grep -q "SIGTRAP"; then
        log_info "SIGTRAP detected in output - analyzing..."
        echo "$output" | grep -A 2 -B 2 "SIGTRAP" | sed 's/^/  /'
    fi
    
    if echo "$output" | grep -q "signal: 5"; then
        log_info "Signal 5 (SIGTRAP) detected - this is the simulator incompatibility issue"
    fi
    
    # Count successful tests
    local passed_tests
    passed_tests=$(echo "$output" | grep -c "test .* \.\.\. ok" || echo "0")
    local failed_tests  
    failed_tests=$(echo "$output" | grep -c "test .* \.\.\. FAILED" || echo "0")
    
    log_info "${build_type} test results: $passed_tests passed, $failed_tests failed before crash"
    
    return $exit_code
}

function analyze_binaries() {
    log_section "Analyzing Generated Binaries"
    
    local target_dir="target/${TARGET}"
    
    if [[ -d "$target_dir" ]]; then
        log_info "Binary sizes and types:"
        
        # Find test executables
        find "$target_dir" -name "*${TEST_PACKAGE}*" -type f -executable 2>/dev/null | while read -r binary; do
            if [[ -f "$binary" ]]; then
                local size=$(stat -f%z "$binary" 2>/dev/null || echo "unknown")
                local type=$(file "$binary" 2>/dev/null || echo "unknown")
                echo "  $(basename "$binary"): ${size} bytes"
                echo "    Type: $type"
                
                # Check for debug symbols
                if nm "$binary" >/dev/null 2>&1; then
                    echo "    Debug symbols: present"
                else
                    echo "    Debug symbols: stripped"
                fi
            fi
        done
    else
        log_warning "Target directory not found: $target_dir"
    fi
}

function run_comparative_analysis() {
    log_section "Comparative Analysis: Debug vs Release"
    
    echo "Testing both debug and release builds to compare behavior..."
    echo ""
    
    # Track results
    local debug_build_success=false
    local release_build_success=false
    local debug_test_compile_success=false
    local release_test_compile_success=false
    local debug_test_run_exit=999
    local release_test_run_exit=999
    
    # Test debug build
    if build_and_analyze "debug"; then
        debug_build_success=true
        if compile_tests "debug"; then
            debug_test_compile_success=true
            attempt_test_execution "debug"
            debug_test_run_exit=$?
        fi
    fi
    
    echo ""
    echo "---"
    echo ""
    
    # Test release build  
    if build_and_analyze "release"; then
        release_build_success=true
        if compile_tests "release"; then
            release_test_compile_success=true
            attempt_test_execution "release"
            release_test_run_exit=$?
        fi
    fi
    
    # Summary comparison
    log_section "Summary Comparison"
    
    echo "Build Success:"
    echo "  Debug:   $([ "$debug_build_success" = true ] && echo "✓" || echo "✗")"
    echo "  Release: $([ "$release_build_success" = true ] && echo "✓" || echo "✗")"
    echo ""
    echo "Test Compilation:"
    echo "  Debug:   $([ "$debug_test_compile_success" = true ] && echo "✓" || echo "✗")"
    echo "  Release: $([ "$release_test_compile_success" = true ] && echo "✓" || echo "✗")"
    echo ""
    echo "Test Execution (exit codes):"
    echo "  Debug:   $debug_test_run_exit $(analyze_exit_code $debug_test_run_exit)"
    echo "  Release: $release_test_run_exit $(analyze_exit_code $release_test_run_exit)"
    
    # Analyze the pattern
    if [[ $debug_test_run_exit -eq 133 && $release_test_run_exit -eq 0 ]]; then
        echo ""
        log_info "PATTERN DETECTED: Debug fails with SIGTRAP, Release succeeds"
        echo "This suggests the issue is related to:"
        echo "  • Debug assertions and runtime checks"
        echo "  • Debugging infrastructure incompatibility"  
        echo "  • Different memory layout/protection in debug builds"
        echo "  • Symbol resolution differences"
    elif [[ $debug_test_run_exit -eq 133 && $release_test_run_exit -eq 133 ]]; then
        echo ""
        log_info "PATTERN: Both debug and release fail with SIGTRAP"
        echo "This suggests a fundamental simulator runtime incompatibility"
    elif [[ $debug_test_run_exit -eq 0 && $release_test_run_exit -eq 0 ]]; then
        echo ""
        log_success "Both debug and release tests work!"
        echo "The simulator environment is compatible with this target"
    fi
}

function main() {
    echo "Debug vs Release SIGTRAP Analysis for tvOS Simulator"
    echo "===================================================="
    echo "Target: $TARGET"
    echo "Timeout: $TIMEOUT_SECONDS seconds"
    echo ""
    
    check_prerequisites
    
    # Set up environment (basic version - the full script would set up DYLD_ROOT_PATH etc)
    export BINDGEN_EXTRA_CLANG_ARGS="-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/AppleTVSimulator.platform/Developer/SDKs/AppleTVSimulator.sdk"
    
    run_comparative_analysis
    
    analyze_binaries
    
    log_section "Recommendations"
    echo "Based on this analysis:"
    echo "• If debug fails but release works: Use release builds for testing"
    echo "• If both fail: Use build-only or test compilation mode"
    echo "• SIGTRAP is expected behavior, not a bug in your code"
    echo "• Successful compilation indicates working tvOS support"
}

function analyze_exit_code() {
    local code=$1
    case $code in
        0) echo "(success)" ;;
        124) echo "(timeout)" ;;
        133) echo "(SIGTRAP)" ;;
        999) echo "(not run)" ;;
        *) echo "(error)" ;;
    esac
}

# Run main function
main "$@"