#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Setup Xcode commands (if needed):
# > xcodebuild -runFirstLaunch
# > sudo xcodebuild -license accept
# > xcode-select --install
#
# Install tvOS simulator commands (if additional runtimes needed):
# > xcrun simctl list runtimes  # List available runtimes
# > xcodebuild -downloadPlatform tvOS  # Download latest tvOS runtime
# Note: Most CI environments (like GitHub Actions) come with tvOS simulators pre-installed
#
# IMPORTANT: tvOS targets are currently Tier 3 targets in Rust and may not be available
# in all toolchains. This script is prepared for future tvOS support.
#
# Usage:
# > ./scripts/ci/tvos-simulator-runner.sh [target]
#
# Planned tvOS targets (when available):
# - aarch64-apple-tvos-sim (default - Apple TV Simulator for Apple Silicon)
# - aarch64-apple-tvos (Apple TV device for Apple Silicon)
# - x86_64-apple-tvos (Apple TV Simulator for Intel)
# - arm64e-apple-tvos (Apple TV device with pointer authentication)
#
# Examples:
# > ./scripts/ci/tvos-simulator-runner.sh                          # Uses default target (aarch64-apple-tvos-sim)
# > ./scripts/ci/tvos-simulator-runner.sh aarch64-apple-tvos-sim   # Explicit simulator target
# > ./scripts/ci/tvos-simulator-runner.sh aarch64-apple-tvos       # Device target (build only)
#
# Note: Device targets (non-simulator) can only be built, not tested, as they require physical hardware.
# Currently, you may need a nightly toolchain or custom target specification for tvOS support.

set -ex

# Default target - can be overridden by command line argument
DEFAULT_TARGET="aarch64-apple-tvos-sim"

# Available tvOS targets
AVAILABLE_TARGETS=(
    "aarch64-apple-tvos-sim"
    "aarch64-apple-tvos"
    "x86_64-apple-tvos"
    "arm64e-apple-tvos"
)

# Help function
function show_help() {
    echo "tvOS Simulator Runner Script"
    echo ""
    echo "Usage: $0 [target|--help|-h]"
    echo ""
    echo "Available tvOS targets (when supported by Rust toolchain):"
    for target in "${AVAILABLE_TARGETS[@]}"; do
        if [[ "$target" == "$DEFAULT_TARGET" ]]; then
            echo "  $target (default)"
        else
            echo "  $target"
        fi
    done
    echo ""
    echo "Examples:"
    echo "  $0                              # Use default target"
    echo "  $0 aarch64-apple-tvos-sim      # Simulator target"
    echo "  $0 aarch64-apple-tvos           # Device target (build only)"
    echo "  TVOS_FORCE_TEST=1 $0            # Attempt test execution (may fail)"
    echo ""
    echo "Environment Variables:"
    echo "  TVOS_FORCE_TEST=1              # Attempt to run tests (potential SIGTRAP failures)"
    echo ""
    echo "Note: tvOS targets are currently Tier 3 and may require nightly Rust."
    echo "Both device and simulator targets are build-only by default due to runtime limitations."
    echo "Simulator tests often fail with SIGTRAP due to runtime incompatibility."
}

# Parse command line arguments
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

TARGET="${1:-$DEFAULT_TARGET}"

# Validate target
if [[ ! " ${AVAILABLE_TARGETS[*]} " =~ " ${TARGET} " ]]; then
    echo "Error: Invalid target '${TARGET}'"
    echo ""
    show_help
    exit 1
fi

echo "Building for target: ${TARGET}"

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SCRIPT_DIR="$(readlink -f "${SCRIPT_DIR}")"

# Find repo root (two directories up from scripts/ci)
REPO_ROOT="$(dirname "$(dirname "${SCRIPT_DIR}")")"

# tvOS simulator runtime detection constants
SIM_IMAGE_LIST_PATH='/Library/Developer/CoreSimulator/Images/images.plist'
# Potential mount base paths for tvOS simulator images
SIM_IMAGE_MOUNT_BASES=('/Volumes' '/Library/Developer/CoreSimulator/Volumes')
SIM_IMAGE_PATTERN='tvOS-'

# Utility functions for plist parsing
function plist_count_images() {
    if [[ -r "${SIM_IMAGE_LIST_PATH}" ]]; then
        plutil -extract 'images' raw "${SIM_IMAGE_LIST_PATH}" -o -
    else
        echo "0"
    fi
}

function plist_image_id_for() {
    plutil -extract "images.${1}.runtimeInfo.bundleIdentifier" raw "${SIM_IMAGE_LIST_PATH}" -o -
}

function plist_image_path_for() {
    plutil -extract "images.${1}.path.relative" raw "${SIM_IMAGE_LIST_PATH}" -o - | sed -e 's/^file:\/\///'
}

function plist_image_build_for() {
    plutil -extract "images.${1}.runtimeInfo.build" raw "${SIM_IMAGE_LIST_PATH}" -o -
}

function find_mount() {
    hdiutil info | grep -s "${1}"
}

function find_actual_mount_point() {
    local image_build="${1}"
    local mount_info
    local mount_point

    echo "DEBUG: Looking for mounted tvOS runtime with build: ${image_build}"

    # Check both potential mount bases
    for base in "${SIM_IMAGE_MOUNT_BASES[@]}"; do
        local potential_mount="${base}/tvOS_${image_build}"
        mount_info=$(hdiutil info | grep -s "${potential_mount}" | head -n 1)
        if [[ -n "${mount_info}" ]]; then
            # Try multiple parsing approaches for mount point extraction
            # Method 1: Look for the mount path in the line (most reliable)
            mount_point=$(echo "${mount_info}" | grep -o "${potential_mount}")
            if [[ -n "${mount_point}" && -d "${mount_point}" ]]; then
                echo "${mount_point}"
                return 0
            fi

            # Method 2: Extract using awk (fallback)
            mount_point=$(echo "${mount_info}" | awk '{print $NF}')
            if [[ -n "${mount_point}" && -d "${mount_point}" ]]; then
                echo "${mount_point}"
                return 0
            fi
        fi
    done

    # If not found with expected names, try to extract actual mount point from hdiutil info
    # Look for any mount that contains the image build
    echo "DEBUG: Searching hdiutil info for pattern: (tvOS.*${image_build}|${image_build}.*tvOS)"
    mount_info=$(hdiutil info | grep -E "(tvOS.*${image_build}|${image_build}.*tvOS)" | head -n 1)
    if [[ -n "${mount_info}" ]]; then
        echo "DEBUG: Found mount info: ${mount_info}"
        # Try to extract mount point from various positions in the output
        # hdiutil info format can vary, so try multiple approaches

        # Method 1: Look for /Volumes/* or /Library/Developer/* paths
        mount_point=$(echo "${mount_info}" | grep -o '/\(Volumes\|Library/Developer\)[^ ]*' | head -n 1)
        if [[ -n "${mount_point}" && -d "${mount_point}" ]]; then
            echo "${mount_point}"
            return 0
        fi

        # Method 2: Try last field (often the mount point)
        mount_point=$(echo "${mount_info}" | awk '{print $NF}')
        if [[ -n "${mount_point}" && -d "${mount_point}" ]]; then
            echo "${mount_point}"
            return 0
        fi

        # Method 3: Try third field (traditional approach)
        mount_point=$(echo "${mount_info}" | awk '{print $3}')
        if [[ -n "${mount_point}" && -d "${mount_point}" ]]; then
            echo "${mount_point}"
            return 0
        fi
    fi

    return 1
}

function find_runtime_root() {
    find "${1}" -type d -name "RuntimeRoot" | head -n 1
}

# Find tvOS SDK path for cross-compilation
function find_tvos_sdk_path() {
    local sdk_path
    local platform_name
    local sdk_name

    # Determine platform and SDK based on target
    if [[ "${TARGET}" == *"-sim" || "${TARGET}" == "x86_64-apple-tvos" ]]; then
        platform_name="AppleTVSimulator"
        sdk_name="AppleTVSimulator"
    else
        platform_name="AppleTVOS"
        sdk_name="AppleTVOS"
    fi

    # Try standard Xcode path first
    sdk_path="/Applications/Xcode.app/Contents/Developer/Platforms/${platform_name}.platform/Developer/SDKs/${sdk_name}.sdk"
    if [[ -d "${sdk_path}" ]]; then
        echo "${sdk_path}"
        return 0
    fi

    # Fallback to finding any available SDK for this platform
    sdk_path=$(find "/Applications/Xcode.app/Contents/Developer/Platforms/${platform_name}.platform/Developer/SDKs" -name "${sdk_name}*.sdk" 2>/dev/null | head -n 1)
    if [[ -n "${sdk_path}" && -d "${sdk_path}" ]]; then
        echo "${sdk_path}"
        return 0
    fi

    return 1
}

# Check if tvOS simulator runtime is available
function check_tvos_runtime_available() {
    local tvos_runtime
    tvos_runtime=$(xcrun simctl list runtimes | grep -i "tvOS" | head -n 1)
    if [[ -n "${tvos_runtime}" ]]; then
        echo "Found tvOS runtime: ${tvos_runtime}"
        return 0
    fi
    return 1
}

# Find tvOS simulator runtime for execution
function find_tvos_runtime() {

    # First try using simctl to find built-in runtimes
    local runtime_paths=(
        "/Applications/Xcode.app/Contents/Developer/Platforms/AppleTVSimulator.platform/Library/Developer/CoreSimulator/Profiles/Runtimes/tvOS.simruntime"
        "/Library/Developer/CoreSimulator/Profiles/Runtimes/tvOS.simruntime"
    )

    for runtime_path in "${runtime_paths[@]}"; do
        if [[ -d "${runtime_path}" ]]; then
            echo "${runtime_path}"
            return 0
        fi
    done

    # Fallback: scan images.plist for downloadable runtimes
    if [[ -r "${SIM_IMAGE_LIST_PATH}" ]]; then
        local image_list_size
        image_list_size=$(plist_count_images)
        local image_list_last_idx=$(( image_list_size - 1 ))

        for i in $(seq 0 "${image_list_last_idx}"); do
            if [[ $(plist_image_id_for "${i}") == *"${SIM_IMAGE_PATTERN}"* ]]; then
                local potential_path
                potential_path=$(plist_image_path_for "${i}")
                if [[ -f "${potential_path}" ]]; then
                    echo "${potential_path}:${i}"
                    return 0
                fi
            fi
        done
    fi

    return 1
}

# Attempt to download tvOS runtime if needed
function download_tvos_runtime_if_needed() {
    if check_tvos_runtime_available; then
        return 0
    fi

    echo "No tvOS simulator runtime found, attempting download..."
    echo "Note: This may fail in CI environments due to authentication requirements"

    if sudo xcodebuild -downloadPlatform tvOS -quiet; then
        echo "Download completed, checking for runtime..."
        sleep 5
        if check_tvos_runtime_available; then
            return 0
        fi
    fi

    echo "ERROR: No tvOS simulator runtime available and download failed"
    echo "Available runtimes:"
    xcrun simctl list runtimes
    return 1
}

# Main execution
echo "Checking tvOS simulator environment..."

# Check for available tvOS runtime
if ! check_tvos_runtime_available; then
    if ! download_tvos_runtime_if_needed; then
        exit 1
    fi
fi

# Find tvOS runtime for execution
RUNTIME_INFO=""
RUNTIME_INFO=$(find_tvos_runtime)
if [[ -z "${RUNTIME_INFO}" ]]; then
    echo "ERROR: No tvOS simulator runtime found for execution"
    exit 1
fi

# Parse runtime path and index (format: "path" or "path:index")
if [[ "${RUNTIME_INFO}" == *:* ]]; then
    RUNTIME_PATH="${RUNTIME_INFO%:*}"
    RUNTIME_INDEX="${RUNTIME_INFO##*:}"
else
    RUNTIME_PATH="${RUNTIME_INFO}"
    RUNTIME_INDEX=""
fi

echo "Found tvOS runtime: ${RUNTIME_PATH}"

# Set up runtime environment for test execution
if [[ -d "${RUNTIME_PATH}" && "${RUNTIME_PATH}" == *.simruntime ]]; then
    # Built-in runtime - use RuntimeRoot directly
    DYLD_ROOT_PATH=$(find_runtime_root "${RUNTIME_PATH}")
    if [[ -z "${DYLD_ROOT_PATH}" ]]; then
        echo "ERROR: RuntimeRoot not found in: ${RUNTIME_PATH}"
        exit 1
    fi
else
    # Disk image runtime - need to mount it
    if [[ -n "${RUNTIME_INDEX}" ]]; then
        echo "DEBUG: Getting build info from plist index: ${RUNTIME_INDEX}"
        IMAGE_BUILD=$(plist_image_build_for "${RUNTIME_INDEX}")
    else
        # Fallback: scan for any tvOS runtime in plist
        echo "DEBUG: No runtime index available, scanning for tvOS runtimes..."
        local found_tvos_index=""
        if [[ -r "${SIM_IMAGE_LIST_PATH}" ]]; then
            local image_list_size
            image_list_size=$(plist_count_images)
            local image_list_last_idx=$(( image_list_size - 1 ))

            for i in $(seq 0 "${image_list_last_idx}"); do
                if [[ $(plist_image_id_for "${i}") == *"${SIM_IMAGE_PATTERN}"* ]]; then
                    found_tvos_index="${i}"
                    echo "DEBUG: Found tvOS runtime at plist index: ${i}"
                    break
                fi
            done
        fi

        if [[ -n "${found_tvos_index}" ]]; then
            IMAGE_BUILD=$(plist_image_build_for "${found_tvos_index}")
        else
            echo "DEBUG: No tvOS runtime found in plist, using index 0 as last resort"
            IMAGE_BUILD=$(plist_image_build_for "0")
        fi
    fi

    echo "DEBUG: IMAGE_BUILD determined as: ${IMAGE_BUILD}"

    # Validate that we got a build number
    if [[ -z "${IMAGE_BUILD}" ]]; then
        echo "ERROR: Unable to determine tvOS runtime build number"
        echo "Available images in plist:"
        if [[ -r "${SIM_IMAGE_LIST_PATH}" ]]; then
            local image_list_size
            image_list_size=$(plist_count_images)
            local image_list_last_idx=$(( image_list_size - 1 ))
            for i in $(seq 0 "${image_list_last_idx}"); do
                echo "  Index ${i}: $(plist_image_id_for "${i}")"
            done
        else
            echo "  Unable to read ${SIM_IMAGE_LIST_PATH}"
        fi
        exit 1
    fi

    # Check if already mounted and get actual mount point
    IMAGE_MOUNT_POINT=$(find_actual_mount_point "${IMAGE_BUILD}")

    # Validate that the mount point exists and is a directory
    if [[ -n "${IMAGE_MOUNT_POINT}" && ! -d "${IMAGE_MOUNT_POINT}" ]]; then
        echo "DEBUG: Mount point returned: '${IMAGE_MOUNT_POINT}'"
        echo "DEBUG: Mount point does not exist or is not a directory, trying each potential mount..."

        # If the returned mount point contains newlines (multiple paths), try each one
        while IFS= read -r mount_path; do
            if [[ -d "${mount_path}" ]]; then
                echo "DEBUG: Found valid mount point: ${mount_path}"
                IMAGE_MOUNT_POINT="${mount_path}"
                break
            fi
        done <<< "${IMAGE_MOUNT_POINT}"

        # If still not valid, clear it so we try to mount
        if [[ ! -d "${IMAGE_MOUNT_POINT}" ]]; then
            echo "DEBUG: No valid mount point found, will attempt to mount"
            IMAGE_MOUNT_POINT=""
        fi
    fi

    if [[ -z "${IMAGE_MOUNT_POINT}" ]]; then
        # Not mounted, try to mount it at the preferred location
        IMAGE_MOUNT_POINT="${SIM_IMAGE_MOUNT_BASES[0]}/tvOS_${IMAGE_BUILD}"
        echo "DEBUG: Will attempt to mount at: ${IMAGE_MOUNT_POINT}"
        echo "Mounting tvOS runtime: ${RUNTIME_PATH}"
        sudo hdiutil attach "${RUNTIME_PATH}" -mountpoint "${IMAGE_MOUNT_POINT}"

        # Verify it mounted successfully
        if ! find_mount "${IMAGE_MOUNT_POINT}"; then
            echo "WARNING: Unable to mount runtime at preferred location: ${IMAGE_MOUNT_POINT}"
            echo "Attempting direct mount as fallback..."

            # Try direct mounting without specifying mount point
            if sudo hdiutil attach "${RUNTIME_PATH}" -quiet; then
                echo "Successfully mounted runtime directly"
                # Find where it actually mounted
                sleep 2
                IMAGE_MOUNT_POINT=$(hdiutil info | grep "${RUNTIME_PATH}" | awk '{print $NF}' | head -n 1)
                if [[ -z "${IMAGE_MOUNT_POINT}" || ! -d "${IMAGE_MOUNT_POINT}" ]]; then
                    echo "ERROR: Unable to determine mount point after direct mount"
                    exit 1
                fi
                echo "Runtime mounted at: ${IMAGE_MOUNT_POINT}"
            else
                echo "ERROR: Unable to mount runtime: ${RUNTIME_PATH}"
                exit 1
            fi
        fi
    else
        echo "tvOS runtime already mounted at: ${IMAGE_MOUNT_POINT}"
    fi

    DYLD_ROOT_PATH=$(find_runtime_root "${IMAGE_MOUNT_POINT}")
    if [[ -z "${DYLD_ROOT_PATH}" ]]; then
        echo "ERROR: RuntimeRoot not found in mounted image: ${IMAGE_MOUNT_POINT}"
        echo "DEBUG: Mount point contents:"
        ls -la "${IMAGE_MOUNT_POINT}" 2>/dev/null || echo "Unable to list mount point contents"
        exit 1
    fi
fi

echo "Using tvOS runtime root: ${DYLD_ROOT_PATH}"
export DYLD_ROOT_PATH

# Find and set up tvOS SDK path for cross-compilation
TVOS_SDK_PATH=""
TVOS_SDK_PATH=$(find_tvos_sdk_path)
if [[ -z "${TVOS_SDK_PATH}" ]]; then
    echo "ERROR: tvOS SDK not found"
    exit 1
fi

echo "Using tvOS SDK: ${TVOS_SDK_PATH}"

# Set up bindgen environment for tvOS cross-compilation
export BINDGEN_EXTRA_CLANG_ARGS="-isysroot ${TVOS_SDK_PATH}"

cd "${REPO_ROOT}"

# Function to attempt force testing with error handling
function force_test_with_handling() {
    local target="${1}"
    echo "Force testing simulator target: ${target}"
    echo "Note: Testing requires tvOS Simulator runtime to be available"
    export RUST_BACKTRACE=1

    # Try release tests
    echo "Running release tests..."
    if timeout 300 cargo +nightly test -Z build-std --release --features bindgen,unstable -p aws-lc-rs --lib --target "${target}"; then
        echo "Release tests completed successfully"
    else
        local exit_code=$?
        echo "Release tests failed with exit code: ${exit_code}"
        if [[ ${exit_code} -eq 124 ]]; then
            echo "Tests timed out after 5 minutes"
        elif [[ ${exit_code} -eq 101 ]]; then
            echo "Tests failed with SIGTRAP (signal 5)"
        fi
        return 1
    fi
}

# First build, then attempt testing
echo "Building simulator target: ${TARGET}"
cargo +nightly build -Z build-std --features bindgen,unstable -p aws-lc-rs --target "${TARGET}" || exit 1
cargo +nightly build -Z build-std --release --features bindgen,unstable -p aws-lc-rs --target "${TARGET}" || exit 1

if [[ "${TVOS_FORCE_TEST}" == "1" ]]; then
    force_test_with_handling "${TARGET}" || exit 1
fi
