#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
set -euo pipefail

# Script to check if sys crate versions referenced in aws-lc-rs are compatible
# with what's available on crates.io. Used to determine if aws-lc-rs publish
# dry-run should be skipped due to unpublished sys crate dependencies.
#
# Exit codes:
#   0 = Compatible (aws-lc-rs can be published)
#   1 = Incompatible (aws-lc-rs should skip publish due to major/minor version changes)
#   2 = Error in script execution

main() {
  local cargo_toml_path="${1:-aws-lc-rs/Cargo.toml}"
  
  # Parse aws-lc-rs/Cargo.toml to extract sys crate versions
  local aws_lc_sys_version
  local aws_lc_fips_sys_version
  
  aws_lc_sys_version=$(grep 'aws-lc-sys.*=' "$cargo_toml_path" | sed 's/.*version = "\([^"]*\)".*/\1/')
  aws_lc_fips_sys_version=$(grep 'aws-lc-fips-sys.*=' "$cargo_toml_path" | sed 's/.*version = "\([^"]*\)".*/\1/')
  
  if [[ -z "$aws_lc_sys_version" || -z "$aws_lc_fips_sys_version" ]]; then
    echo "Error: Could not extract sys crate versions from $cargo_toml_path" >&2
    exit 2
  fi
  
  echo "Local aws-lc-sys version: $aws_lc_sys_version"
  echo "Local aws-lc-fips-sys version: $aws_lc_fips_sys_version"
  
  local skip_reason=""
  local should_skip=false
  
  # Check aws-lc-sys
  echo "Checking aws-lc-sys version $aws_lc_sys_version on crates.io..."
  if ! check_version_exists "aws-lc-sys" "$aws_lc_sys_version"; then
    echo "aws-lc-sys version $aws_lc_sys_version not found on crates.io"
    local latest_aws_lc_sys
    if ! latest_aws_lc_sys=$(get_latest_version "aws-lc-sys"); then
      echo "Error: Failed to get latest version for aws-lc-sys" >&2
      exit 2
    fi
    echo "Latest aws-lc-sys version on crates.io: $latest_aws_lc_sys"
    
    if ! compare_versions "$aws_lc_sys_version" "$latest_aws_lc_sys"; then
      should_skip=true
      skip_reason="aws-lc-sys version $aws_lc_sys_version not published (major/minor version change from $latest_aws_lc_sys)"
      echo "aws-lc-sys: Major/minor version change detected"
    else
      echo "aws-lc-sys: Only patch version difference, compatible"
    fi
  else
    echo "aws-lc-sys version $aws_lc_sys_version found on crates.io"
  fi
  
  # Check aws-lc-fips-sys
  echo "Checking aws-lc-fips-sys version $aws_lc_fips_sys_version on crates.io..."
  if ! check_version_exists "aws-lc-fips-sys" "$aws_lc_fips_sys_version"; then
    echo "aws-lc-fips-sys version $aws_lc_fips_sys_version not found on crates.io"
    local latest_aws_lc_fips_sys
    if ! latest_aws_lc_fips_sys=$(get_latest_version "aws-lc-fips-sys"); then
      echo "Error: Failed to get latest version for aws-lc-fips-sys" >&2
      exit 2
    fi
    echo "Latest aws-lc-fips-sys version on crates.io: $latest_aws_lc_fips_sys"
    
    if ! compare_versions "$aws_lc_fips_sys_version" "$latest_aws_lc_fips_sys"; then
      should_skip=true
      if [[ -n "$skip_reason" ]]; then
        skip_reason="$skip_reason; aws-lc-fips-sys version $aws_lc_fips_sys_version not published (major/minor version change from $latest_aws_lc_fips_sys)"
      else
        skip_reason="aws-lc-fips-sys version $aws_lc_fips_sys_version not published (major/minor version change from $latest_aws_lc_fips_sys)"
      fi
      echo "aws-lc-fips-sys: Major/minor version change detected"
    else
      echo "aws-lc-fips-sys: Only patch version difference, compatible"
    fi
  else
    echo "aws-lc-fips-sys version $aws_lc_fips_sys_version found on crates.io"
  fi
  
  # Output results
  echo "Final decision: should_skip=$should_skip"
  if [[ "$should_skip" == "true" ]]; then
    echo "::notice::Skipping aws-lc-rs publish dry-run: $skip_reason"
    echo "SHOULD_SKIP=true"
    echo "SKIP_REASON=$skip_reason"
  else
    echo "::notice::All sys crate versions are compatible, aws-lc-rs publish dry-run will proceed"
    echo "SHOULD_SKIP=false"
    echo "SKIP_REASON="
  fi
}

# Function to check if version exists on crates.io
check_version_exists() {
  local crate_name=$1
  local version=$2
  local response
  local http_code
  
  echo "  Fetching versions for $crate_name..."
  
  # Use curl with verbose error reporting
  if response=$(curl -s --max-time 30 --retry 2 --retry-delay 1 \
                --user-agent "aws-lc-rs-version-check" \
                --write-out "HTTPSTATUS:%{http_code}" \
                "https://crates.io/api/v1/crates/$crate_name/versions" 2>&1); then

    # Extract HTTP status code
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')

    echo "  HTTP status: $http_code"

    if [[ "$http_code" == "200" ]] && [[ -n "$response" ]]; then
      echo "  Successfully fetched versions"
    else
      echo "  HTTP error $http_code"
      return 1
    fi
  else
    echo "  Curl failed: " $?
    return 1
  fi

  if [[ -z "$response" ]]; then
    echo "  Warning: Empty response for $crate_name versions"
    echo "  Assuming version exists to avoid false negatives"
    return 0  # Assume version exists to avoid false negatives
  fi
  
  echo "  Searching for version $version in response..."
  if echo "$response" | grep -q "\"num\":\"$version\""; then
    echo "  Found version $version"
    return 0
  else
    echo "  Version $version not found"
    return 1
  fi
}

# Function to get latest published version
get_latest_version() {
  local crate_name=$1
  local response
  local max_version
  local http_code
  
  echo "  Fetching crate info for $crate_name..." >&2
  
  if response=$(curl -s --max-time 30 --retry 2 --retry-delay 1 \
                --user-agent "aws-lc-rs-version-check" \
                --write-out "HTTPSTATUS:%{http_code}" \
                "https://crates.io/api/v1/crates/$crate_name" 2>&1); then

    # Extract HTTP status code
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')

    echo "  HTTP status: $http_code" >&2

    if [[ "$http_code" == "200" ]] && [[ -n "$response" ]]; then
      echo "  Successfully fetched crate info" >&2
    else
      echo "  HTTP error $http_code" >&2
      return 1
    fi
  else
    echo "  Curl failed: " $? >&2
    return 1
  fi

  if [[ -z "$response" ]]; then
    echo "  Error: Empty response for $crate_name info" >&2
    return 1
  fi
  
  if ! max_version=$(echo "$response" | grep -o '"max_version":"[^"]*"' | cut -d'"' -f4); then
    echo "  Error: Failed to extract max_version from response" >&2
    echo "  Response preview: $(echo "$response" | head -c 200)..." >&2
    return 1
  fi
  
  if [[ -z "$max_version" ]]; then
    echo "  Error: Empty max_version extracted" >&2
    return 1
  fi
  
  echo "$max_version"
  return 0
}

# Function to compare versions (returns 0 if only patch differs, 1 if minor/major differs)
compare_versions() {
  local local_ver=$1
  local published_ver=$2
  
  echo "  Comparing versions: local=$local_ver vs published=$published_ver"
  
  # Extract major.minor from both versions
  local local_major_minor
  local published_major_minor
  
  local_major_minor=$(echo "$local_ver" | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/')
  published_major_minor=$(echo "$published_ver" | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/')
  
  echo "  Extracted major.minor: local=$local_major_minor vs published=$published_major_minor"
  
  if [[ "$local_major_minor" == "$published_major_minor" ]]; then
    echo "  Result: Only patch version differs (compatible)"
    return 0  # Only patch version differs
  else
    echo "  Result: Major or minor version differs (incompatible)"
    return 1  # Major or minor version differs
  fi
}

# Run main function with all arguments
main "$@"
