// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Prebuilt AWS-LC library linking support.
//!
//! This module provides functionality to link against a pre-existing AWS-LC
//! installation instead of building from source.

use std::path::{Path, PathBuf};

use crate::{emit_warning, get_aws_lc_include_path, optional_env_crate_target};

/// Configuration for prebuilt AWS-LC linking mode
pub(crate) struct Config {
    /// Path to the AWS-LC installation directory
    pub install_dir: PathBuf,
    /// Optional path to pre-generated Rust bindings file (from PREBUILT_BINDINGS env var)
    pub bindings_override: Option<PathBuf>,
    /// Whether to skip version compatibility check
    pub skip_version_check: bool,
}

// Safety: This static is only written once during initialize() which is called
// at the start of main() before any other code runs. Build scripts are single-threaded.
static mut SYS_CONFIG: Option<Config> = None;

/// Constructs the full environment variable name for error messages.
/// For example, for aws-lc-sys crate: "AWS_LC_SYS_PREBUILT_INSTALL_DIR"
pub(crate) fn env_var_crate_target(name: &str) -> String {
    let crate_name = crate::crate_name().to_uppercase().replace('-', "_");
    format!("{crate_name}_{name}")
}

/// Initialize prebuilt configuration from environment variables.
/// Must be called from main.rs initialize() function.
pub(crate) fn initialize() {
    // Check if prebuilt mode is enabled via PREBUILT_INSTALL_DIR
    let install_dir_env = optional_env_crate_target("PREBUILT_INSTALL_DIR");

    let install_dir = match install_dir_env {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => return, // Prebuilt mode not enabled
    };

    // Read optional bindings override path
    let bindings_override = optional_env_crate_target("PREBUILT_BINDINGS").map(PathBuf::from);

    // Read optional skip version check flag
    let skip_version_check = optional_env_crate_target("PREBUILT_SKIP_VERSION_CHECK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let config = Config {
        install_dir,
        bindings_override,
        skip_version_check,
    };

    // Safety: Called once from initialize(), single-threaded build script
    unsafe {
        SYS_CONFIG = Some(config);
    }
}

/// Returns the prebuilt configuration if prebuilt mode is enabled.
#[allow(static_mut_refs)]
pub(crate) fn get_config() -> Option<&'static Config> {
    // Safety: Only called after initialize(), single-threaded build script
    unsafe { SYS_CONFIG.as_ref() }
}

/// Returns true if prebuilt mode is enabled (PREBUILT_INSTALL_DIR is set).
pub(crate) fn is_enabled() -> bool {
    get_config().is_some()
}

/// Detects if the prebuilt AWS-LC has a symbol prefix by checking for BORINGSSL_PREFIX.
///
/// Returns the prefix string if found, or None if no prefix is configured.
pub(crate) fn detect_prefix(include_dir: &Path) -> Option<String> {
    let prefix_header = include_dir
        .join("openssl")
        .join("boringssl_prefix_symbols.h");

    let content = std::fs::read_to_string(&prefix_header).ok()?;

    // Look for: #define BORINGSSL_PREFIX <prefix_name>
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("#define") && line.contains("BORINGSSL_PREFIX") {
            // Parse: "#define BORINGSSL_PREFIX my_prefix"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "BORINGSSL_PREFIX" {
                return Some(parts[2].to_string());
            }
        }
    }

    None
}

/// Validates AWS-LC headers and extracts version string in one pass.
///
/// Checks for OPENSSL_IS_AWSLC marker and AWSLC_VERSION_NUMBER_STRING.
/// Returns the version string (e.g., "1.35.0") on success.
pub(crate) fn validate_and_extract_version(include_dir: &Path) -> Result<String, String> {
    let base_h = include_dir.join("openssl").join("base.h");
    let content = std::fs::read_to_string(&base_h)
        .map_err(|e| format!("Failed to read {}: {}", base_h.display(), e))?;

    // Verify this is AWS-LC (not OpenSSL or BoringSSL)
    if !content.contains("OPENSSL_IS_AWSLC") {
        return Err(format!(
            "Headers at {} are not valid AWS-LC headers.\n\
             The OPENSSL_IS_AWSLC marker was not found in base.h.\n\
             Ensure the path contains AWS-LC headers, not OpenSSL or BoringSSL.",
            include_dir.display()
        ));
    }

    // Extract version: look for #define AWSLC_VERSION_NUMBER_STRING "X.Y.Z"
    for line in content.lines() {
        let line = line.trim();
        if line.contains("AWSLC_VERSION_NUMBER_STRING") && line.contains('"') {
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    return Ok(line[start + 1..start + 1 + end].to_string());
                }
            }
        }
    }

    Err(format!(
        "Could not find AWSLC_VERSION_NUMBER_STRING in {}.\n\
         The file appears to be AWS-LC headers but version could not be determined.",
        base_h.display()
    ))
}

/// Parses version string "X.Y.Z" into comparable components.
pub(crate) fn parse_version(version_str: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("Invalid version format: {}", version_str));
    }
    Ok((
        parts[0]
            .parse()
            .map_err(|_| format!("Invalid major version: {}", parts[0]))?,
        parts[1]
            .parse()
            .map_err(|_| format!("Invalid minor version: {}", parts[1]))?,
        parts[2]
            .parse()
            .map_err(|_| format!("Invalid patch version: {}", parts[2]))?,
    ))
}

/// Returns true if installed version >= required version.
pub(crate) fn version_compatible(installed: &str, required: &str) -> Result<bool, String> {
    let (i_maj, i_min, i_pat) = parse_version(installed)?;
    let (r_maj, r_min, r_pat) = parse_version(required)?;

    Ok((i_maj, i_min, i_pat) >= (r_maj, r_min, r_pat))
}

/// Returns the bundled AWS-LC version from the crate's headers.
///
/// Uses the existing `get_aws_lc_include_path()` function from the codebase
/// to locate the bundled headers.
pub(crate) fn get_bundled_awslc_version() -> String {
    let manifest_dir = crate::current_dir();
    let bundled_include = get_aws_lc_include_path(&manifest_dir);
    validate_and_extract_version(&bundled_include)
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

/// Validates a prebuilt AWS-LC installation.
///
/// Returns (version_string, detected_prefix) on success.
pub(crate) fn validate_installation(
    include_dir: &Path,
    skip_version_check: bool,
) -> Result<(String, Option<String>), String> {
    // Get the appropriate env var name for error messages
    let install_dir_env_var = env_var_crate_target("PREBUILT_INSTALL_DIR");

    // 1. Verify include directory exists
    if !include_dir.exists() {
        return Err(format!(
            "Include directory not found: {}\n\
             Verify {} points to a valid installation.",
            include_dir.display(),
            install_dir_env_var
        ));
    }

    // 2. Read base.h and validate AWS-LC headers + extract version in one pass
    let version = validate_and_extract_version(include_dir)?;

    // 3. Check version compatibility
    let required_version = get_bundled_awslc_version();
    if let Ok(compatible) = version_compatible(&version, &required_version) {
        if !compatible {
            if skip_version_check {
                emit_warning(format!(
                    "WARNING: Skipping version check. Installed {} < required {}. \
                     This may cause runtime issues.",
                    version, required_version
                ));
            } else {
                let env_prefix = install_dir_env_var.trim_end_matches("_INSTALL_DIR");
                return Err(format!(
                    "AWS-LC version mismatch: installed {} < required {}.\n\
                     Please upgrade AWS-LC or unset {} to build from source.\n\
                     To bypass this check (not recommended), set {}_SKIP_VERSION_CHECK=1",
                    version, required_version, install_dir_env_var, env_prefix
                ));
            }
        }
    }

    // 4. Detect symbol prefix
    let prefix = detect_prefix(include_dir);

    emit_warning(format!(
        "Prebuilt AWS-LC: version={}, prefix={:?}",
        version,
        prefix.as_deref().unwrap_or("none")
    ));

    Ok((version, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -------------------------------------------------------------------------
    // parse_version tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_version_valid() {
        assert_eq!(parse_version("1.2.3").unwrap(), (1, 2, 3));
        assert_eq!(parse_version("0.0.0").unwrap(), (0, 0, 0));
        assert_eq!(parse_version("10.20.30").unwrap(), (10, 20, 30));
    }

    #[test]
    fn test_parse_version_invalid() {
        assert!(parse_version("1.2").is_err());
        assert!(parse_version("1.2.3.4").is_err());
        assert!(parse_version("a.b.c").is_err());
        assert!(parse_version("").is_err());
        assert!(parse_version("1.2.").is_err());
    }

    // -------------------------------------------------------------------------
    // version_compatible tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_version_compatible_equal() {
        assert!(version_compatible("1.2.3", "1.2.3").unwrap());
    }

    #[test]
    fn test_version_compatible_newer_major() {
        assert!(version_compatible("2.0.0", "1.9.9").unwrap());
    }

    #[test]
    fn test_version_compatible_newer_minor() {
        assert!(version_compatible("1.3.0", "1.2.9").unwrap());
    }

    #[test]
    fn test_version_compatible_newer_patch() {
        assert!(version_compatible("1.2.4", "1.2.3").unwrap());
    }

    #[test]
    fn test_version_compatible_older_major() {
        assert!(!version_compatible("1.0.0", "2.0.0").unwrap());
    }

    #[test]
    fn test_version_compatible_older_minor() {
        assert!(!version_compatible("1.1.0", "1.2.0").unwrap());
    }

    #[test]
    fn test_version_compatible_older_patch() {
        assert!(!version_compatible("1.2.2", "1.2.3").unwrap());
    }

    // -------------------------------------------------------------------------
    // detect_prebuilt_prefix tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_detect_prefix_with_prefix() {
        let temp_dir = tempfile::tempdir().unwrap();
        let openssl_dir = temp_dir.path().join("openssl");
        std::fs::create_dir_all(&openssl_dir).unwrap();

        let header_path = openssl_dir.join("boringssl_prefix_symbols.h");
        let mut file = std::fs::File::create(&header_path).unwrap();
        writeln!(file, "#ifndef BORINGSSL_PREFIX_SYMBOLS_H").unwrap();
        writeln!(file, "#define BORINGSSL_PREFIX_SYMBOLS_H").unwrap();
        writeln!(file, "#define BORINGSSL_PREFIX my_custom_prefix").unwrap();
        writeln!(file, "#endif").unwrap();

        let prefix = detect_prefix(temp_dir.path());
        assert_eq!(prefix, Some("my_custom_prefix".to_string()));
    }

    #[test]
    fn test_detect_prefix_without_header() {
        let temp_dir = tempfile::tempdir().unwrap();
        let prefix = detect_prefix(temp_dir.path());
        assert_eq!(prefix, None);
    }

    #[test]
    fn test_detect_prefix_header_without_define() {
        let temp_dir = tempfile::tempdir().unwrap();
        let openssl_dir = temp_dir.path().join("openssl");
        std::fs::create_dir_all(&openssl_dir).unwrap();

        let header_path = openssl_dir.join("boringssl_prefix_symbols.h");
        let mut file = std::fs::File::create(&header_path).unwrap();
        writeln!(file, "#ifndef BORINGSSL_PREFIX_SYMBOLS_H").unwrap();
        writeln!(file, "#define BORINGSSL_PREFIX_SYMBOLS_H").unwrap();
        writeln!(file, "// No BORINGSSL_PREFIX defined").unwrap();
        writeln!(file, "#endif").unwrap();

        let prefix = detect_prefix(temp_dir.path());
        assert_eq!(prefix, None);
    }

    // -------------------------------------------------------------------------
    // validate_and_extract_version tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_validate_and_extract_version_valid() {
        let temp_dir = tempfile::tempdir().unwrap();
        let openssl_dir = temp_dir.path().join("openssl");
        std::fs::create_dir_all(&openssl_dir).unwrap();

        let base_h = openssl_dir.join("base.h");
        let mut file = std::fs::File::create(&base_h).unwrap();
        writeln!(file, "#ifndef OPENSSL_BASE_H").unwrap();
        writeln!(file, "#define OPENSSL_BASE_H").unwrap();
        writeln!(file, "#define OPENSSL_IS_AWSLC 1").unwrap();
        writeln!(file, "#define AWSLC_VERSION_NUMBER_STRING \"1.35.0\"").unwrap();
        writeln!(file, "#endif").unwrap();

        let version = validate_and_extract_version(temp_dir.path()).unwrap();
        assert_eq!(version, "1.35.0");
    }

    #[test]
    fn test_validate_and_extract_version_not_awslc() {
        let temp_dir = tempfile::tempdir().unwrap();
        let openssl_dir = temp_dir.path().join("openssl");
        std::fs::create_dir_all(&openssl_dir).unwrap();

        let base_h = openssl_dir.join("base.h");
        let mut file = std::fs::File::create(&base_h).unwrap();
        writeln!(file, "#ifndef OPENSSL_BASE_H").unwrap();
        writeln!(file, "#define OPENSSL_BASE_H").unwrap();
        writeln!(file, "// Not AWS-LC").unwrap();
        writeln!(file, "#endif").unwrap();

        let result = validate_and_extract_version(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not valid AWS-LC headers"));
    }

    #[test]
    fn test_validate_and_extract_version_missing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = validate_and_extract_version(temp_dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn test_validate_and_extract_version_missing_version_string() {
        let temp_dir = tempfile::tempdir().unwrap();
        let openssl_dir = temp_dir.path().join("openssl");
        std::fs::create_dir_all(&openssl_dir).unwrap();

        let base_h = openssl_dir.join("base.h");
        let mut file = std::fs::File::create(&base_h).unwrap();
        writeln!(file, "#ifndef OPENSSL_BASE_H").unwrap();
        writeln!(file, "#define OPENSSL_BASE_H").unwrap();
        writeln!(file, "#define OPENSSL_IS_AWSLC 1").unwrap();
        // Missing AWSLC_VERSION_NUMBER_STRING
        writeln!(file, "#endif").unwrap();

        let result = validate_and_extract_version(temp_dir.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Could not find AWSLC_VERSION_NUMBER_STRING"));
    }
}
