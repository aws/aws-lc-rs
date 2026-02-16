// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! PrebuiltBuilder for linking against pre-existing AWS-LC installations.
//!
//! This builder is used when the `PREBUILT_INSTALL_DIR` environment variable
//! is set, allowing users to link against a system-installed AWS-LC instead
//! of building from source.

use crate::prebuilt_aws_lc::env_var_crate_target;
use crate::{emit_warning, target_env, target_os, OutputLibType};
use std::path::{Path, PathBuf};

/// Builder for linking against a prebuilt AWS-LC installation.
#[derive(Debug)]
pub(crate) struct PrebuiltBuilder {
    install_dir: PathBuf,
    include_dir: PathBuf,
    lib_dir: PathBuf,
    output_lib_type: OutputLibType,
    prefix: Option<String>,
}

impl PrebuiltBuilder {
    /// Creates a new PrebuiltBuilder for the given installation directory.
    ///
    /// # Arguments
    /// * `install_dir` - Path to the AWS-LC installation root directory
    /// * `prefix` - Optional symbol prefix (e.g., "my_prefix" for libmy_prefix_crypto.a)
    ///
    /// # Errors
    /// Returns an error if the library directory doesn't exist or no suitable
    /// library files are found.
    pub(crate) fn new(install_dir: PathBuf, prefix: Option<String>) -> Result<Self, String> {
        let include_dir = install_dir.join("include");

        // Check lib64 first (RHEL, Fedora, SUSE use lib64 for 64-bit libraries)
        let lib_dir = if install_dir.join("lib64").exists() && cfg!(target_pointer_width = "64") {
            install_dir.join("lib64")
        } else {
            install_dir.join("lib")
        };

        if !lib_dir.exists() {
            return Err(format!(
                "Library directory not found: {} (also checked lib64/)\n\
                 Expected AWS-LC libraries at this location.\n\
                 Verify {} points to a valid AWS-LC installation.",
                install_dir.join("lib").display(),
                env_var_crate_target("PREBUILT_INSTALL_DIR")
            ));
        }

        let output_lib_type = Self::detect_lib_type(&lib_dir, &prefix)?;

        Ok(Self {
            install_dir,
            include_dir,
            lib_dir,
            output_lib_type,
            prefix,
        })
    }

    /// Returns the include directory path.
    pub(crate) fn include_dir(&self) -> &Path {
        &self.include_dir
    }

    /// Returns the library directory path.
    #[allow(dead_code)]
    pub(crate) fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    /// Returns the symbol prefix, if any.
    #[allow(dead_code)]
    pub(crate) fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Returns the detected output library type (Static or Dynamic).
    #[allow(dead_code)]
    pub(crate) fn output_lib_type(&self) -> OutputLibType {
        self.output_lib_type
    }

    /// Returns the crypto library name (with prefix if applicable).
    pub(crate) fn crypto_lib_name(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{}_crypto", p),
            None => "crypto".to_string(),
        }
    }

    /// Returns the SSL library name (with prefix if applicable).
    pub(crate) fn ssl_lib_name(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{}_ssl", p),
            None => "ssl".to_string(),
        }
    }

    /// Detects whether to use static or dynamic linking based on available libraries.
    ///
    /// Respects user preference from `OutputLibType::default()` (which checks AWS_LC_SYS_STATIC
    /// env var). Falls back to static if available, then dynamic.
    fn detect_lib_type(lib_dir: &Path, prefix: &Option<String>) -> Result<OutputLibType, String> {
        let crypto_name = match prefix {
            Some(p) => format!("{}_crypto", p),
            None => "crypto".to_string(),
        };

        let static_exists = Self::find_static_lib(lib_dir, &crypto_name).is_some();
        let dynamic_exists = Self::find_dynamic_lib(lib_dir, &crypto_name).is_some();

        // Get user's preference (respects AWS_LC_SYS_STATIC env var)
        let preferred = OutputLibType::default();

        match (static_exists, dynamic_exists, preferred) {
            // User explicitly wants static and it exists
            (true, _, OutputLibType::Static) => Ok(OutputLibType::Static),
            // User explicitly wants dynamic and it exists
            (_, true, OutputLibType::Dynamic) => Ok(OutputLibType::Dynamic),
            // User wants static but only dynamic exists
            (false, true, OutputLibType::Static) => {
                emit_warning(
                    "Static library requested but not found, falling back to dynamic linking",
                );
                Ok(OutputLibType::Dynamic)
            }
            // User wants dynamic but only static exists
            (true, false, OutputLibType::Dynamic) => {
                emit_warning(
                    "Dynamic library requested but not found, falling back to static linking",
                );
                Ok(OutputLibType::Static)
            }
            // Neither library found
            (false, false, _) => {
                let expected = match prefix {
                    Some(p) => format!("lib{p}_crypto.a, lib{p}_crypto.so, {p}_crypto.lib, etc."),
                    None => "libcrypto.a, libcrypto.so, crypto.lib, etc.".to_string(),
                };
                Err(format!(
                    "No crypto library found in {}\nExpected: {}",
                    lib_dir.display(),
                    expected
                ))
            }
        }
    }

    /// Finds a static library file in the given directory.
    fn find_static_lib(lib_dir: &Path, name: &str) -> Option<PathBuf> {
        let candidates = match (target_os().as_str(), target_env().as_str()) {
            ("windows", "msvc") => vec![format!("{}.lib", name)],
            _ => vec![format!("lib{}.a", name)],
        };
        candidates
            .into_iter()
            .map(|c| lib_dir.join(c))
            .find(|p| p.exists())
    }

    /// Finds a dynamic library file in the given directory.
    fn find_dynamic_lib(lib_dir: &Path, name: &str) -> Option<PathBuf> {
        let candidates = match target_os().as_str() {
            "windows" => vec![format!("{}.dll", name), format!("lib{}.dll.a", name)],
            "macos" | "ios" | "tvos" => vec![format!("lib{}.dylib", name)],
            _ => vec![format!("lib{}.so", name)],
        };
        candidates
            .into_iter()
            .map(|c| lib_dir.join(c))
            .find(|p| p.exists())
    }

    /// Verifies that a required library exists.
    fn verify_library_exists(&self, base_name: &str) -> Result<(), String> {
        let name = match &self.prefix {
            Some(p) => format!("{}_{}", p, base_name),
            None => base_name.to_string(),
        };

        let found = match self.output_lib_type {
            OutputLibType::Static => Self::find_static_lib(&self.lib_dir, &name).is_some(),
            OutputLibType::Dynamic => Self::find_dynamic_lib(&self.lib_dir, &name).is_some(),
        };

        if !found {
            return Err(format!(
                "Required library '{}' not found in {}",
                name,
                self.lib_dir.display()
            ));
        }
        Ok(())
    }
}

impl crate::Builder for PrebuiltBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        self.verify_library_exists("crypto")?;
        if cfg!(feature = "ssl") {
            self.verify_library_exists("ssl")?;
        }
        Ok(())
    }

    fn build(&self) -> Result<(), String> {
        emit_warning(format!(
            "Using prebuilt AWS-LC from: {}",
            self.install_dir.display()
        ));

        println!("cargo:rustc-link-search=native={}", self.lib_dir.display());

        println!(
            "cargo:rustc-link-lib={}={}",
            self.output_lib_type.rust_lib_type(),
            self.crypto_lib_name()
        );

        if cfg!(feature = "ssl") {
            println!(
                "cargo:rustc-link-lib={}={}",
                self.output_lib_type.rust_lib_type(),
                self.ssl_lib_name()
            );
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Prebuilt"
    }
}

// =============================================================================
// Binding Management Functions
// =============================================================================

/// Locates pre-generated bindings, checking explicit override first, then conventional location.
pub(crate) fn find_prebuilt_bindings(
    config: &crate::prebuilt_aws_lc::Config,
) -> Option<std::path::PathBuf> {
    // 1. Explicit override takes priority
    if let Some(ref path) = config.bindings_override {
        if path.exists() {
            return Some(path.clone());
        }
        // Warn if env var is set but file doesn't exist
        emit_warning(format!(
            "WARNING: {} points to non-existent file: {}",
            env_var_crate_target("PREBUILT_BINDINGS"),
            path.display()
        ));
    }

    // 2. Check conventional location: $INSTALL_DIR/share/rust/aws_lc_bindings.rs
    let conventional = config
        .install_dir
        .join("share")
        .join("rust")
        .join("aws_lc_bindings.rs");
    if conventional.exists() {
        return Some(conventional);
    }

    None
}

/// Handles bindings for prebuilt AWS-LC mode.
///
/// This function attempts to locate or generate bindings in the following order:
/// 1. Use explicit override from PREBUILT_BINDINGS env var
/// 2. Use conventional location at $INSTALL_DIR/share/rust/aws_lc_bindings.rs
/// 3. Generate via internal bindgen (if feature enabled)
/// 4. Generate via external bindgen-cli
pub(crate) fn handle_prebuilt_bindings(
    config: &crate::prebuilt_aws_lc::Config,
    include_dir: &Path,
    manifest_dir: &Path,
    out_dir: &Path,
    prefix: &Option<String>,
) -> Result<(), String> {
    let dest = out_dir.join("bindings.rs");

    // Try to find existing bindings first (override or conventional location)
    if let Some(bindings_path) = find_prebuilt_bindings(config) {
        std::fs::copy(&bindings_path, &dest).map_err(|e| {
            format!(
                "Failed to copy bindings from {}: {}",
                bindings_path.display(),
                e
            )
        })?;
        emit_warning(format!(
            "Using prebuilt bindings from: {}",
            bindings_path.display()
        ));
        return Ok(());
    }

    // No existing bindings found - generate via bindgen
    generate_bindings_with_bindgen(include_dir, manifest_dir, out_dir, prefix)
}

/// Generates bindings using bindgen (internal or external).
fn generate_bindings_with_bindgen(
    include_dir: &Path,
    manifest_dir: &Path,
    out_dir: &Path,
    prefix: &Option<String>,
) -> Result<(), String> {
    // Try internal bindgen first (when bindgen crate is available)
    #[cfg(any(feature = "bindgen", feature = "fips"))]
    {
        if crate::internal_bindgen_supported()
            && !crate::is_external_bindgen_requested().unwrap_or(false)
        {
            emit_warning(format!(
                "Generating bindings for prebuilt AWS-LC (prefix: {:?})",
                prefix.as_deref().unwrap_or("none")
            ));

            let options = crate::BindingOptions {
                build_prefix: prefix.clone(),
                include_ssl: cfg!(feature = "ssl"),
                disable_prelude: true,
                prebuilt_include_dir: Some(include_dir.to_path_buf()),
            };

            let bindings = crate::sys_bindgen::generate_bindings(manifest_dir, &options);
            let bindings_path = out_dir.join("bindings.rs");
            bindings
                .write_to_file(&bindings_path)
                .map_err(|e| format!("Failed to write bindings: {}", e))?;

            return Ok(());
        }
    }

    // Try external bindgen-cli as fallback
    if try_external_bindgen(include_dir, manifest_dir, out_dir, prefix)? {
        return Ok(());
    }

    // Neither internal nor external bindgen available
    let bindings_env_var = env_var_crate_target("PREBUILT_BINDINGS");
    Err(format!(
        "No pre-generated bindings found and bindgen is not available.\n\n\
         To resolve this, either:\n\
         1. Install AWS-LC with Rust bindings (share/rust/aws_lc_bindings.rs), or\n\
         2. Set {} to point to a bindings file, or\n\
         3. Enable the 'bindgen' feature: cargo build --features bindgen, or\n\
         4. Install bindgen-cli: cargo install bindgen-cli",
        bindings_env_var
    ))
}

/// Attempts to generate bindings using external bindgen-cli.
///
/// Returns `Ok(true)` if successful, `Ok(false)` if bindgen-cli not available,
/// or `Err` if bindgen-cli was found but generation failed.
fn try_external_bindgen(
    include_dir: &Path,
    manifest_dir: &Path,
    out_dir: &Path,
    prefix: &Option<String>,
) -> Result<bool, String> {
    // Check if external bindgen is available by testing the command
    if !test_bindgen_cli_command() {
        return Ok(false);
    }

    emit_warning(format!(
        "Generating bindings for prebuilt AWS-LC via bindgen-cli (prefix: {:?})",
        prefix.as_deref().unwrap_or("none")
    ));

    let options = crate::BindingOptions {
        build_prefix: prefix.clone(),
        include_ssl: cfg!(feature = "ssl"),
        disable_prelude: true,
        prebuilt_include_dir: Some(include_dir.to_path_buf()),
    };

    let bindings_path = out_dir.join("bindings.rs");

    // Use existing invoke_external_bindgen infrastructure
    crate::invoke_external_bindgen(manifest_dir, &options, &bindings_path)
        .map_err(|e| format!("External bindgen failed: {}", e))?;

    Ok(true)
}

/// Tests if bindgen-cli is available in PATH.
fn test_bindgen_cli_command() -> bool {
    use std::ffi::OsStr;
    crate::execute_command(OsStr::new("bindgen"), &[OsStr::new("--version")]).status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Mutex to serialize tests that modify environment variables.
    /// Environment variables are process-global state, so tests that modify them
    /// must not run in parallel.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Sets up Cargo environment variables needed for tests that call target_os(), target_env(), etc.
    /// Returns a guard that restores the original environment when dropped.
    /// The guard also holds a mutex lock to prevent parallel test execution.
    fn setup_test_env() -> impl Drop {
        struct EnvGuard<'a> {
            vars: Vec<(String, Option<String>)>,
            _lock: MutexGuard<'a, ()>,
        }
        impl Drop for EnvGuard<'_> {
            fn drop(&mut self) {
                for (key, original) in &self.vars {
                    match original {
                        Some(val) => std::env::set_var(key, val),
                        None => std::env::remove_var(key),
                    }
                }
                // _lock is dropped here, releasing the mutex
            }
        }

        // Acquire lock first to ensure exclusive access to env vars.
        // This serializes tests that modify environment variables across threads.
        //
        // WARNING: Do not call setup_test_env() multiple times in the same scope/thread.
        // std::sync::Mutex is not reentrant, so a second call from the same thread will
        // deadlock waiting for the lock held by the first call.
        let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let vars_to_set = [
            ("CARGO_CFG_TARGET_OS", std::env::consts::OS),
            ("CARGO_CFG_TARGET_ENV", ""),
            ("CARGO_CFG_TARGET_FEATURE", ""),
            ("CARGO_CFG_TARGET_ARCH", std::env::consts::ARCH),
            ("TARGET", std::env::consts::ARCH), // Simplified target for testing
            ("CARGO_PKG_NAME", "aws-lc-sys"),   // Required by crate_name()
        ];

        let mut guard = EnvGuard {
            vars: Vec::new(),
            _lock: lock,
        };
        for (key, val) in vars_to_set {
            guard.vars.push((key.to_string(), std::env::var(key).ok()));
            std::env::set_var(key, val);
        }
        guard
    }

    // -------------------------------------------------------------------------
    // PrebuiltBuilder library name tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_crypto_lib_name_no_prefix() {
        // Create a minimal valid installation for testing
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

        let builder = PrebuiltBuilder {
            install_dir: temp.path().to_path_buf(),
            include_dir: temp.path().join("include"),
            lib_dir,
            output_lib_type: OutputLibType::Static,
            prefix: None,
        };

        assert_eq!(builder.crypto_lib_name(), "crypto");
        assert_eq!(builder.ssl_lib_name(), "ssl");
    }

    #[test]
    fn test_crypto_lib_name_with_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("libmy_prefix_crypto.a"), b"").unwrap();

        let builder = PrebuiltBuilder {
            install_dir: temp.path().to_path_buf(),
            include_dir: temp.path().join("include"),
            lib_dir,
            output_lib_type: OutputLibType::Static,
            prefix: Some("my_prefix".to_string()),
        };

        assert_eq!(builder.crypto_lib_name(), "my_prefix_crypto");
        assert_eq!(builder.ssl_lib_name(), "my_prefix_ssl");
    }

    // -------------------------------------------------------------------------
    // Library detection tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_find_static_lib_unix() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path();
        std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

        let result = PrebuiltBuilder::find_static_lib(lib_dir, "crypto");
        // Result depends on target platform, but should find the file on Unix-like systems
        #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
        assert!(result.is_some());
    }

    #[test]
    fn test_find_dynamic_lib_unix() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path();
        std::fs::write(lib_dir.join("libcrypto.so"), b"").unwrap();

        let result = PrebuiltBuilder::find_dynamic_lib(lib_dir, "crypto");
        // Result depends on target platform
        #[cfg(target_os = "linux")]
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_lib_type_static_preferred() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path();
        // Create both static and dynamic libs
        std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();
        std::fs::write(lib_dir.join("libcrypto.so"), b"").unwrap();

        let result = PrebuiltBuilder::detect_lib_type(lib_dir, &None);
        // When both exist, behavior depends on is_crt_static()
        #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_detect_lib_type_no_library() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path();
        // No libraries created

        let result = PrebuiltBuilder::detect_lib_type(lib_dir, &None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No crypto library found"));
    }

    #[test]
    fn test_detect_lib_type_prefixed() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path();
        std::fs::write(lib_dir.join("libmy_prefix_crypto.a"), b"").unwrap();

        let prefix = Some("my_prefix".to_string());
        let result = PrebuiltBuilder::detect_lib_type(lib_dir, &prefix);

        #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------------
    // PrebuiltBuilder::new tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_prebuilt_builder_new_lib64() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let include_dir = temp.path().join("include");
        let lib64_dir = temp.path().join("lib64");
        std::fs::create_dir_all(&include_dir).unwrap();
        std::fs::create_dir_all(&lib64_dir).unwrap();
        std::fs::write(lib64_dir.join("libcrypto.a"), b"").unwrap();

        let result = PrebuiltBuilder::new(temp.path().to_path_buf(), None);

        #[cfg(target_pointer_width = "64")]
        {
            // On 64-bit systems, should prefer lib64
            #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
            {
                assert!(result.is_ok());
                let builder = result.unwrap();
                assert!(builder.lib_dir().ends_with("lib64"));
            }
        }
    }

    #[test]
    fn test_prebuilt_builder_new_missing_lib_dir() {
        // This test doesn't need env setup as it fails before calling detect_lib_type
        let temp = tempfile::tempdir().unwrap();
        let include_dir = temp.path().join("include");
        std::fs::create_dir_all(&include_dir).unwrap();
        // No lib or lib64 directory

        let result = PrebuiltBuilder::new(temp.path().to_path_buf(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Library directory not found"));
    }

    #[test]
    fn test_prebuilt_builder_verify_library_exists() {
        let _env = setup_test_env();
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

        let builder = PrebuiltBuilder {
            install_dir: temp.path().to_path_buf(),
            include_dir: temp.path().join("include"),
            lib_dir,
            output_lib_type: OutputLibType::Static,
            prefix: None,
        };

        // crypto should be found
        #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
        assert!(builder.verify_library_exists("crypto").is_ok());

        // ssl should not be found
        #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
        assert!(builder.verify_library_exists("ssl").is_err());
    }

    #[test]
    fn test_prefix_accessor() {
        let temp = tempfile::tempdir().unwrap();
        let lib_dir = temp.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();

        let builder_no_prefix = PrebuiltBuilder {
            install_dir: temp.path().to_path_buf(),
            include_dir: temp.path().join("include"),
            lib_dir: lib_dir.clone(),
            output_lib_type: OutputLibType::Static,
            prefix: None,
        };
        assert_eq!(builder_no_prefix.prefix(), None);

        let builder_with_prefix = PrebuiltBuilder {
            install_dir: temp.path().to_path_buf(),
            include_dir: temp.path().join("include"),
            lib_dir,
            output_lib_type: OutputLibType::Static,
            prefix: Some("test_prefix".to_string()),
        };
        assert_eq!(builder_with_prefix.prefix(), Some("test_prefix"));
    }
}
