// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use super::*;
use std::io::Write;
use std::sync::{Mutex, MutexGuard};

/// Mutex to serialize tests that modify environment variables.
/// Environment variables are process-global state, so tests that modify them
/// must not run in parallel.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Sets up Cargo environment variables needed for tests that call target_os(), target_env(), etc.
/// Returns a guard that restores the original environment when dropped.
/// The guard also holds a mutex lock to prevent parallel test execution.
fn setup_test_env() -> impl Drop {
    setup_test_env_with_target(std::env::consts::OS, "")
}

/// Like `setup_test_env`, but forces specific `CARGO_CFG_TARGET_OS` and
/// `CARGO_CFG_TARGET_ENV` values so tests can exercise platform-specific
/// resolution logic (notably MSVC) on any host.
fn setup_test_env_with_target(os: &str, env: &str) -> impl Drop {
    struct EnvGuard<'a> {
        vars: Vec<(String, Option<String>)>,
        _lock: MutexGuard<'a, ()>,
    }
    impl Drop for EnvGuard<'_> {
        fn drop(&mut self) {
            for (key, original) in &self.vars {
                match original {
                    Some(val) => unsafe { std::env::set_var(key, val) },
                    None => unsafe { std::env::remove_var(key) },
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
        ("CARGO_CFG_TARGET_OS", os),
        ("CARGO_CFG_TARGET_ENV", env),
        ("CARGO_CFG_TARGET_FEATURE", ""),
        ("CARGO_CFG_TARGET_ARCH", std::env::consts::ARCH),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
        ("TARGET", std::env::consts::ARCH), // Simplified target for testing
        ("CARGO_PKG_NAME", "aws-lc-sys"),   // Required by crate_name()
    ];

    let mut guard = EnvGuard {
        vars: Vec::new(),
        _lock: lock,
    };
    for (key, val) in vars_to_set {
        guard.vars.push((key.to_string(), std::env::var(key).ok()));
        unsafe { std::env::set_var(key, val) };
    }
    guard
}

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
// detect_prefix tests
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
fn test_detect_prefix_with_trailing_inline_comment() {
    // A real header may have an inline comment after the prefix value.
    // The parser's 3-token check (`parts[2]`) should still yield the
    // prefix name without picking up the comment.
    let temp_dir = tempfile::tempdir().unwrap();
    let openssl_dir = temp_dir.path().join("openssl");
    std::fs::create_dir_all(&openssl_dir).unwrap();

    let header_path = openssl_dir.join("boringssl_prefix_symbols.h");
    let mut file = std::fs::File::create(&header_path).unwrap();
    writeln!(
        file,
        "#define BORINGSSL_PREFIX my_custom_prefix /* inline comment */"
    )
    .unwrap();

    let prefix = detect_prefix(temp_dir.path());
    assert_eq!(prefix, Some("my_custom_prefix".to_string()));
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
fn test_validate_and_extract_version_ignores_comment_false_match() {
    let temp_dir = tempfile::tempdir().unwrap();
    let openssl_dir = temp_dir.path().join("openssl");
    std::fs::create_dir_all(&openssl_dir).unwrap();

    let base_h = openssl_dir.join("base.h");
    let mut file = std::fs::File::create(&base_h).unwrap();
    writeln!(file, "#define OPENSSL_IS_AWSLC 1").unwrap();
    writeln!(
        file,
        "// Don't bump AWSLC_VERSION_NUMBER_STRING \"by hand\""
    )
    .unwrap();
    writeln!(file, "#define AWSLC_VERSION_NUMBER_STRING \"1.73.0\"").unwrap();

    let version = validate_and_extract_version(temp_dir.path()).unwrap();
    assert_eq!(
        version, "1.73.0",
        "parser must skip the comment and read the actual #define"
    );
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
    writeln!(file, "#endif").unwrap();

    let result = validate_and_extract_version(temp_dir.path());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Could not find AWSLC_VERSION_NUMBER_STRING"));
}

// -------------------------------------------------------------------------
// Library resolution tests
// -------------------------------------------------------------------------

#[test]
fn test_resolve_crypto_vanilla_static() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

    #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
    {
        let (lib_type, name, path) = SystemLibrary::resolve_crypto_library(lib_dir, None).unwrap();
        assert_eq!(name, "crypto");
        assert_eq!(path, lib_dir.join("libcrypto.a"));
        assert!(matches!(lib_type, OutputLibType::Static));
    }
}

#[test]
fn test_resolve_crypto_awslc_suffix_only() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto-awslc.a"), b"").unwrap();

    #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
    {
        let (_, name, path) = SystemLibrary::resolve_crypto_library(lib_dir, None).unwrap();
        assert_eq!(name, "crypto-awslc");
        assert_eq!(path, lib_dir.join("libcrypto-awslc.a"));
    }
}

#[test]
fn test_resolve_crypto_prefers_plain_over_awslc() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();
    std::fs::write(lib_dir.join("libcrypto-awslc.a"), b"").unwrap();

    #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
    {
        let (_, name, _) = SystemLibrary::resolve_crypto_library(lib_dir, None).unwrap();
        assert_eq!(name, "crypto");
    }
}

#[test]
fn test_resolve_crypto_ignores_symbol_prefixed_filename() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libfoo_crypto.a"), b"").unwrap();

    let result = SystemLibrary::resolve_crypto_library(lib_dir, None);
    assert!(matches!(result, Err(ResolveCryptoLibErr::NotFound)));
}

#[test]
fn test_resolve_crypto_no_library() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();

    let result = SystemLibrary::resolve_crypto_library(lib_dir, None);
    assert!(matches!(result, Err(ResolveCryptoLibErr::NotFound)));
}

// -------------------------------------------------------------------------
// Explicit static/dynamic preference (AWS_LC_SYS_STATIC=1 / =0).
// -------------------------------------------------------------------------

#[test]
#[cfg(not(all(target_os = "windows", target_env = "msvc")))]
fn test_resolve_crypto_static_required_but_only_dynamic_present() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    std::fs::write(lib_dir.join("libcrypto.so"), b"").unwrap();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    std::fs::write(lib_dir.join("libcrypto.dylib"), b"").unwrap();

    let result = SystemLibrary::resolve_crypto_library(lib_dir, Some(OutputLibType::Static));
    assert!(matches!(
        result,
        Err(ResolveCryptoLibErr::OnlyDynamicButStaticRequired)
    ));
}

#[test]
#[cfg(not(all(target_os = "windows", target_env = "msvc")))]
fn test_resolve_crypto_dynamic_required_but_only_static_present() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

    let result = SystemLibrary::resolve_crypto_library(lib_dir, Some(OutputLibType::Dynamic));
    assert!(matches!(
        result,
        Err(ResolveCryptoLibErr::OnlyStaticButDynamicRequired)
    ));
}

#[test]
#[cfg(not(all(target_os = "windows", target_env = "msvc")))]
fn test_resolve_crypto_static_required_and_present() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    std::fs::write(lib_dir.join("libcrypto.so"), b"").unwrap();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    std::fs::write(lib_dir.join("libcrypto.dylib"), b"").unwrap();

    let (lib_type, _, _) =
        SystemLibrary::resolve_crypto_library(lib_dir, Some(OutputLibType::Static)).unwrap();
    assert!(matches!(lib_type, OutputLibType::Static));
}

#[test]
#[cfg(not(all(target_os = "windows", target_env = "msvc")))]
fn test_resolve_crypto_dynamic_required_and_present() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    std::fs::write(lib_dir.join("libcrypto.so"), b"").unwrap();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    std::fs::write(lib_dir.join("libcrypto.dylib"), b"").unwrap();

    let (lib_type, _, _) =
        SystemLibrary::resolve_crypto_library(lib_dir, Some(OutputLibType::Dynamic)).unwrap();
    assert!(matches!(lib_type, OutputLibType::Dynamic));
}

#[test]
fn test_find_static_lib_unix() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

    let result = find_lib_file(lib_dir, "crypto", OutputLibType::Static);
    #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
    assert!(result.is_some());
}

#[test]
fn test_find_dynamic_lib_unix() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    let lib_dir = temp.path();
    std::fs::write(lib_dir.join("libcrypto.so"), b"").unwrap();

    let result = find_lib_file(lib_dir, "crypto", OutputLibType::Dynamic);
    #[cfg(target_os = "linux")]
    assert!(result.is_some());
}

// -------------------------------------------------------------------------
// MSVC import-library vs static-archive disambiguation
// -------------------------------------------------------------------------

#[test]
fn test_msvc_static_archive_without_sibling_dll() {
    let _env = setup_test_env_with_target("windows", "msvc");
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path();
    let lib_dir = prefix.join("lib");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::write(lib_dir.join("crypto.lib"), b"").unwrap();

    assert_eq!(
        find_lib_file(&lib_dir, "crypto", OutputLibType::Static),
        Some(lib_dir.join("crypto.lib")),
    );
    assert_eq!(
        find_lib_file(&lib_dir, "crypto", OutputLibType::Dynamic),
        None,
    );
}

#[test]
fn test_msvc_import_library_with_sibling_dll() {
    let _env = setup_test_env_with_target("windows", "msvc");
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path();
    let lib_dir = prefix.join("lib");
    let bin_dir = prefix.join("bin");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(lib_dir.join("crypto.lib"), b"").unwrap();
    std::fs::write(bin_dir.join("crypto.dll"), b"").unwrap();

    assert_eq!(
        find_lib_file(&lib_dir, "crypto", OutputLibType::Static),
        None,
    );
    assert_eq!(
        find_lib_file(&lib_dir, "crypto", OutputLibType::Dynamic),
        Some(lib_dir.join("crypto.lib")),
    );
}

#[test]
fn test_msvc_resolve_shared_install_honors_dynamic_preference() {
    let _env = setup_test_env_with_target("windows", "msvc");
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path();
    let lib_dir = prefix.join("lib");
    let bin_dir = prefix.join("bin");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(lib_dir.join("crypto.lib"), b"").unwrap();
    std::fs::write(bin_dir.join("crypto.dll"), b"").unwrap();

    let (lib_type, name, path) = SystemLibrary::resolve_crypto_library(&lib_dir, None).unwrap();
    assert!(matches!(lib_type, OutputLibType::Dynamic));
    assert_eq!(name, "crypto");
    assert_eq!(path, lib_dir.join("crypto.lib"));
}

// -------------------------------------------------------------------------
// SystemLibrary::resolve tests
// -------------------------------------------------------------------------

fn setup_valid_include(base: &Path) -> PathBuf {
    let include_dir = base.join("include");
    let openssl_dir = include_dir.join("openssl");
    std::fs::create_dir_all(&openssl_dir).unwrap();
    std::fs::write(
        openssl_dir.join("base.h"),
        "#define OPENSSL_IS_AWSLC\n#define AWSLC_VERSION_NUMBER_STRING \"99.0.0\"\n",
    )
    .unwrap();
    include_dir
}

fn test_config(install_dir: &Path) -> Config {
    Config {
        install_dir: install_dir.to_path_buf(),
        bindings_override: None,
        skip_version_check: true,
    }
}

#[test]
fn test_system_library_new_lib64() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    setup_valid_include(temp.path());
    let lib64_dir = temp.path().join("lib64");
    std::fs::create_dir_all(&lib64_dir).unwrap();
    std::fs::write(lib64_dir.join("libcrypto.a"), b"").unwrap();
    #[cfg(feature = "ssl")]
    std::fs::write(lib64_dir.join("libssl.a"), b"").unwrap();

    let config = test_config(temp.path());
    let result = SystemLibrary::resolve(&config, temp.path());

    #[cfg(target_pointer_width = "64")]
    {
        #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
        {
            assert!(result.is_ok(), "{:?}", result.err());
            let builder = result.unwrap();
            assert!(builder.lib_dir.ends_with("lib64"));
            assert_eq!(builder.crypto_lib_name(), "crypto");
        }
    }
}

#[test]
fn test_system_library_new_missing_lib_dir() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    setup_valid_include(temp.path());

    let config = test_config(temp.path());
    let result = SystemLibrary::resolve(&config, temp.path());
    match result {
        Err(msg) => assert!(msg.contains("Library directory not found")),
        Ok(_) => panic!("expected Err for missing lib dir"),
    }
}

#[test]
fn test_system_library_new_missing_crypto() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    setup_valid_include(temp.path());
    let lib_dir = temp.path().join("lib");
    std::fs::create_dir_all(&lib_dir).unwrap();

    let config = test_config(temp.path());
    let result = SystemLibrary::resolve(&config, temp.path());
    match result {
        Err(msg) => assert!(msg.contains("No crypto library found")),
        Ok(_) => panic!("expected Err when no crypto library is present"),
    }
}

#[test]
#[cfg(feature = "ssl")]
fn test_system_library_new_missing_ssl_under_feature() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    setup_valid_include(temp.path());
    let lib_dir = temp.path().join("lib");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

    let config = test_config(temp.path());
    let result = SystemLibrary::resolve(&config, temp.path());
    match result {
        Err(msg) => assert!(msg.contains("No ssl library found")),
        Ok(_) => panic!("expected Err when ssl feature enabled but libssl absent"),
    }
}

#[test]
#[cfg(not(feature = "ssl"))]
fn test_system_library_new_no_ssl_when_feature_disabled() {
    let _env = setup_test_env();
    let temp = tempfile::tempdir().unwrap();
    setup_valid_include(temp.path());
    let lib_dir = temp.path().join("lib");
    std::fs::create_dir_all(&lib_dir).unwrap();
    std::fs::write(lib_dir.join("libcrypto.a"), b"").unwrap();

    #[cfg(not(all(target_os = "windows", target_env = "msvc")))]
    {
        let config = test_config(temp.path());
        let builder = SystemLibrary::resolve(&config, temp.path()).unwrap();
        assert_eq!(builder.crypto_lib_name(), "crypto");
        assert_eq!(builder.ssl_lib_name(), None);
    }
}
