// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Support for linking against a system-installed AWS-LC library.

use crate::{
    emit_rustc_cfg, emit_warning, env_crate_var_to_bool, get_aws_lc_include_path, is_fips_build,
    optional_env_crate_target, out_dir, target_env, target_os, OutputLibType, OSSL_CONF_DEFINES,
};
use std::path::{Path, PathBuf};

/// Configuration for system-installed AWS-LC linking mode.
pub(crate) struct Config {
    /// Path to the AWS-LC installation directory
    pub install_dir: PathBuf,
    /// Optional path to pre-generated Rust bindings file (from `SYSTEM_BINDINGS` env var)
    pub bindings_override: Option<PathBuf>,
    /// Whether to skip version compatibility check
    pub skip_version_check: bool,
}

/// Formats the full environment variable name for the current crate + given
/// suffix (e.g. `"SYSTEM_DIR"` → `"AWS_LC_SYS_SYSTEM_DIR"`).
/// Does NOT read the variable — use `optional_env_crate_target` for that.
fn crate_env_var_name(name: &str) -> String {
    let crate_name = crate::crate_name().to_uppercase().replace('-', "_");
    format!("{crate_name}_{name}")
}

/// Returns the system-library configuration if one was requested via
/// `<crate>_SYSTEM_DIR`, or `None` otherwise.
pub(crate) fn get_config() -> Option<Config> {
    let install_dir = match optional_env_crate_target("SYSTEM_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => return None,
    };

    let bindings_override = optional_env_crate_target("SYSTEM_BINDINGS")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);

    let skip_version_check = optional_env_crate_target("SYSTEM_SKIP_VERSION_CHECK")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

    Some(Config {
        install_dir,
        bindings_override,
        skip_version_check,
    })
}

fn detect_prefix(include_dir: &Path) -> Option<String> {
    let prefix_header = include_dir
        .join("openssl")
        .join("boringssl_prefix_symbols.h");

    let content = std::fs::read_to_string(&prefix_header).ok()?;

    // Look for: #define BORINGSSL_PREFIX <prefix_name>
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "#define" && parts[1] == "BORINGSSL_PREFIX" {
            return Some(parts[2].to_string());
        }
    }

    None
}

/// Candidate bare library names for libcrypto, in preference order.
///
/// `crypto` covers plain AWS-LC installs (the common case). `crypto-awslc`
/// covers installs produced with `ENABLE_DIST_PKG=ON` or a non-Apple Unix
/// shared build that disables `ENABLE_PRE_SONAME_BUILD`, where AWS-LC's
/// `CMake` appends the `-awslc` SONAME suffix to the library file name.
/// Typically those installs also ship `libcrypto.{so,a}` symlinks via the
/// OpenSSL-shim, but not when `ENABLE_DIST_PKG_OPENSSL_SHIM=OFF`.
///
/// Note: the `BORINGSSL_PREFIX` symbol-prefixing feature does *not* rename
/// the library file in upstream AWS-LC's build — it only renames the
/// symbols inside. Do not try to apply the symbol prefix here.
const CRYPTO_LIB_CANDIDATES: &[&str] = &["crypto", "crypto-awslc"];

/// Candidate bare library names for libssl, in preference order.
/// See `CRYPTO_LIB_CANDIDATES` for the rationale.
const SSL_LIB_CANDIDATES: &[&str] = &["ssl", "ssl-awslc"];

/// Result of `resolve_crypto_library`. The two `Only*Required` variants are
/// only produced when the user explicitly set `AWS_LC_SYS_STATIC` (truthy or
/// falsy) and we cannot honor that preference because only the other form is
/// installed; in that case the build fails rather than silently using the
/// wrong linkage.
#[cfg_attr(test, derive(Debug))]
enum ResolveCryptoLibErr {
    NotFound,
    OnlyDynamicButStaticRequired,
    OnlyStaticButDynamicRequired,
}

/// Returns `Some(_)` only when the user explicitly set `AWS_LC_SYS_STATIC`
/// (or `AWS_LC_FIPS_SYS_STATIC` for the FIPS crate). `None` means "unset";
/// callers may pick a default and silently fall back to whichever form is
/// available. This distinction matters: when the user is explicit about
/// linkage, we treat it as a hard requirement.
fn explicit_lib_type_preference() -> Option<OutputLibType> {
    env_crate_var_to_bool("STATIC").map(|stc| {
        if stc {
            OutputLibType::Static
        } else {
            OutputLibType::Dynamic
        }
    })
}

fn validate_and_extract_version(include_dir: &Path) -> Result<String, String> {
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

    // Extract version: look for `#define AWSLC_VERSION_NUMBER_STRING "X.Y.Z"`.
    // Match on the first whitespace-separated tokens rather than a bare
    // `contains`, so that an unrelated line that merely mentions the macro
    // name (e.g. a comment) cannot false-match.
    for line in content.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("#define") {
            continue;
        }
        if tokens.next() != Some("AWSLC_VERSION_NUMBER_STRING") {
            continue;
        }
        if let Some(value) = tokens.next() {
            let trimmed = value.trim_matches('"');
            if trimmed != value && !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
        return Err(format!(
            "Malformed AWSLC_VERSION_NUMBER_STRING in {}",
            base_h.display()
        ));
    }

    Err(format!(
        "Could not find AWSLC_VERSION_NUMBER_STRING in {}.\n\
         The file appears to be AWS-LC headers but version could not be determined.",
        base_h.display()
    ))
}

fn parse_version(version_str: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("Invalid version format: {version_str}"));
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

fn version_compatible(installed: &str, required: &str) -> Result<bool, String> {
    let (i_maj, i_min, i_pat) = parse_version(installed)?;
    let (r_maj, r_min, r_pat) = parse_version(required)?;

    Ok((i_maj, i_min, i_pat) >= (r_maj, r_min, r_pat))
}

fn get_bundled_awslc_version(manifest_dir: &Path) -> (String, PathBuf) {
    let bundled_include = get_aws_lc_include_path(manifest_dir);
    let base_h = bundled_include.join("openssl").join("base.h");
    let version = validate_and_extract_version(&bundled_include).unwrap_or_else(|e| {
        panic!(
            "Failed to determine bundled AWS-LC version from {}: {e}\n\
             The system-library linking path reads the bundled AWS-LC headers to enforce\n\
             a minimum version. If the git submodule is not initialized, either run\n\
             `git submodule update --init --recursive` or set {}=1 to bypass.",
            bundled_include.display(),
            crate_env_var_name("SYSTEM_SKIP_VERSION_CHECK")
        )
    });
    (version, base_h)
}

/// A resolved system-installed AWS-LC library, ready for linking.
pub(crate) struct SystemLibrary {
    install_dir: PathBuf,
    include_dir: PathBuf,
    lib_dir: PathBuf,
    output_lib_type: OutputLibType,
    /// Detected symbol prefix (from `BORINGSSL_PREFIX`), if any.
    prefix: Option<String>,
    /// Resolved bare library name for libcrypto (e.g. `"crypto"` or
    /// `"crypto-awslc"`). Passed directly to `-l<name>`.
    crypto_lib_name: String,
    /// Full path to the resolved libcrypto file on disk. Cached at
    /// construction so downstream consumers (notably `rerun-if-changed`)
    /// don't re-probe the filesystem.
    crypto_lib_path: PathBuf,
    /// Resolved bare library name for libssl. `Some` only when the `ssl`
    /// feature is enabled; populated at construction time after the
    /// library has been located on disk.
    ssl_lib_name: Option<String>,
    /// Full path to the resolved libssl file on disk, when the `ssl`
    /// feature is enabled.
    ssl_lib_path: Option<PathBuf>,
    /// Optional path to pre-generated Rust bindings file (from `SYSTEM_BINDINGS` env var)
    bindings_override: Option<PathBuf>,
}

impl SystemLibrary {
    #[allow(clippy::too_many_lines)]
    fn resolve(config: &Config, manifest_dir: &Path) -> Result<Self, String> {
        let install_dir = &config.install_dir;
        let include_dir = install_dir.join("include");
        let install_dir_env_var = crate_env_var_name("SYSTEM_DIR");

        // 1. Verify include directory exists
        if !include_dir.exists() {
            return Err(format!(
                "Include directory not found: {}\n\
                 Verify {} points to a valid installation.",
                include_dir.display(),
                install_dir_env_var
            ));
        }

        // 2. Read base.h and validate AWS-LC headers + extract version
        let version = validate_and_extract_version(&include_dir)?;

        // 3. Check version compatibility
        if config.skip_version_check {
            emit_warning(format!(
                "Skipping AWS-LC version compatibility check (installed={version})."
            ));
        } else {
            let (required_version, bundled_base_h) = get_bundled_awslc_version(manifest_dir);
            println!("cargo:rerun-if-changed={}", bundled_base_h.display());
            let compatible = version_compatible(&version, &required_version)?;
            if !compatible {
                return Err(format!(
                    "AWS-LC version mismatch: installed {version} < required {required_version}.\n\
                     Please upgrade AWS-LC or unset {install_dir_env_var} to build from source.\n\
                     To bypass this check (not recommended), set {}=1",
                    crate_env_var_name("SYSTEM_SKIP_VERSION_CHECK")
                ));
            }
        }

        // 4. Detect symbol prefix
        let prefix = detect_prefix(&include_dir);

        emit_warning(format!(
            "System AWS-LC: version={}, prefix={:?}",
            version,
            prefix.as_deref().unwrap_or("none")
        ));

        // 5. Resolve lib directory
        let target_is_64bit = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH")
            .map(|w| w == "64")
            .unwrap_or(cfg!(target_pointer_width = "64"));
        let lib_dir = if install_dir.join("lib64").exists() && target_is_64bit {
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
                crate_env_var_name("SYSTEM_DIR")
            ));
        }

        // 6. Resolve crypto library
        let (output_lib_type, crypto_lib_name, crypto_lib_path) =
            Self::resolve_crypto_library(&lib_dir, explicit_lib_type_preference()).map_err(
                |e| match e {
                    ResolveCryptoLibErr::NotFound => format!(
                        "No crypto library found in {}\n\
                         Expected one of: {}",
                        lib_dir.display(),
                        expected_lib_filenames(CRYPTO_LIB_CANDIDATES, None)
                    ),
                    ResolveCryptoLibErr::OnlyDynamicButStaticRequired => format!(
                        "{var}=1 is set, but only a dynamic crypto library was found in {}.\n\
                         Expected one of: {}\n\
                         Provide a static archive at this location, or unset {var} to allow \
                         dynamic linking.",
                        lib_dir.display(),
                        expected_lib_filenames(CRYPTO_LIB_CANDIDATES, Some(OutputLibType::Static)),
                        var = crate_env_var_name("STATIC"),
                    ),
                    ResolveCryptoLibErr::OnlyStaticButDynamicRequired => format!(
                        "{var}=0 is set, but only a static crypto library was found in {}.\n\
                         Expected one of: {}\n\
                         Provide a shared library at this location, or unset {var} to allow \
                         static linking.",
                        lib_dir.display(),
                        expected_lib_filenames(CRYPTO_LIB_CANDIDATES, Some(OutputLibType::Dynamic)),
                        var = crate_env_var_name("STATIC"),
                    ),
                },
            )?;

        // 7. Resolve ssl library (if feature enabled)
        let (ssl_lib_name, ssl_lib_path) = if cfg!(feature = "ssl") {
            let (name, path) = find_candidate(&lib_dir, output_lib_type, SSL_LIB_CANDIDATES)
                .ok_or_else(|| {
                    format!(
                        "No ssl library found in {}\n\
                             Expected one of: {}",
                        lib_dir.display(),
                        expected_lib_filenames(SSL_LIB_CANDIDATES, None)
                    )
                })?;
            (Some(name), Some(path))
        } else {
            (None, None)
        };

        Ok(Self {
            install_dir: install_dir.clone(),
            include_dir,
            lib_dir,
            output_lib_type,
            prefix,
            crypto_lib_name,
            crypto_lib_path,
            ssl_lib_name,
            ssl_lib_path,
            bindings_override: config.bindings_override.clone(),
        })
    }

    fn include_dir(&self) -> &Path {
        &self.include_dir
    }

    fn library_file_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.crypto_lib_path.clone()];
        if let Some(ref ssl_path) = self.ssl_lib_path {
            paths.push(ssl_path.clone());
        }
        paths
    }

    fn crypto_lib_name(&self) -> &str {
        &self.crypto_lib_name
    }

    fn ssl_lib_name(&self) -> Option<&str> {
        self.ssl_lib_name.as_deref()
    }

    /// Resolves the crypto library by probing each candidate name against each
    /// lib type. When `explicit_pref` is `Some`, the user has set
    /// `AWS_LC_SYS_STATIC` explicitly and the requested form is required: if
    /// only the other form is present we return an error rather than silently
    /// falling back. When `explicit_pref` is `None`, we prefer the form picked
    /// by `OutputLibType::default()` but fall back to whichever form is
    /// available. Returns `(lib_type, link_name, path)` on success.
    fn resolve_crypto_library(
        lib_dir: &Path,
        explicit_pref: Option<OutputLibType>,
    ) -> Result<(OutputLibType, String, PathBuf), ResolveCryptoLibErr> {
        let preferred = explicit_pref.unwrap_or_default();

        // Try the preferred linkage form first.
        if let Some((name, path)) = find_candidate(lib_dir, preferred, CRYPTO_LIB_CANDIDATES) {
            return Ok((preferred, name, path));
        }

        // Preferred form not found. If the user was explicit, that's an error.
        if explicit_pref.is_some() {
            return match preferred {
                OutputLibType::Static => Err(ResolveCryptoLibErr::OnlyDynamicButStaticRequired),
                OutputLibType::Dynamic => Err(ResolveCryptoLibErr::OnlyStaticButDynamicRequired),
            };
        }

        // User didn't specify — try the other form as a fallback.
        let fallback = match preferred {
            OutputLibType::Static => OutputLibType::Dynamic,
            OutputLibType::Dynamic => OutputLibType::Static,
        };

        if let Some((name, path)) = find_candidate(lib_dir, fallback, CRYPTO_LIB_CANDIDATES) {
            let desc = match fallback {
                OutputLibType::Static => "static",
                OutputLibType::Dynamic => "dynamic",
            };
            emit_warning(format!(
                "Only {desc} crypto library found in system install; using {desc} linking."
            ));
            return Ok((fallback, name, path));
        }

        Err(ResolveCryptoLibErr::NotFound)
    }

    /// Links the system-installed AWS-LC: validates FIPS (if needed), resolves
    /// bindings, emits `cargo:rustc-link-*` directives, and publishes cargo
    /// metadata. This is the single entry point called from `main.rs`.
    pub(crate) fn link(config: &Config, manifest_dir: &Path) -> Result<(), String> {
        let lib = Self::resolve(config, manifest_dir)?;

        // FIPS validation is not yet supported for the system-library path.
        if is_fips_build() {
            return Err(format!(
                "System-library linking is not yet supported for FIPS builds.\n\
                 Unset {} to build aws-lc-fips-sys from source.",
                crate_env_var_name("SYSTEM_DIR"),
            ));
        }

        lib.resolve_bindings(manifest_dir)?;

        emit_rustc_cfg("use_bindgen_pregenerated");

        // Emit link directives
        emit_warning(format!(
            "Using system-installed AWS-LC from: {}",
            lib.install_dir.display()
        ));
        println!("cargo:rustc-link-search=native={}", lib.lib_dir.display());
        println!(
            "cargo:rustc-link-lib={}={}",
            lib.output_lib_type.rust_lib_type(),
            lib.crypto_lib_name
        );
        if let Some(ref ssl_name) = lib.ssl_lib_name {
            println!(
                "cargo:rustc-link-lib={}={}",
                lib.output_lib_type.rust_lib_type(),
                ssl_name
            );
        }

        // Cargo metadata
        println!("cargo:include={}", lib.include_dir().display());
        println!("cargo:libcrypto={}", lib.crypto_lib_name());
        if let Some(ssl_name) = lib.ssl_lib_name() {
            println!("cargo:libssl={ssl_name}");
        }
        println!("cargo:conf={}", OSSL_CONF_DEFINES.join(","));

        println!("cargo:rerun-if-changed=builder/");
        println!("cargo:rerun-if-changed={}", lib.include_dir().display());
        for lib_path in lib.library_file_paths() {
            println!("cargo:rerun-if-changed={}", lib_path.display());
        }
        for env_var in [
            "SYSTEM_DIR",
            "SYSTEM_BINDINGS",
            "SYSTEM_SKIP_VERSION_CHECK",
            "STATIC",
        ] {
            println!("cargo:rerun-if-env-changed={}", crate_env_var_name(env_var));
        }

        Ok(())
    }

    /// Resolves Rust bindings for the system library using a 4-level fallback:
    /// 1. Explicit override (`SYSTEM_BINDINGS` env var)
    /// 2. Conventional location (`share/rust/aws_lc_bindings.rs`)
    /// 3. Internal bindgen (when feature enabled)
    /// 4. External `bindgen-cli`
    fn resolve_bindings(&self, manifest_dir: &Path) -> Result<(), String> {
        let out_dir = out_dir();

        // 1. Pre-generated bindings (explicit override or conventional location)
        if let Some(bindings_path) = self.find_system_bindings()? {
            let dest = out_dir.join("bindings.rs");
            std::fs::copy(&bindings_path, &dest).map_err(|e| {
                format!(
                    "Failed to copy bindings from {}: {}",
                    bindings_path.display(),
                    e
                )
            })?;
            emit_warning(format!(
                "Using pre-generated bindings from: {}",
                bindings_path.display()
            ));
            return Ok(());
        }

        // 2. Internal bindgen (when the bindgen crate is available)
        #[cfg(any(feature = "bindgen", feature = "fips"))]
        {
            if crate::internal_bindgen_supported()
                && !crate::is_external_bindgen_requested().unwrap_or(false)
            {
                emit_warning(format!(
                    "Generating bindings for system-installed AWS-LC (prefix: {:?})",
                    self.prefix.as_deref().unwrap_or("none")
                ));

                let options = crate::BindingOptions {
                    build_prefix: self.prefix.clone(),
                    include_ssl: cfg!(feature = "ssl"),
                    disable_prelude: true,
                    external_include_dir: Some(self.include_dir.clone()),
                };

                let bindings = crate::sys_bindgen::generate_bindings(manifest_dir, &options);
                let bindings_path = out_dir.join("bindings.rs");
                bindings
                    .write_to_file(&bindings_path)
                    .map_err(|e| format!("Failed to write bindings: {e}"))?;

                return Ok(());
            }
        }

        // 3. External bindgen-cli as fallback
        if self.try_external_bindgen(manifest_dir) {
            return Ok(());
        }

        // 4. Nothing worked — guide the user
        let bindings_env_var = crate_env_var_name("SYSTEM_BINDINGS");
        Err(format!(
            "No pre-generated bindings found and bindgen is not available.\n\n\
             To resolve this, either:\n\
             1. Install AWS-LC with Rust bindings (share/rust/aws_lc_bindings.rs), or\n\
             2. Set {bindings_env_var} to point to a bindings file, or\n\
             3. Enable the 'bindgen' feature: cargo build --features bindgen, or\n\
             4. Install bindgen-cli: cargo install bindgen-cli"
        ))
    }

    /// Locates pre-generated bindings from the explicit override or conventional
    /// install location. Returns `Ok(None)` when neither is available.
    fn find_system_bindings(&self) -> Result<Option<PathBuf>, String> {
        // 1. Explicit override takes priority. A misconfigured path is a hard error
        // rather than a silent fall-through to bindgen, since the user clearly
        // asked for these specific bindings.
        if let Some(ref path) = self.bindings_override {
            if path.is_file() {
                return Ok(Some(path.clone()));
            }
            return Err(format!(
                "{} does not point to a file: {}",
                crate_env_var_name("SYSTEM_BINDINGS"),
                path.display()
            ));
        }

        // 2. Check conventional location populated by AWS-LC's CMake install
        // (see https://github.com/aws/aws-lc/pull/2999, AWS-LC v1.68.0+).
        let conventional = self
            .install_dir
            .join("share")
            .join("rust")
            .join("aws_lc_bindings.rs");
        if conventional.exists() {
            return Ok(Some(conventional));
        }

        Ok(None)
    }

    /// Attempts to generate bindings via the external `bindgen-cli` tool.
    /// Returns `true` if successful, `false` if bindgen is not available.
    fn try_external_bindgen(&self, manifest_dir: &Path) -> bool {
        // External bindgen collects symbols without the prefix applied—the prefix
        // is resolved at link time via `--prefix-link-name`. This matches the
        // from-source external bindgen behavior in invoke_external_bindgen().
        let options = crate::BindingOptions {
            build_prefix: None,
            include_ssl: cfg!(feature = "ssl"),
            disable_prelude: true,
            external_include_dir: Some(self.include_dir.clone()),
        };

        let bindings_path = out_dir().join("bindings.rs");

        match crate::invoke_external_bindgen(manifest_dir, &options, &self.prefix, &bindings_path) {
            Ok(()) => {
                emit_warning(format!(
                    "Generated bindings for system-installed AWS-LC via bindgen-cli (prefix: {:?})",
                    self.prefix.as_deref().unwrap_or("none")
                ));
                true
            }
            Err(_) => false,
        }
    }
}

/// Returns the platform-specific filenames for a library named `base` of the
/// given linkage type, in preference order. Multiple are possible (Windows GNU
/// dynamic accepts both `{base}.dll` and `lib{base}.dll.a`).
///
/// This is the **single source of truth** for AWS-LC's installed-filename
/// convention across platforms; both `find_lib_file` and `expected_lib_filenames`
/// derive from it.
///
/// On MSVC, both real static archives and DLL import libraries are named
/// `{base}.lib`, so this function returns the same single name for either
/// linkage. The two are disambiguated at probe time inside `find_lib_file`
/// via the sibling `../bin/{base}.dll` check.
fn lib_filenames(base: &str, lib_type: OutputLibType) -> Vec<String> {
    // MSVC is special: same `.lib` filename for both static and import
    // libraries; the two are disambiguated at probe time by sibling DLL.
    if matches!(
        (target_os().as_str(), target_env().as_str()),
        ("windows", "msvc")
    ) {
        return vec![format!("{base}.lib")];
    }

    match lib_type {
        // All non-MSVC targets use the standard Unix `lib{base}.a` static
        // archive convention (including MinGW).
        OutputLibType::Static => vec![format!("lib{base}.a")],
        OutputLibType::Dynamic => match target_os().as_str() {
            // MinGW/GNU ABI: import library is `lib{base}.dll.a`. Also
            // accept a bare `{base}.dll` co-located with the import library.
            "windows" => vec![format!("{base}.dll"), format!("lib{base}.dll.a")],
            "macos" | "ios" | "tvos" => vec![format!("lib{base}.dylib")],
            _ => vec![format!("lib{base}.so")],
        },
    }
}

/// Locates a library named `name` of the requested `lib_type` in `lib_dir`.
///
/// On MSVC, both static archives and DLL import libraries are named
/// `{name}.lib`. The two are disambiguated by `msvc_has_sibling_dll`: if
/// `../bin/{name}.dll` exists, the `.lib` is an import library (dynamic);
/// otherwise it is a real static archive.
fn find_lib_file(lib_dir: &Path, name: &str, lib_type: OutputLibType) -> Option<PathBuf> {
    let is_msvc = matches!(
        (target_os().as_str(), target_env().as_str()),
        ("windows", "msvc")
    );
    let want_dynamic = matches!(lib_type, OutputLibType::Dynamic);

    lib_filenames(name, lib_type)
        .into_iter()
        .map(|fname| lib_dir.join(fname))
        .find(|path| {
            if !path.exists() {
                return false;
            }
            // MSVC: `{name}.lib` could be either a real static archive or a
            // DLL import library. Classify by sibling-DLL presence.
            if is_msvc {
                let is_import_lib = msvc_has_sibling_dll(lib_dir, name);
                if is_import_lib != want_dynamic {
                    return false;
                }
            }
            true
        })
}

/// Returns `(link_name, file_path)` for the first candidate in `candidates`
/// whose library of the given `lib_type` exists in `lib_dir`.
fn find_candidate(
    lib_dir: &Path,
    lib_type: OutputLibType,
    candidates: &[&str],
) -> Option<(String, PathBuf)> {
    candidates
        .iter()
        .find_map(|name| find_lib_file(lib_dir, name, lib_type).map(|p| ((*name).to_string(), p)))
}

/// Comma-separated list of platform-appropriate filenames the resolver looks
/// for. `filter = Some(_)` narrows to a single linkage form; `filter = None`
/// emits both static and dynamic forms (static first, deduplicated — on MSVC
/// the two share the same `.lib` filename).
fn expected_lib_filenames(candidates: &[&str], filter: Option<OutputLibType>) -> String {
    let mut names: Vec<String> = Vec::new();
    for base in candidates {
        let mut push = |name: String| {
            if !names.contains(&name) {
                names.push(name);
            }
        };
        if let Some(lt) = filter {
            lib_filenames(base, lt).into_iter().for_each(&mut push);
        } else {
            lib_filenames(base, OutputLibType::Static)
                .into_iter()
                .for_each(&mut push);
            lib_filenames(base, OutputLibType::Dynamic)
                .into_iter()
                .for_each(&mut push);
        }
    }
    names.join(", ")
}

/// Returns `true` when a sibling `../bin/{name}.dll` exists relative to
/// `lib_dir`. `CMake` installs the runtime DLL under `bin/` while the import
/// library goes to `lib/` on MSVC, so this is the canonical way to detect
/// that the `.lib` in `lib_dir` is an import library rather than a real
/// static archive.
fn msvc_has_sibling_dll(lib_dir: &Path, name: &str) -> bool {
    lib_dir
        .parent()
        .is_some_and(|root| root.join("bin").join(format!("{name}.dll")).exists())
}

#[cfg(test)]
#[path = "system_library_tests.rs"]
mod tests;
