// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Tests for `builder/printenv.bat`, which locates a Visual Studio installation
//! and prints the environment that its `vcvarsall.bat` sets up.
//!
//! The script reaches both `vswhere.exe` and the directory it searches as a
//! last resort through `%ProgramFiles(x86)%`. Each test points that variable at
//! a temporary directory holding the `fake-vswhere` binary and stand-in
//! installations, so the outcome does not depend on what is installed on the
//! machine running the tests.
#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const COMMUNITY: &str = "Microsoft.VisualStudio.Product.Community";
const ENTERPRISE: &str = "Microsoft.VisualStudio.Product.Enterprise";
const BUILD_TOOLS: &str = "Microsoft.VisualStudio.Product.BuildTools";
const TEST_AGENT: &str = "Microsoft.VisualStudio.Product.TestAgent";

// The components the builder asks for; see `msvc_tools_component` in
// `builder/cmake_builder.rs`.
const X64_TOOLS: &str = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64";
const ARM64_TOOLS: &str = "Microsoft.VisualStudio.Component.VC.Tools.ARM64";
/// A toolset pinned to one version. It comes with `vcvarsall.bat`, but is not
/// the component the builder asks for.
const PINNED_X64_TOOLS: &str = "Microsoft.VisualStudio.Component.VC.14.38.17.8.x86.x64";
const PINNED_ARM64_TOOLS: &str = "Microsoft.VisualStudio.Component.VC.14.38.17.8.ARM64";

/// The target library directory provided by the component.
fn lib_arch(component: &str) -> &'static str {
    match component {
        X64_TOOLS | PINNED_X64_TOOLS => "x64",
        ARM64_TOOLS | PINNED_ARM64_TOOLS => "arm64",
        _ => panic!("unknown component: {component}"),
    }
}

#[derive(Clone, Copy)]
enum Location {
    /// Under `%ProgramFiles%`, as Visual Studio 2022 is by default. The script
    /// can only learn of these from vswhere.
    ProgramFiles,
    /// Under `%ProgramFiles(x86)%\Microsoft Visual Studio`, the directory the
    /// script searches when vswhere reports nothing usable.
    SearchedDirectory,
    /// Anywhere else, as with `--installPath C:\BuildTools`.
    Custom,
}

enum Vcvarsall {
    /// Exits 0, as the real one does even when the installation lacks the
    /// tools for the requested architecture.
    Succeeds,
    Fails,
    Absent,
}

struct Install {
    name: &'static str,
    product: &'static str,
    version: &'static str,
    location: Location,
    components: &'static [&'static str],
    vcvarsall: Vcvarsall,
}

impl Install {
    fn new(
        name: &'static str,
        product: &'static str,
        version: &'static str,
        location: Location,
        components: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            product,
            version,
            location,
            components,
            vcvarsall: Vcvarsall::Succeeds,
        }
    }

    fn vcvarsall(mut self, vcvarsall: Vcvarsall) -> Self {
        self.vcvarsall = vcvarsall;
        self
    }
}

/// What the script reports once an installation's `vcvarsall.bat` has run.
#[derive(Debug, PartialEq)]
struct Found {
    install: String,
    arch: String,
}

fn found(install: &str, arch: &str) -> Found {
    Found {
        install: install.to_owned(),
        arch: arch.to_owned(),
    }
}

/// A machine with a set of Visual Studio installations.
struct Machine {
    dir: TempDir,
    /// The installations vswhere knows of, in the form `fake-vswhere` reads.
    instances: Vec<String>,
    unsupported_vswhere_options: &'static str,
}

impl Machine {
    fn new() -> Self {
        let machine = Self {
            dir: tempfile::tempdir().unwrap(),
            instances: Vec::new(),
            unsupported_vswhere_options: "",
        };
        fs::create_dir_all(machine.vswhere().parent().unwrap()).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_fake-vswhere"), machine.vswhere()).unwrap();
        // Like a caller with x64 libraries already on LIB, even for ARM64 builds.
        let inherited_lib = machine.dir.path().join("inherited-x64");
        fs::create_dir(&inherited_lib).unwrap();
        fs::write(inherited_lib.join("msvcrt.lib"), "").unwrap();

        // The published crate has the script with LF line endings, while a
        // Windows checkout may have CRLF. cmd.exe does not treat the two alike,
        // so every test runs both.
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../builder/printenv.bat");
        let script = fs::read_to_string(script).unwrap().replace("\r\n", "\n");
        fs::write(machine.dir.path().join("printenv-lf.bat"), &script).unwrap();
        let script = script.replace('\n', "\r\n");
        fs::write(machine.dir.path().join("printenv-crlf.bat"), script).unwrap();
        machine
    }

    fn program_files_x86(&self) -> PathBuf {
        self.dir.path().join("Program Files (x86)")
    }

    fn searched_directory(&self) -> PathBuf {
        self.program_files_x86().join("Microsoft Visual Studio")
    }

    fn vswhere(&self) -> PathBuf {
        self.searched_directory()
            .join("Installer")
            .join("vswhere.exe")
    }

    fn without_vswhere(self) -> Self {
        fs::remove_file(self.vswhere()).unwrap();
        self
    }

    /// Makes vswhere reject an option, as a version that predates it would.
    fn with_vswhere_lacking(mut self, option: &'static str) -> Self {
        self.unsupported_vswhere_options = option;
        self
    }

    fn with(mut self, install: Install) -> Self {
        let Install {
            name,
            product,
            version,
            location,
            components,
            vcvarsall,
        } = install;
        let dir = match location {
            Location::ProgramFiles => self
                .dir
                .path()
                .join("Program Files")
                .join("Microsoft Visual Studio"),
            Location::SearchedDirectory => self.searched_directory(),
            Location::Custom => self.dir.path().to_owned(),
        }
        .join(name);

        let exit_code = match vcvarsall {
            Vcvarsall::Succeeds => Some(0),
            Vcvarsall::Fails => Some(1),
            Vcvarsall::Absent => None,
        };
        fs::create_dir_all(&dir).unwrap();
        if let Some(exit_code) = exit_code {
            let build_dir = dir.join("VC").join("Auxiliary").join("Build");
            fs::create_dir_all(&build_dir).unwrap();
            // The real vcvarsall.bat only adds the libraries of the requested
            // architecture to LIB when the installation has them.
            for component in components {
                let lib_dir = build_dir.join("lib").join(lib_arch(component));
                fs::create_dir_all(&lib_dir).unwrap();
                fs::write(lib_dir.join("msvcrt.lib"), "").unwrap();
            }
            // A failed initialization can leave a partially modified environment.
            let failed_environment = if exit_code == 0 {
                ""
            } else {
                "@set \"FAKE_VCVARS_FAILED=1\"\r\n"
            };
            fs::write(
                build_dir.join("vcvarsall.bat"),
                format!(
                    "@set \"FAKE_VCVARS_FROM={name}\"\r\n\
                     @set \"FAKE_VCVARS_ARCH=%1\"\r\n\
                     @set \"VCToolsInstallDir=%~dp0\"\r\n\
                     @set \"VSCMD_ARG_TGT_ARCH=%1\"\r\n\
                     @if \"%1\"==\"x64_arm64\" set \"VSCMD_ARG_TGT_ARCH=arm64\"\r\n\
                     @if exist \"%~dp0lib\\%VSCMD_ARG_TGT_ARCH%\" set \"LIB=%~dp0lib\\%VSCMD_ARG_TGT_ARCH%;%LIB%\"\r\n\
                     @echo fake vcvarsall diagnostic=not an environment variable\r\n\
                     {failed_environment}\
                     @exit /b {exit_code}\r\n"
                ),
            )
            .unwrap();
        }

        self.instances.push(format!(
            "{}|{}|{}|{}",
            version,
            product,
            dir.display(),
            components.join(",")
        ));
        self
    }

    /// Runs the script the way the builder does. On failure, returns what the
    /// script printed.
    fn locate(&self, args: &[&str]) -> Result<Found, String> {
        let lf = self.run("printenv-lf.bat", args);
        let crlf = self.run("printenv-crlf.bat", args);
        assert_eq!(
            lf, crlf,
            "LF and CRLF copies of the script disagree:\n{lf:?}\n{crlf:?}"
        );
        lf
    }

    fn run(&self, script: &str, args: &[&str]) -> Result<Found, String> {
        let instances = self.dir.path().join("instances.txt");
        fs::write(&instances, self.instances.join("\n")).unwrap();

        let output = Command::new(self.dir.path().join(script))
            .args(args)
            .env("ProgramFiles(x86)", self.program_files_x86())
            .env("LIB", self.dir.path().join("inherited-x64"))
            .env("FAKE_VSWHERE_INSTANCES", instances)
            .env("FAKE_VSWHERE_UNSUPPORTED", self.unsupported_vswhere_options)
            .env_remove("FAKE_VCVARS_FAILED")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            assert!(
                output.stdout.is_empty(),
                "a rejected environment was printed"
            );
            return Err(stderr.into_owned());
        }
        assert!(stderr.contains("fake vcvarsall diagnostic="));
        let mut pairs = output.stdout.chunks_exact(2);
        let words: Vec<_> = pairs
            .by_ref()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        assert!(pairs.remainder().is_empty());
        let stdout = String::from_utf16(&words).unwrap();
        assert!(!stdout.contains("fake vcvarsall diagnostic="));
        assert!(
            !stdout
                .lines()
                .any(|line| line.starts_with("FAKE_VCVARS_FAILED=")),
            "a failed initialization contaminated the successful environment"
        );
        // The builder takes the environment from the `NAME=value` lines.
        let variable = |name: &str| {
            let mut values = stdout
                .lines()
                .filter_map(|line| line.strip_prefix(name)?.strip_prefix('='));
            let value = values
                .next()
                .unwrap_or_else(|| panic!("the script succeeded without setting {name}"));
            assert!(values.next().is_none(), "{name} was printed more than once");
            value.to_owned()
        };
        Ok(Found {
            install: variable("FAKE_VCVARS_FROM"),
            arch: variable("FAKE_VCVARS_ARCH"),
        })
    }
}

#[test]
fn finds_visual_studio_in_default_location() {
    let machine = Machine::new().with(Install::new(
        "Enterprise",
        ENTERPRISE,
        "17.14.1",
        Location::ProgramFiles,
        &[X64_TOOLS, ARM64_TOOLS],
    ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("Enterprise", "x64"))
    );
}

// https://github.com/aws/aws-lc-rs/issues/1305
#[test]
fn finds_build_tools_in_custom_location() {
    let machine = Machine::new().with(Install::new(
        "BuildTools",
        BUILD_TOOLS,
        "17.14.1",
        Location::Custom,
        &[X64_TOOLS],
    ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("BuildTools", "x64"))
    );
}

#[test]
fn finds_build_tools_lacking_requested_component() {
    let machine = Machine::new().with(Install::new(
        "BuildTools",
        BUILD_TOOLS,
        "17.14.1",
        Location::Custom,
        &[PINNED_X64_TOOLS],
    ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("BuildTools", "x64"))
    );
}

#[test]
fn prefers_newest_installation_of_any_product() {
    let machine = Machine::new()
        .with(Install::new(
            "VS2019",
            COMMUNITY,
            "16.11.2",
            Location::SearchedDirectory,
            &[X64_TOOLS],
        ))
        .with(Install::new(
            "BuildTools",
            BUILD_TOOLS,
            "17.14.1",
            Location::Custom,
            &[X64_TOOLS],
        ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("BuildTools", "x64"))
    );
}

#[test]
fn prefers_installation_with_requested_component() {
    let machine = Machine::new()
        .with(Install::new(
            "Community",
            COMMUNITY,
            "17.10.0",
            Location::ProgramFiles,
            &[X64_TOOLS, ARM64_TOOLS],
        ))
        .with(Install::new(
            "Enterprise",
            ENTERPRISE,
            "17.14.1",
            Location::ProgramFiles,
            &[X64_TOOLS],
        ));
    assert_eq!(
        machine.locate(&["x64_arm64", ARM64_TOOLS]),
        Ok(found("Community", "x64_arm64"))
    );
}

#[test]
fn defaults_to_x64_tools_without_arguments() {
    let machine = Machine::new()
        .with(Install::new(
            "Community",
            COMMUNITY,
            "17.10.0",
            Location::ProgramFiles,
            &[X64_TOOLS],
        ))
        .with(Install::new(
            "BuildTools",
            BUILD_TOOLS,
            "17.14.1",
            Location::Custom,
            &[PINNED_X64_TOOLS],
        ));
    assert_eq!(machine.locate(&[]), Ok(found("Community", "x64")));
}

#[test]
fn skips_installation_with_requested_component_but_no_vcvarsall() {
    let machine = Machine::new()
        .with(Install::new(
            "Community",
            COMMUNITY,
            "17.10.0",
            Location::ProgramFiles,
            &[X64_TOOLS, PINNED_ARM64_TOOLS],
        ))
        .with(
            Install::new(
                "BuildTools",
                BUILD_TOOLS,
                "17.14.1",
                Location::Custom,
                &[ARM64_TOOLS],
            )
            .vcvarsall(Vcvarsall::Absent),
        );
    assert_eq!(
        machine.locate(&["x64_arm64", ARM64_TOOLS]),
        Ok(found("Community", "x64_arm64"))
    );
}

#[test]
fn skips_newer_installation_without_vcvarsall() {
    let machine = Machine::new()
        .with(Install::new(
            "BuildTools",
            BUILD_TOOLS,
            "17.10.0",
            Location::Custom,
            &[PINNED_X64_TOOLS],
        ))
        .with(
            Install::new("TestAgent", TEST_AGENT, "17.14.1", Location::Custom, &[])
                .vcvarsall(Vcvarsall::Absent),
        );
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("BuildTools", "x64"))
    );
}

#[test]
fn tries_older_installation_when_newest_vcvarsall_fails() {
    let machine = Machine::new()
        .with(Install::new(
            "Community",
            COMMUNITY,
            "17.10.0",
            Location::ProgramFiles,
            &[X64_TOOLS],
        ))
        .with(
            Install::new(
                "BuildTools",
                BUILD_TOOLS,
                "17.14.1",
                Location::Custom,
                &[X64_TOOLS],
            )
            .vcvarsall(Vcvarsall::Fails),
        );
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("Community", "x64"))
    );
}

#[test]
fn skips_newer_installation_lacking_tools_for_target() {
    let machine = Machine::new()
        .with(Install::new(
            "Community",
            COMMUNITY,
            "17.10.0",
            Location::ProgramFiles,
            &[PINNED_ARM64_TOOLS],
        ))
        .with(Install::new(
            "BuildTools",
            BUILD_TOOLS,
            "17.14.1",
            Location::Custom,
            &[X64_TOOLS],
        ));
    assert_eq!(
        machine.locate(&["x64_arm64", ARM64_TOOLS]),
        Ok(found("Community", "x64_arm64"))
    );
}

#[test]
fn finds_pinned_build_tools_when_vswhere_lacks_sort() {
    let machine = Machine::new()
        .with_vswhere_lacking("-sort")
        .with(Install::new(
            "BuildTools",
            BUILD_TOOLS,
            "17.14.1",
            Location::Custom,
            &[PINNED_X64_TOOLS],
        ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("BuildTools", "x64"))
    );
}

#[test]
fn falls_back_to_original_query_with_older_vswhere() {
    let machine = Machine::new()
        .with_vswhere_lacking("-products")
        .with(Install::new(
            "VS2017",
            COMMUNITY,
            "15.9.1",
            Location::Custom,
            &[PINNED_X64_TOOLS],
        ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("VS2017", "x64"))
    );
}

#[test]
fn searches_default_directory_without_vswhere() {
    let machine = Machine::new().without_vswhere().with(Install::new(
        "BuildTools",
        BUILD_TOOLS,
        "17.14.1",
        Location::SearchedDirectory,
        &[X64_TOOLS],
    ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("BuildTools", "x64"))
    );
}

#[test]
fn searches_default_directory_after_vcvarsall_fails() {
    let machine = Machine::new()
        .without_vswhere()
        .with(
            Install::new(
                "Broken",
                BUILD_TOOLS,
                "17.14.1",
                Location::SearchedDirectory,
                &[X64_TOOLS],
            )
            .vcvarsall(Vcvarsall::Fails),
        )
        .with(Install::new(
            "Working",
            COMMUNITY,
            "17.10.0",
            Location::SearchedDirectory,
            &[X64_TOOLS],
        ));
    assert_eq!(
        machine.locate(&["x64", X64_TOOLS]),
        Ok(found("Working", "x64"))
    );
}

#[test]
fn fails_when_nothing_is_installed() {
    let output = Machine::new().locate(&["x64", X64_TOOLS]).unwrap_err();
    assert!(
        output.contains("No usable vcvarsall.bat found."),
        "{output}"
    );
}

#[test]
fn inherited_x64_lib_does_not_satisfy_arm64_target() {
    let machine = Machine::new().with(Install::new(
        "Enterprise",
        ENTERPRISE,
        "17.14.1",
        Location::ProgramFiles,
        &[X64_TOOLS],
    ));
    let output = machine.locate(&["x64_arm64", ARM64_TOOLS]).unwrap_err();
    assert!(
        output.contains("No MSVC libraries for x64_arm64"),
        "{output}"
    );
}

#[test]
fn fails_when_vcvarsall_fails() {
    let machine = Machine::new().with(
        Install::new(
            "Enterprise",
            ENTERPRISE,
            "17.14.1",
            Location::ProgramFiles,
            &[X64_TOOLS],
        )
        .vcvarsall(Vcvarsall::Fails),
    );
    let output = machine.locate(&["x64", X64_TOOLS]).unwrap_err();
    assert!(
        output.contains("Failed to set Visual Studio environment variables."),
        "{output}"
    );
}
