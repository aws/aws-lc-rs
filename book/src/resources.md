# Resources

## Build Environment Variables

The `aws-lc-sys` crate supports several environment variables that can help configure or troubleshoot
the build process. The `aws-lc-fips-sys` crate supports most of the same environment variables, but
uses an `AWS_LC_FIPS_SYS_` prefix instead of `AWS_LC_SYS_`.

> **Note:** None of the environment variables below are officially supported, and any one of them
> might be removed or changed in a future release. Please [contact us] about any bugs you find in
> our build process.

### Target-Specific Variables

Many of these environment variables also support target-specific variants. For example:
- `AWS_LC_SYS_CFLAGS` applies to all targets
- `AWS_LC_SYS_CFLAGS_aarch64_unknown_linux_gnu` applies only to the `aarch64-unknown-linux-gnu` target

The target-specific variant takes precedence when both are set.

### Library Output

* **`AWS_LC_SYS_STATIC`** | **`AWS_LC_FIPS_SYS_STATIC`**

  Controls whether the build produces a static or shared library.
  - `1` - Build as static library (e.g., `*.a`)
  - `0` - Build as shared/dynamic library (e.g., `*.so`, `*.dylib`, `*.dll`)

  Default: static library

  > **Note:** For `aws-lc-fips-sys`, static library builds are only supported on Linux and BSD targets
  > with x86_64 or aarch64 architectures. On other platforms, FIPS builds to shared libraries.

### Build System

* **`AWS_LC_SYS_CMAKE_BUILDER`**

  Controls which build system is used to compile AWS-LC. This option only applies to `aws-lc-sys`.
  - `1` - Force use of CMake
  - `0` - Force use of the `cc` crate builder

  Default: The `cc` crate builder is used by default. **CMake is not required for `aws-lc-sys`.**

  > **Note:** The `aws-lc-fips-sys` crate always requires CMake and does not support this option.

* **`AWS_LC_SYS_NO_PREGENERATED_SRC`**

  When set to `1`, forces the build to generate CMake source files instead of using
  pre-generated ones.

### Bindings Generation

* **`AWS_LC_SYS_EXTERNAL_BINDGEN`** | **`AWS_LC_FIPS_SYS_EXTERNAL_BINDGEN`**

  Controls whether to use the external `bindgen-cli` tool for generating bindings.
  - `1` - Use external `bindgen-cli` (must be installed via `cargo install bindgen-cli`)
  - `0` - Use internal bindgen or pre-generated bindings

  > **Note:** For users of `aws-lc-rs`, bindgen is never required. `aws-lc-sys` provides universal
  > bindings that work for users of `aws-lc-rs` across all supported platforms. This option
  > is primarily useful for direct consumers of `aws-lc-sys` who need complete API bindings
  > on platforms without pre-generated bindings.

* **`AWS_LC_SYS_NO_PREFIX`** | **`AWS_LC_FIPS_SYS_NO_PREFIX`**

  When set to `1`, the build will not apply a unique prefix to the library name or the symbols
  it contains. This may be useful in certain linking scenarios but can cause symbol conflicts
  if multiple versions are linked.

* **`AWS_LC_SYS_NO_U1_BINDINGS`**

  When set to `1`, uses bindings that don't include the `\x01` prefix on symbol names.
  This is automatically enabled for certain backends (like Cranelift) and architectures
  (like MIPS) that don't support the prefixed symbols.

### Assembly and Optimization

* **`AWS_LC_SYS_NO_ASM`** | **`AWS_LC_FIPS_SYS_NO_ASM`**

  When set to `1`, forces the build to use pure C implementations for all cryptographic
  operations instead of optimized assembly.

  > **Note**: When using the CMake builder, this option is only available when `OPT_LEVEL = "0"`.
  > When using the `cc` crate builder, this option is available for optimization levels 0, 1, and 2.

  > **WARNING**: Performance on most platforms is extremely limited by this option. Certain security
  > properties, such as resistance to timing attacks, can only be provided when assembly code is used.

* **`AWS_LC_SYS_PREBUILT_NASM`**

  Controls the use of prebuilt NASM objects on Windows x86-64.
  - `1` - Allow use of prebuilt NASM objects
  - `0` - Prevent use of prebuilt NASM objects (requires NASM to be installed)

  See the section on [Prebuilt NASM objects](requirements/windows.md#prebuilt-nasm-objects)
  for more information.

### Compiler Configuration

* **`AWS_LC_SYS_CC`** / **`AWS_LC_SYS_TARGET_CC`**

  Specifies the C compiler to use. Falls back to the standard `CC` / `TARGET_CC` environment
  variables if not set.

* **`AWS_LC_SYS_CXX`** / **`AWS_LC_SYS_TARGET_CXX`**

  Specifies the C++ compiler to use. Falls back to the standard `CXX` / `TARGET_CXX`
  environment variables if not set.

* **`AWS_LC_SYS_CFLAGS`** / **`AWS_LC_SYS_TARGET_CFLAGS`**

  Additional flags to pass to the C compiler during the AWS-LC build. Falls back to
  `CFLAGS` / `TARGET_CFLAGS` if not set.

* **`AWS_LC_SYS_C_STD`**

  Specifies the C language standard to use.
  - `99` - Use C99
  - `11` - Use C11

  Default: C11 on most platforms.

### Entropy Configuration

* **`AWS_LC_SYS_NO_JITTER_ENTROPY`**

  When set to `1`, disables the CPU jitter entropy source in the build. This affects the
  random number generation subsystem. Use of jitter entropy has a one-time-per-process
  latency cost, typically around 50ms, for the collection of entropy. This flag may be
  used to eliminate this latency.

  > **Note:** This option is only available for `aws-lc-sys`.

### Advanced Options

* **`AWS_LC_SYS_EFFECTIVE_TARGET`**

  Overrides the target triple string used for certain build decisions. This affects selection of pre-generated bindings.

  > **Note:** This variable does **not** override the underlying Cargo target configuration
  > (`CARGO_CFG_TARGET_*` variables). Build decisions that depend on `target_os()`,
  > `target_arch()`, `target_vendor()`, or `target_env()` are not affected by this setting.
  > It is primarily useful for selecting different pre-generated bindings or symbol prefixes
  > when building for targets that are compatible with another target's bindings.

## `aws-lc-rs` Environment Variables

The `aws-lc-rs` crate supports the following environment variables for configuring build behavior.

* **`AWS_LC_RS_DEV_TESTS_ONLY`**

  Enables development-only testing functionality without requiring the `dev-tests-only` feature flag.
  When enabled, the `rand::unsealed` module is exposed, allowing consumers to provide their own
  implementations of `SecureRandom` for deterministic or custom random number generation in tests.

  - `1` - Enable development testing functionality
  - `0` - Explicitly disable (overrides the `dev-tests-only` feature flag if set)

  This setting is restricted to dev/debug profile builds. Attempting to use it in a release build
  will result in a compilation panic.

  > **Note:** This environment variable can also override the `dev-tests-only` Cargo feature flag.
  > If both the feature flag and the environment variable are present, the environment variable
  > takes precedence.

* **`AWS_LC_RS_DISABLE_SLOW_TESTS`**

  When set to `1`, disables slow-running tests in the `aws-lc-rs` test suite. This can be useful
  for faster iteration during development.

## Links

- [API Reference Guide](https://docs.rs/aws-lc-rs/latest)
- [GitHub Repository](https://github.com/aws/aws-lc-rs)

[contact us]: https://github.com/aws/aws-lc-rs/issues/new/choose
