# Resources

## Troubleshooting

There are a few environment variables that may help in diagnosing/remdiating build problem. These affect the way that
`aws-lc-sys` or `aws-lc-fips-sys` build the underlying AWS-LC library.

None of the environment variables below are officially supported, and any one of them might be removed or changed on a
future release. Please [contact us] about any bugs you find in our build process.

* `AWS_LC_SYS_STATIC` | `AWS_LC_FIPS_SYS_STATIC` -- value can be set to `0` or `1` to force the resulting build
  artifact to be shared library (e.g., `*.so`) or static library (e.g., `*.a`).
* `AWS_LC_SYS_CMAKE_BUILDER` -- value can be set to `1` or `0` to force the build to use (`1`) or not use (`0`) CMake.
* `AWS_LC_SYS_EXTERNAL_BINDGEN | ``AWS_LC_FIPS_SYS_EXTERNAL_BINDGEN` -- value can be set to `1` or `0` to force the
  build to use (`1`) or not use (`0`) the `bindgen-cli` instead of the pre-generated or internally generated bindings.
* `AWS_LC_SYS_NO_PREFIX` | `AWS_LC_FIPS_SYS_NO_PREFIX` -- value can be set to `1` to force the build to not prefix the
  library nor the symbols it contains.
* `AWS_LC_SYS_NO_ASM` | `AWS_LC_FIPS_SYS_NO_ASM` -- value can be set to `1` to force the build to use C-language
  implementations for all cryptographic operations. Our optimized hardware-specific assembly implementations will not
  be used. This option is only available for unoptimized (i.e., `OPT_LEVEL = "0"` or "debug") builds.
  **WARNING**: Performance on most platforms is extremely limited by this option. Certain security
  properties, such as resistance to timing attacks, can only be provided when assembly code is used.
* `AWS_LC_SYS_PREBUILT_NASM` -- value can be set to `1` to *allow* the build to use our prebuilt NASM objects.
  The value can be set to `0` to *prevent* our prebuilt NASM objects from being used. See the section on
  [Prebuilt NASM objects](requirements/windows.md#prebuilt-nasm-objects) for more information.
* `AWS_LC_SYS_CFLAGS` -- if value is set, it will be used as the value of `CFLAGS` in the environment when the AWS-LC
  build is performed.
* `AWS_LC_SYS_C_STD` -- value can be set to determine the C standard used by the C compiler. It may be set to
  either `99` for C99 or `11` for C11. On most platforms, C11 will be used by default.

## Links

- [API Reference Guide](https://docs.rs/aws-lc-rs/latest)
- [GitHub Repository](https://github.com/awslabs/aws-lc-rs)

[contact us]: https://github.com/awslabs/aws-lc-rs/issues/new/choose
