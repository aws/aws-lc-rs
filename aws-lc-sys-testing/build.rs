fn main() {
    // ensure that the include path is exported and set up correctly
    cc::Build::new()
        .include(env("DEP_AWS_LC_0_12_0_INCLUDE"))
        .file("src/testing.c")
        .compile("aws_ls_sys_testing");

    // ensure the libcrypto artifact is linked
    println!("cargo:rustc-link-lib=aws_lc_0_12_0_crypto");
}

fn env<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    println!("cargo:rerun-if-env-changed={s}");
    std::env::var(s).unwrap_or_else(|_| panic!("missing env var {s}"))
}
