fn main() {
    let mutually_exclusives_count = vec![cfg!(feature = "non-fips"), cfg!(feature = "fips")]
        .iter()
        .filter(|x| **x)
        .count();

    if mutually_exclusives_count > 1 {
        eprint!("fips and non-fips are mutually exclusive crate features.");
        std::process::exit(1);
    }

    // This appears asymmetric, but it reflects the `cfg` statements in lib.rs that
    // require `aws-lc-sys` to be present when "fips" is not enabled.
    let at_least_one_count = vec![cfg!(feature = "aws-lc-sys"), cfg!(feature = "fips")]
        .iter()
        .filter(|x| **x)
        .count();

    if at_least_one_count < 1 {
        eprint!(
            "one of the following features must be specified: \
        aws-lc-sys, non-fips, or fips."
        );
        std::process::exit(1);
    }

    // "aws-lc-fips-sys" should not be specified w/o fips
    let xnor_count = vec![cfg!(feature = "fips"), cfg!(feature = "aws-lc-fips-sys")]
        .iter()
        .filter(|x| **x)
        .count();

    if xnor_count == 1 {
        eprint!("For a FIPS build specify the fips feature.");
        std::process::exit(1);
    }
}
