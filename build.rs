fn main() {
    let mutually_exclusives_count = vec![cfg!(feature = "bindgen"), cfg!(feature = "fips")]
        .iter()
        .filter(|x| **x)
        .count();

    if mutually_exclusives_count > 1 {
        eprint!("bindgen and bindgen-fips are mutually exclusive crate features");
        std::process::exit(1);
    }
}
