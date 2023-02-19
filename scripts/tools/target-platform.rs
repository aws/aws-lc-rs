#!/usr/bin/env rust-script

fn main() {
    println!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
}
