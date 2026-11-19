// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! A stand-in for `vswhere.exe`, which `tests/printenv_test.rs` runs
//! `builder/printenv.bat` against.
//!
//! It implements the options the script passes, as `vswhere -help` describes
//! them, over the installations listed in the file named by
//! `FAKE_VSWHERE_INSTANCES`. Each line of that file describes one installation,
//! in the order they were installed:
//!
//! ```text
//! <version>|<product ID>|<installation path>|<component ID>,<component ID>,...
//! ```
//!
//! Anything else is rejected the way vswhere rejects an option it does not
//! know, so a new option in the script fails the tests until it is modelled
//! here. `FAKE_VSWHERE_UNSUPPORTED` lists further options to reject, which
//! imitates an older vswhere.

use std::iter::Peekable;
use std::process::exit;
use std::{env, fs};

/// The products vswhere searches when `-products` is not given.
const DEFAULT_PRODUCTS: [&str; 3] = [
    "Microsoft.VisualStudio.Product.Community",
    "Microsoft.VisualStudio.Product.Professional",
    "Microsoft.VisualStudio.Product.Enterprise",
];

/// vswhere's exit code for an invalid argument.
const INVALID_PARAMETER: i32 = 87;

struct Instance {
    version: Vec<u32>,
    product: String,
    path: String,
    components: Vec<String>,
}

#[derive(Default)]
struct Query {
    products: Vec<String>,
    requires: Vec<String>,
    latest: bool,
    sort: bool,
}

/// Parses the arguments, or returns the first one that is not supported.
fn parse_query(args: &[String], unsupported: &[&str]) -> Result<Query, String> {
    let mut query = Query::default();
    let mut reports_installation_path = false;
    let mut args = args.iter().peekable();
    while let Some(arg) = args.next() {
        if unsupported.contains(&arg.as_str()) {
            return Err(arg.clone());
        }
        match arg.as_str() {
            "-products" => query.products = option_values(&mut args),
            "-requires" => query.requires = option_values(&mut args),
            "-latest" => query.latest = true,
            "-sort" => query.sort = true,
            "-property" if args.next().map(String::as_str) == Some("installationPath") => {
                reports_installation_path = true;
            }
            _ => return Err(arg.clone()),
        }
    }
    if reports_installation_path {
        Ok(query)
    } else {
        Err("output other than -property installationPath".to_owned())
    }
}

/// Takes the values of an option, which run up to the next option.
fn option_values<'a>(args: &mut Peekable<impl Iterator<Item = &'a String>>) -> Vec<String> {
    let mut values = Vec::new();
    while let Some(value) = args.next_if(|arg| !arg.starts_with('-')) {
        values.push(value.clone());
    }
    values
}

fn read_instances() -> Vec<Instance> {
    let Ok(file) = env::var("FAKE_VSWHERE_INSTANCES") else {
        return Vec::new();
    };
    let contents = fs::read_to_string(&file).unwrap_or_else(|e| panic!("{file}: {e}"));
    contents
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.splitn(4, '|').collect();
            let [version, product, path, components] = fields[..] else {
                panic!("{file}: malformed line: {line}");
            };
            Instance {
                version: version
                    .split('.')
                    .map(|part| part.parse().expect("numeric version"))
                    .collect(),
                product: product.to_owned(),
                path: path.to_owned(),
                components: components
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect(),
            }
        })
        .collect()
}

/// Returns the instances the query selects, in the order vswhere reports them.
fn select(mut instances: Vec<Instance>, query: &Query) -> Vec<Instance> {
    instances.retain(|instance| {
        let product_selected = if query.products.is_empty() {
            DEFAULT_PRODUCTS.contains(&instance.product.as_str())
        } else {
            query
                .products
                .iter()
                .any(|product| product == "*" || *product == instance.product)
        };
        product_selected
            && query
                .requires
                .iter()
                .all(|id| instance.components.contains(id))
    });
    if query.sort || query.latest {
        // Newest version first and, among equal versions, the last installed
        // first. The sort is stable, so reversing first gives the latter.
        instances.reverse();
        instances.sort_by(|a, b| b.version.cmp(&a.version));
    }
    if query.latest {
        instances.truncate(1);
    }
    instances
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let unsupported = env::var("FAKE_VSWHERE_UNSUPPORTED").unwrap_or_default();
    let unsupported: Vec<&str> = unsupported.split(',').collect();
    let query = match parse_query(&args, &unsupported) {
        Ok(query) => query,
        Err(unsupported) => {
            // vswhere writes this error to stdout, where the script reads it
            // in place of installation paths.
            println!("Error 0x57: fake-vswhere does not support: {unsupported}");
            exit(INVALID_PARAMETER);
        }
    };
    for instance in select(read_instances(), &query) {
        println!("{}", instance.path);
    }
}
