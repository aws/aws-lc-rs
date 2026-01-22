// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! CI Benchmarking tool for aws-lc-rs
//!
//! This tool measures CPU instruction counts using Valgrind's callgrind tool,
//! providing deterministic and reproducible benchmark results suitable for CI.
//!
//! ## Usage
//!
//! Run all benchmarks:
//! ```bash
//! cargo run --release -p aws-lc-rs-bench -- run-all --output-dir results
//! ```
//!
//! Compare two benchmark runs:
//! ```bash
//! cargo run --release -p aws-lc-rs-bench -- compare baseline-results candidate-results
//! ```

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod benchmarks;

/// The significance threshold for reporting benchmark differences (2%)
const SIGNIFICANCE_THRESHOLD: f64 = 0.02;

#[derive(Parser)]
#[command(name = "aws-lc-rs-bench")]
#[command(about = "CI benchmarking tool for aws-lc-rs")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run all benchmarks and output results to a directory
    RunAll {
        /// Output directory for benchmark results
        #[arg(short, long, default_value = "target/aws-lc-rs-bench")]
        output_dir: PathBuf,
    },

    /// Run a single benchmark by name (used internally by the runner)
    RunSingle {
        /// Name of the benchmark to run
        name: String,
    },

    /// List all available benchmarks
    List,

    /// Compare results from two benchmark runs
    Compare {
        /// Path to baseline results directory
        baseline_dir: PathBuf,
        /// Path to candidate results directory
        candidate_dir: PathBuf,
        /// Output format (markdown or json)
        #[arg(short, long, default_value = "markdown")]
        format: OutputFormat,
    },

    /// Run benchmarks in wall-time mode (for local testing)
    Walltime {
        /// Number of iterations per benchmark
        #[arg(short, long, default_value = "10")]
        iterations: usize,
    },
}

#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Markdown,
    Json,
}

/// Result of a single benchmark
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub instructions: u64,
}

/// Comparison between baseline and candidate results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkComparison {
    pub name: String,
    pub baseline: u64,
    pub candidate: u64,
    pub diff: i64,
    pub diff_percent: f64,
    pub significant: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::RunAll { output_dir } => run_all_benchmarks(&output_dir),
        Commands::RunSingle { name } => run_single_benchmark(&name),
        Commands::List => list_benchmarks(),
        Commands::Compare {
            baseline_dir,
            candidate_dir,
            format,
        } => compare_results(&baseline_dir, &candidate_dir, format),
        Commands::Walltime { iterations } => run_walltime_benchmarks(iterations),
    }
}

/// Run all benchmarks using callgrind for instruction counting
fn run_all_benchmarks(output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir).context("Failed to create output directory")?;

    let benchmarks = benchmarks::all_benchmarks();
    let executable = std::env::current_exe().context("Failed to get current executable path")?;

    let mut results: BTreeMap<String, u64> = BTreeMap::new();
    let callgrind_dir = output_dir.join("callgrind");
    fs::create_dir_all(&callgrind_dir).context("Failed to create callgrind output directory")?;

    println!("Running {} benchmarks...", benchmarks.len());

    for bench in &benchmarks {
        print!("  {} ... ", bench.name);
        std::io::stdout().flush()?;

        let callgrind_out = callgrind_dir.join(format!("{}.callgrind", bench.name));
        let log_file = callgrind_dir.join(format!("{}.log", bench.name));

        // Run the benchmark under callgrind
        let output = Command::new("valgrind")
            .args([
                "--tool=callgrind",
                "--callgrind-out-file",
                callgrind_out.to_str().unwrap(),
                "--collect-atstart=no",
                "--cache-sim=no",
                "--branch-sim=no",
            ])
            .arg(&executable)
            .arg("run-single")
            .arg(&bench.name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to run valgrind")?;

        // Save the log file
        fs::write(&log_file, &output.stderr).context("Failed to write log file")?;

        if !output.status.success() {
            println!("FAILED");
            eprintln!(
                "Benchmark {} failed: {}",
                bench.name,
                String::from_utf8_lossy(&output.stderr)
            );
            continue;
        }

        // Parse instruction count from callgrind output
        let instr_count = parse_callgrind_output(&callgrind_out)?;
        results.insert(bench.name.clone(), instr_count);

        println!("{} instructions", format_number(instr_count));
    }

    // Write results to CSV
    let csv_path = output_dir.join("results.csv");
    let mut csv_file = File::create(&csv_path).context("Failed to create results CSV")?;
    for (name, count) in &results {
        writeln!(csv_file, "{},{}", name, count)?;
    }

    println!("\nResults written to {}", csv_path.display());
    Ok(())
}

/// Run a single benchmark (called by the runner under callgrind)
fn run_single_benchmark(name: &str) -> Result<()> {
    let benchmarks = benchmarks::all_benchmarks();
    let bench = benchmarks
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| anyhow::anyhow!("Benchmark not found: {}", name))?;

    // Start instruction counting
    #[cfg(target_os = "linux")]
    crabgrind::callgrind::start_instrumentation();

    // Run the benchmark
    (bench.func)();

    // Stop instruction counting
    #[cfg(target_os = "linux")]
    crabgrind::callgrind::stop_instrumentation();

    Ok(())
}

/// List all available benchmarks
fn list_benchmarks() -> Result<()> {
    let benchmarks = benchmarks::all_benchmarks();
    println!("Available benchmarks ({}):", benchmarks.len());
    for bench in benchmarks {
        println!("  {}: {}", bench.name, bench.description);
    }
    Ok(())
}

/// Compare results from two benchmark runs
fn compare_results(baseline_dir: &Path, candidate_dir: &Path, format: OutputFormat) -> Result<()> {
    let baseline = read_results(&baseline_dir.join("results.csv"))?;
    let candidate = read_results(&candidate_dir.join("results.csv"))?;

    let mut comparisons: Vec<BenchmarkComparison> = Vec::new();

    for (name, &candidate_count) in &candidate {
        if let Some(&baseline_count) = baseline.get(name) {
            let diff = candidate_count as i64 - baseline_count as i64;
            let diff_percent = if baseline_count > 0 {
                (diff as f64 / baseline_count as f64) * 100.0
            } else {
                0.0
            };
            let significant = diff_percent.abs() > SIGNIFICANCE_THRESHOLD * 100.0;

            comparisons.push(BenchmarkComparison {
                name: name.clone(),
                baseline: baseline_count,
                candidate: candidate_count,
                diff,
                diff_percent,
                significant,
            });
        }
    }

    // Sort by absolute difference percentage (largest first)
    comparisons.sort_by(|a, b| {
        b.diff_percent
            .abs()
            .partial_cmp(&a.diff_percent.abs())
            .unwrap()
    });

    match format {
        OutputFormat::Markdown => print_markdown_report(&comparisons, &baseline, &candidate),
        OutputFormat::Json => print_json_report(&comparisons)?,
    }

    Ok(())
}

/// Run benchmarks in wall-time mode (for local testing)
fn run_walltime_benchmarks(iterations: usize) -> Result<()> {
    let benchmarks = benchmarks::all_benchmarks();

    println!(
        "Running {} benchmarks with {} iterations each...\n",
        benchmarks.len(),
        iterations
    );

    for bench in &benchmarks {
        let mut times: Vec<u128> = Vec::with_capacity(iterations);

        // Warm-up run
        (bench.func)();

        for _ in 0..iterations {
            let start = Instant::now();
            (bench.func)();
            times.push(start.elapsed().as_nanos());
        }

        let min = times.iter().min().unwrap();
        let max = times.iter().max().unwrap();
        let avg: u128 = times.iter().sum::<u128>() / iterations as u128;

        println!(
            "{}: min={} avg={} max={} ns",
            bench.name,
            format_number(*min as u64),
            format_number(avg as u64),
            format_number(*max as u64)
        );
    }

    Ok(())
}

/// Parse instruction count from callgrind output file
fn parse_callgrind_output(path: &Path) -> Result<u64> {
    let file = File::open(path).context("Failed to open callgrind output")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("summary:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1]
                    .parse()
                    .context("Failed to parse instruction count");
            }
        }
    }

    anyhow::bail!("Could not find instruction count in callgrind output")
}

/// Read benchmark results from CSV file
fn read_results(path: &Path) -> Result<BTreeMap<String, u64>> {
    let file =
        File::open(path).context(format!("Failed to open results file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut results = BTreeMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let count: u64 = parts[1]
                .parse()
                .context("Failed to parse instruction count")?;
            results.insert(name, count);
        }
    }

    Ok(results)
}

/// Print comparison report in Markdown format
fn print_markdown_report(
    comparisons: &[BenchmarkComparison],
    baseline: &BTreeMap<String, u64>,
    candidate: &BTreeMap<String, u64>,
) {
    println!("# Benchmark Results\n");

    // Summary
    let significant_regressions: Vec<_> = comparisons
        .iter()
        .filter(|c| c.significant && c.diff > 0)
        .collect();
    let significant_improvements: Vec<_> = comparisons
        .iter()
        .filter(|c| c.significant && c.diff < 0)
        .collect();
    let unchanged: Vec<_> = comparisons.iter().filter(|c| !c.significant).collect();

    println!("## Summary\n");
    println!(
        "- {} benchmarks with no significant change (< {}%)",
        unchanged.len(),
        SIGNIFICANCE_THRESHOLD * 100.0
    );
    if !significant_improvements.is_empty() {
        println!(
            "- ✅ {} benchmarks improved",
            significant_improvements.len()
        );
    }
    if !significant_regressions.is_empty() {
        println!(
            "- ⚠️ {} benchmarks regressed",
            significant_regressions.len()
        );
    }

    // Check for missing benchmarks
    let missing_in_candidate: Vec<_> = baseline
        .keys()
        .filter(|k| !candidate.contains_key(*k))
        .collect();
    let new_in_candidate: Vec<_> = candidate
        .keys()
        .filter(|k| !baseline.contains_key(*k))
        .collect();

    if !missing_in_candidate.is_empty() {
        println!("\n### ⚠️ Benchmarks removed\n");
        for name in &missing_in_candidate {
            println!("- {}", name);
        }
    }

    if !new_in_candidate.is_empty() {
        println!("\n### ℹ️ New benchmarks\n");
        for name in &new_in_candidate {
            println!("- {}", name);
        }
    }

    // Significant changes table
    let significant: Vec<_> = comparisons.iter().filter(|c| c.significant).collect();
    if !significant.is_empty() {
        println!("\n## Significant Changes\n");
        println!("| Benchmark | Baseline | Candidate | Diff |");
        println!("| --------- | -------: | --------: | ---: |");
        for comp in &significant {
            let emoji = if comp.diff > 0 { "⚠️" } else { "✅" };
            println!(
                "| {} | {} | {} | {} {:+.2}% |",
                comp.name,
                format_number(comp.baseline),
                format_number(comp.candidate),
                emoji,
                comp.diff_percent
            );
        }
    }

    // Full results (collapsed)
    println!("\n<details>");
    println!(
        "<summary>Full Results ({} benchmarks)</summary>\n",
        comparisons.len()
    );
    println!("| Benchmark | Baseline | Candidate | Diff |");
    println!("| --------- | -------: | --------: | ---: |");
    for comp in comparisons {
        println!(
            "| {} | {} | {} | {:+.2}% |",
            comp.name,
            format_number(comp.baseline),
            format_number(comp.candidate),
            comp.diff_percent
        );
    }
    println!("\n</details>");
}

/// Print comparison report in JSON format
fn print_json_report(comparisons: &[BenchmarkComparison]) -> Result<()> {
    let json = serde_json::to_string_pretty(comparisons)?;
    println!("{}", json);
    Ok(())
}

/// Format a number with thousand separators
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
