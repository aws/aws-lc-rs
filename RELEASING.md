# Releasing aws-lc-rs Crates

This document describes the release process for the aws-lc-rs family of crates:

- **aws-lc-rs** - The main Rust crypto library
- **aws-lc-sys** - Low-level FFI bindings to AWS-LC
- **aws-lc-fips-sys** - Low-level FFI bindings to FIPS-validated AWS-LC

## Table of Contents

- [Prerequisites](#prerequisites)
- [One-Time Setup](#one-time-setup)
  - [Trusted Publishing on crates.io](#trusted-publishing-on-cratesio)
  - [GitHub Environment Configuration](#github-environment-configuration)
- [Pre-Release Checklist](#pre-release-checklist)
- [Automated Release Process](#automated-release-process)
  - [Draft Release Notes](#draft-release-notes)
- [Manual Release Process](#manual-release-process)
- [Post-Release Steps](#post-release-steps)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before performing a release, ensure you have:

- Write access to the [aws/aws-lc-rs](https://github.com/aws/aws-lc-rs) repository
- Owner permissions on the crates at [crates.io](https://crates.io) (for manual releases)
- Approval permissions for the `release-approval` GitHub environment

## One-Time Setup

These steps only need to be performed once per repository, not for each release.

### Trusted Publishing on crates.io

The automated workflow uses [Trusted Publishing](https://blog.rust-lang.org/2023/11/09/crates-io-trusted-publishing.html) (OIDC) to authenticate with crates.io without storing API tokens.

For each crate, configure Trusted Publishing:

1. Go to [crates.io](https://crates.io) and sign in
2. Navigate to "Account Settings" → "API Tokens"
3. Click on the crate name (e.g., `aws-lc-rs`)
4. Go to "Settings" → "Trusted publishers"
5. Click "Add" and enter:
   - **Repository owner**: `aws`
   - **Repository name**: `aws-lc-rs`
   - **Workflow filename**: `release.yml`
   - **Environment**: *(leave blank)*

Repeat for all three crates:
- `aws-lc-rs`
- `aws-lc-sys`
- `aws-lc-fips-sys`

### GitHub Environment Configuration

Create a protected environment for release approvals:

1. Go to the repository **Settings** → **Environments**
2. Click **New environment**
3. Name it: `release-approval`
4. Configure protection rules:
   - Enable **Required reviewers**
   - Add team members who can approve releases
   - Optionally enable **Wait timer** for additional safety
5. Click **Save protection rules**

## Pre-Release Checklist

Before initiating a release, verify:

- [ ] All CI checks pass on the `main` branch
- [ ] Version numbers are updated in `Cargo.toml` for each crate being released
- [ ] The `links` field in `Cargo.toml` matches the version (e.g., `aws_lc_1_2_3` for version `1.2.3`)
- [ ] Prefix symbols are regenerated if versions changed (see `scripts/generate/`)
- [ ] AWS-LC submodule commit hash is documented in `Cargo.toml`
- [ ] Any new public APIs are documented

## Automated Release Process

The recommended way to release is using the GitHub Actions workflow.

> **Note:** The workflow can only be triggered from the `main` branch.

### Steps

1. **Navigate to Actions**
   - Go to the repository's **Actions** tab
   - Select **"Release Crates"** workflow

2. **Configure Release**
   - Click **"Run workflow"**
   - Select which crates to release:
     - `release_aws_lc_sys` - Release aws-lc-sys
     - `release_aws_lc_fips_sys` - Release aws-lc-fips-sys
     - `release_aws_lc_rs` - Release aws-lc-rs
   - Set `dry_run` to:
     - `true` - Validate everything without publishing (recommended first)
     - `false` - Actually publish to crates.io

3. **Run Dry Run First**
   - Always run with `dry_run: true` first
   - Review the workflow output for any issues
   - Verify versions and sanity checks pass

4. **Approve and Publish**
   - Run again with `dry_run: false`
   - Wait for sanity checks to complete
   - When prompted, approve the release in the `release-approval` environment
   - Monitor the publishing progress

5. **Verify Publication**
   - The workflow will automatically verify the crates are available
   - Check the workflow summary for status of each crate

6. **Finalize the Draft Release**
   - The workflow automatically creates a **draft GitHub release** with all merged PRs listed
   - Go to [Releases](https://github.com/aws/aws-lc-rs/releases) and find the draft
   - Edit the release notes:
     - Move notable PRs from "Other Merged PRs" to "What's Changed"
     - Edit PR titles to be more user-friendly/descriptive
     - Group changes under appropriate headings (Build Improvements, Bug Fixes, etc.)
     - Add links to resolved issues under "Issues Being Closed"
     - Add first-time contributors to "New Contributors"
   - Publish the release when ready

### Release Order

The workflow automatically handles the correct publish order:

1. **aws-lc-fips-sys** (no internal dependencies)
2. **aws-lc-sys** (no internal dependencies)
3. **aws-lc-rs** (depends on aws-lc-sys)

Each crate waits for crates.io to index the previous one before proceeding.

Git tags are created **after** successful publication to avoid orphan tags if publishing fails.

### Draft Release Notes

The automated workflow creates a **draft GitHub release** with a template that includes:

```markdown
## What's Changed
<!-- Move important PRs here with edited titles -->

### Build Improvements
<!-- Build-related changes -->

### Issues Being Closed
<!-- Links to resolved issues -->

## Other Merged PRs
* PR title by @author in https://github.com/aws/aws-lc-rs/pull/XXX
* PR title by @author in https://github.com/aws/aws-lc-rs/pull/YYY
...

## New Contributors
<!-- First-time contributors -->

**Full Changelog**: https://github.com/aws/aws-lc-rs/compare/vX.Y.Z...vA.B.C
```

**To finalize the release:**

1. Review each PR in "Other Merged PRs"
2. Move user-facing changes to "What's Changed"
3. Edit PR titles to be clearer (e.g., "Fix build on Windows 7" instead of "Address issue #123")
4. Group related changes under sub-headings
5. Add any issues that are resolved (check PR descriptions for "Fixes #XXX")
6. Identify and credit new contributors
7. Publish the release

## Post-Release Steps

After a successful release:

1. **Finalize GitHub Release** (Automated workflow only)
   - The workflow creates a draft release with all PRs in "Other Merged PRs"
   - Go to https://github.com/aws/aws-lc-rs/releases
   - Click on the draft release to edit it
   - Organize the release notes:
     - Move important PRs to "What's Changed" with descriptive titles
     - Add sub-headings like "Build Improvements", "Bug Fixes"
     - Link resolved issues under "Issues Being Closed"
     - Credit new contributors
   - Click "Publish release" when ready

2. **Monitor for Issues**
   - Watch for bug reports related to the new release
   - Be prepared to yank and re-release if critical issues are found

## Troubleshooting

### "Version already exists on crates.io"

The version has already been published. You cannot republish the same version.
- Bump the version number in `Cargo.toml`
- Regenerate prefix symbols if this is a `-sys` crate
- Commit and push changes
- Retry the release

### Trusted Publishing Authentication Fails

Verify the Trusted Publisher configuration on crates.io:
- Correct repository owner (`aws`)
- Correct repository name (`aws-lc-rs`)
- Correct workflow filename (`release.yml`)

### "links" Field Mismatch

The `links` field must match the version with underscores:
- Version `1.2.3` → `links = "aws_lc_1_2_3"`

Update the `links` field and regenerate prefix symbols:
```bash
# Regenerate bindings and prefix symbols
cd scripts/generate
./generate_all.sh
```

### crates.io Rate Limiting

If you hit rate limits:
- Wait a few minutes before retrying
- The workflow has built-in delays between publishes

### FIPS Build Requires go.mod

The aws-lc-fips-sys crate requires a `go.mod` file during packaging. The workflow handles this automatically, but for manual releases:

```bash
cat << 'EOF' > aws-lc-fips-sys/aws-lc/go.mod
module boringssl.googlesource.com/boringssl

go 1.18
EOF
```

Remember to not commit this file—it's only needed temporarily for packaging.

### Workflow Approval Timeout

If the approval times out:
- Re-run the workflow
- Approvals must be given within the GitHub-configured timeout period

### Dependency Version Mismatch

If the workflow fails with a dependency version mismatch error:
- Verify that `aws-lc-rs/Cargo.toml` references the correct version of `aws-lc-sys`
- The versions should match when releasing both crates together

### Sanity Check Failures

If sanity checks fail:
- Review the specific error in the workflow logs
- Common issues:
  - `links` field doesn't match version
  - Prefix symbols not regenerated
  - AWS-LC commit hash not in Cargo.toml
  - Clippy warnings (shown as warnings, not failures)
  - Formatting issues (`cargo fmt --check` fails)

---

## Additional Resources

- [crates.io Trusted Publishing Documentation](https://doc.rust-lang.org/cargo/reference/registry-web-api.html#trusted-publishing)
- [crates.io Yank Documentation](https://doc.rust-lang.org/cargo/commands/cargo-yank.html)
- [GitHub Environments Documentation](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)
- [AWS-LC FIPS Documentation](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md)
