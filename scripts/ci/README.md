# Bindings-generator commit jobs

The sys and FIPS bindings-generator workflows separate generation from committing. Build jobs check out an exact input SHA, run with `contents: read` and no persisted checkout credentials, and export patches. Each stage's commit job checks out the same SHA, applies patches to the index, checks paths and file modes, and pushes one commit. The next stage consumes that commit's SHA.

## Security boundary

The goal is to isolate repository-write credentials from generation tooling and limit the files a compromised generator can change. The commit jobs must not build, format, import, or execute generated output, or install generation dependencies. They commit directly from the validated index without checking generated files out into the worktree.

Path and mode checks do not validate content. A regular, non-executable file can still contain malicious Rust or C, Cargo configuration, or machine code in a NASM object. Later build jobs may execute this content, which is why they also run without repository-write credentials. Pinning cross and its images prevents silently following newer upstream revisions, but does not prove the pinned tools or their output are trustworthy; other build inputs are not fully pinned either.

Generated changes still need review before merging or publishing. For stronger content-integrity assurance, independently regenerate and compare output using trusted tooling, especially prebuilt objects that cannot be meaningfully reviewed as source. Artifact hashes or attestations from the same compromised generator would establish provenance, not that its output is benign. These workflows do not enforce independent regeneration or provide reproducible-build guarantees.

## Branch changes and retries

A generated commit's only parent is the stage's input SHA. The push uses an explicit `--force-with-lease=<ref>:<input-sha>` as a compare-and-swap: it can advance only that exact tip, not overwrite intervening commits or recreate a deleted branch. It does not rebase output onto newer inputs, even if such a rebase would be conflict-free.

Transient push failures retry the same commit up to five times, sleeping only between attempts. If the remote already contains that exact commit, the push is treated as successful. If the branch has moved or disappeared, start a fresh generation run at the current tip (or a new generation branch); rerunning the old workflow retains its stale input SHA.

## Local regression tests

```sh
python3 -B -m unittest discover -s scripts/tests -p test_generated_changes.py -v
```

The tests use temporary repositories and a local bare remote. They do not build AWS-LC, use GitHub credentials, or push to GitHub.
