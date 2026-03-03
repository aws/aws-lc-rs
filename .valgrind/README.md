# Valgrind Configuration for aws-lc-rs

This directory contains Valgrind suppression rules and documentation for memory testing in aws-lc-rs.

## Files

- `rust-test.supp` - Valgrind suppression file for known false positives

## Understanding Valgrind Leak Categories

Valgrind classifies memory leaks into four categories:

| Category | Description | Action Required |
|----------|-------------|-----------------|
| **definitely lost** | Memory was allocated but no pointer to it exists. This is a **real memory leak**. | ⚠️ Must fix |
| **indirectly lost** | Memory is only reachable via "definitely lost" memory. This is also a **real leak**. | ⚠️ Must fix |
| **possibly lost** | A pointer to the middle of the block exists (interior pointer). Common in Rust data structures. | Usually false positive |
| **still reachable** | Memory is still pointed to at program exit. Typically intentional global/static data. | Usually intentional |

## What Our Suppressions Do

The `rust-test.supp` file **ONLY** suppresses known false positives:

- ✅ Suppresses: `possibly lost` from Rust test harness threading
- ✅ Suppresses: `still reachable` from static/global initialization
- ❌ Does NOT suppress: `definitely lost` (real leaks)
- ❌ Does NOT suppress: `indirectly lost` (real leaks)

This means **actual memory leaks will always be reported**, even with suppressions enabled.

## Running Valgrind Tests

### Standard Run (with suppressions)

```bash
# From the repository root
./aws-lc-rs/scripts/run-valgrind.sh

# Run a specific test
./aws-lc-rs/scripts/run-valgrind.sh ecdsa_tests
```

### Verify Suppressions Aren't Masking Real Leaks

Use `--strict-leaks` mode to check only for real memory leaks:

```bash
./aws-lc-rs/scripts/run-valgrind.sh --strict-leaks
```

This mode:
- Only reports `definitely lost` and `indirectly lost` memory
- Ignores `possibly lost` and `still reachable` (the false positives)
- Runs without suppressions

**If `--strict-leaks` passes, your suppressions are safe** - they're only hiding false positives, not real leaks.

### See All Warnings (without suppressions)

```bash
./aws-lc-rs/scripts/run-valgrind.sh --no-suppress
```

### Generate New Suppression Rules

If you encounter new false positives:

```bash
./aws-lc-rs/scripts/run-valgrind.sh --gen-suppressions 2>&1 | tee valgrind-output.txt
```

Review the generated rules carefully before adding them to `rust-test.supp`.

## Suppression Rule Anatomy

```
{
   rule_name                    # Descriptive name
   Memcheck:Leak                # Error type (Leak for memory leaks)
   match-leak-kinds: possible   # CRITICAL: Only match specific leak types
   fun:malloc                   # Function at top of stack
   ...                          # Zero or more frames (wildcard)
   fun:*specific_function*      # Specific function pattern
   obj:*/*_test*-*              # Object file pattern (test binaries)
   ...
   fun:__libc_start_main*       # Anchor at program startup
}
```

### Key Safety Rules for Suppressions

1. **Always use `match-leak-kinds`** - Never suppress all leak types
2. **Be specific** - Include multiple stack frames to narrow matches
3. **Anchor to known patterns** - Use `__libc_start_main` for init-time allocations
4. **Use `obj:` patterns** - Limit to test binaries when appropriate
5. **Document why** - Add comments explaining each suppression

## CI Integration

The CI pipeline should run Valgrind tests in two modes:

1. **Regular mode** (with suppressions) - Catches new leaks while ignoring known false positives
2. **Periodic strict mode** - Verifies suppressions aren't masking real issues

Example CI configuration:

```yaml
# Regular Valgrind check
- name: Valgrind Memory Check
  run: ./aws-lc-rs/scripts/run-valgrind.sh --release

# Weekly verification that suppressions are safe
- name: Valgrind Strict Leak Check
  run: ./aws-lc-rs/scripts/run-valgrind.sh --strict-leaks --release
  if: github.event.schedule == 'weekly'
```

## Troubleshooting

### "Possibly lost" appearing despite suppressions

1. Check that the stack trace matches your suppression pattern
2. Binary names include a hash (e.g., `ecdsa_tests-973dd01c3567415a`)
3. Use `--gen-suppressions` to see the exact pattern needed

### New false positive from Rust/stdlib update

1. Run `--gen-suppressions` to capture the pattern
2. Verify it's truly a false positive (check `--strict-leaks` passes)
3. Add a specific suppression with documentation

### Suppression not matching

Common issues:
- Function names change between Rust versions
- Use wildcards: `fun:*thread*Thread*new*` instead of exact names
- Object paths vary: use `obj:*/*_test*-*` pattern

## Known False Positives

### Rust Test Harness

The Rust test harness creates thread pools and uses `call_once` for initialization.
These allocations are intentionally kept alive for the program's lifetime and appear
as "possibly lost" or "still reachable".

### Thread-Local Storage

Rust's `thread_local!` macro and `std::thread::Thread` use pthread TLS, which
allocates memory that lives until thread/program exit.

### AWS-LC Static Initialization

AWS-LC initializes various internal state on first use via `CRYPTO_once`.
This memory is intentionally never freed.

## References

- [Valgrind Manual - Suppression Files](https://valgrind.org/docs/manual/manual-core.html#manual-core.suppress)
- [Valgrind Memcheck Manual](https://valgrind.org/docs/manual/mc-manual.html)
- [Rust Test Harness Source](https://github.com/rust-lang/rust/tree/master/library/test)