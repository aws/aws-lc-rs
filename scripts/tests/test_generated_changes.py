# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
"""Local-only regression tests for the generated-changes commit job."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "ci/ci_commit_generated_changes.sh"
REAL_GIT = shutil.which("git")
BASH = shutil.which("bash")
BRANCH = "ci/generated-fixture"
REF = f"refs/heads/{BRANCH}"
OUTPUT = "aws-lc-sys/src/generated.rs"
BINARY = "aws-lc-fips-sys/src/generated.bin"
REMOVED = "aws-lc-sys/src/obsolete.rs"
REMOVED_BINARY = "aws-lc-fips-sys/src/obsolete.bin"
ALLOWLIST = ("aws-lc-sys/src", "aws-lc-fips-sys/src")

# Delegate to real Git except for requested transport faults; sleep only records.
STUB = r'''
import json
import os
from pathlib import Path
import subprocess
import sys

program = Path(sys.argv[0]).name
args = sys.argv[1:]
trace = Path(os.environ["FIXTURE_TRACE"])
history = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
real_git = [os.environ["FIXTURE_GIT"], "--no-pager"]
event = {"program": program, "args": args}
if program == "git" and args[0] == "push":
    event["head"] = subprocess.check_output(real_git + ["rev-parse", "HEAD"], timeout=10).decode().strip()
with trace.open("a") as log:
    log.write(json.dumps(event) + "\n")
if program == "sleep":
    sys.exit(0)
ordinal = 1 + sum(e["program"] == program and e["args"][0] == args[0] for e in history)
if args[0] == "push" and ordinal <= int(os.environ["FIXTURE_REJECTIONS"]):
    print("Injected push rejection", file=sys.stderr)
    sys.exit(1)
if args[0] == "ls-remote" and ordinal <= int(os.environ["FIXTURE_QUERY_FAILURES"]):
    print("Injected remote query failure", file=sys.stderr)
    sys.exit(1)
status = subprocess.run(real_git + args, check=False, timeout=10).returncode
if args[0] == "push" and status == 0 and os.environ["FIXTURE_LOST_ACK"] == "1":
    print("Injected lost push acknowledgement", file=sys.stderr)
    status = 1
sys.exit(status)
'''


class Fixture:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="generated-changes-")
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.remote = self.root / "origin.git"
        self.generator = self.root / "generator"
        self.bin = self.root / "bin"
        self.patches = self.root / "patches"
        self.patch = self.patches / "generated.patch"
        self.trace = self.root / "trace.jsonl"
        home, hooks = self.root / "home", self.root / "hooks"
        for directory in (self.bin, self.patches, home, hooks):
            directory.mkdir()
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("GIT_", "GITHUB_"))
        }
        self.env.update(
            HOME=str(home), XDG_CONFIG_HOME=str(home / "config"), LC_ALL="C",
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
            GIT_ATTR_NOSYSTEM="1", GIT_CONFIG_COUNT="4",
            GIT_CONFIG_KEY_0="core.hooksPath", GIT_CONFIG_VALUE_0=str(hooks),
            GIT_CONFIG_KEY_1="commit.gpgsign", GIT_CONFIG_VALUE_1="false",
            GIT_CONFIG_KEY_2="core.autocrlf", GIT_CONFIG_VALUE_2="false",
            GIT_CONFIG_KEY_3="core.filemode", GIT_CONFIG_VALUE_3="true",
            GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
            GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
            GIT_EDITOR="true", GIT_SEQUENCE_EDITOR="true",
            GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat",
        )
        self.git("init", "--quiet", "--bare", "-b", BRANCH, str(self.remote), cwd=self.root)
        self.git("init", "--quiet", "-b", BRANCH, str(self.work), cwd=self.root)
        initial = {
            OUTPUT: b"original bindings\n", BINARY: b"\0original\xff\n",
            REMOVED: b"obsolete bindings\n", REMOVED_BINARY: b"\0obsolete\xff\n",
            "generator-input.txt": b"earlier input\n",
        }
        for name, data in initial.items():
            path = self.work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Earlier fixture input")
        self.previous = self.sha()
        (self.work / "generator-input.txt").write_bytes(b"generation input\n")
        self.git("add", "generator-input.txt")
        self.git("commit", "--quiet", "-m", "Original generation base")
        self.base = self.sha()
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "--quiet", "origin", f"HEAD:{REF}")
        self.git("clone", "--quiet", str(self.remote), str(self.generator), cwd=self.root)
        stub = self.bin / "git"
        stub.write_text(f"#!{sys.executable}\n" + STUB)
        stub.chmod(0o755)
        (self.bin / "sleep").symlink_to("git")
        self.original = self.snapshot()
        return self

    def __exit__(self, *exc):
        self.temp.cleanup()

    def git(self, *args, cwd=None):
        assert REAL_GIT is not None
        return subprocess.run(
            [REAL_GIT, "--no-pager", *args], cwd=cwd or self.work, env=self.env,
            capture_output=True, check=True, timeout=10,
        ).stdout

    def sha(self):
        return self.git("rev-parse", "HEAD").decode().strip()

    def tip(self):
        result = self.git("ls-remote", "--refs", str(self.remote), REF).split()
        return result[0].decode() if result else None

    def snapshot(self):
        return {
            path.relative_to(self.work).as_posix(): (
                path.lstat().st_mode,
                os.readlink(path) if path.is_symlink()
                else path.read_bytes() if path.is_file() else None,
            )
            for path in self.work.rglob("*")
            if path.relative_to(self.work).parts[0] != ".git"
        }

    def make_patch(self, changes):
        for name, data in changes.items():
            path = self.generator / name
            if data is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        self.git("add", "--all", cwd=self.generator)
        self.export_patch()

    def export_patch(self):
        self.patch.write_bytes(self.git(
            "diff", "--cached", "--binary", "--full-index", "--no-ext-diff",
            "--no-renames", cwd=self.generator,
        ))

    def run(self, rejections=0, query_failures=0, lost_ack=False):
        assert BASH is not None and REAL_GIT is not None
        env = {
            **self.env,
            "PATH": str(self.bin) + os.pathsep + self.env.get("PATH", os.defpath),
            "GITHUB_REF_NAME": BRANCH, "FIXTURE_GIT": REAL_GIT,
            "FIXTURE_TRACE": str(self.trace), "FIXTURE_REJECTIONS": str(rejections),
            "FIXTURE_QUERY_FAILURES": str(query_failures),
            "FIXTURE_LOST_ACK": "1" if lost_ack else "0",
        }
        return subprocess.run(
            [BASH, str(SCRIPT), "Commit generated fixture", str(self.patches), *ALLOWLIST],
            cwd=self.work, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False, timeout=30,
        )

    def events(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()]


@unittest.skipUnless(REAL_GIT and BASH, "Git and Bash are required")
class GeneratedChangesTests(unittest.TestCase):
    def invoke(self, fixture, success=True, attempts=1, sleeps=(), **faults):
        refs = fixture.git("for-each-ref", cwd=fixture.remote)
        result = fixture.run(**faults)
        self.assertEqual(result.returncode == 0, success, result.stdout.decode(errors="replace"))
        self.assertEqual(fixture.snapshot(), fixture.original, "Generated bytes entered the worktree")
        events = fixture.events()
        git_events = [event for event in events if event["program"] == "git"]
        commands = [event["args"][0] for event in git_events]
        self.assertFalse(set(commands) & {"pull", "rebase", "reset", "checkout", "switch", "restore"})
        self.assertEqual(commands.count("commit"), 1 if attempts else 0)
        pushes = [event for event in git_events if event["args"][0] == "push"]
        self.assertEqual(len(pushes), attempts)
        self.assertEqual(
            [event["args"] for event in events if event["program"] == "sleep"],
            [[str(delay)] for delay in sleeps],
        )
        if attempts:
            commit = fixture.sha()
            self.assertEqual(
                fixture.git("rev-list", "--parents", "-n", "1", "HEAD").decode().split(),
                [commit, fixture.base],
            )
            self.assertEqual(fixture.git("write-tree"), fixture.git("rev-parse", "HEAD^{tree}"))
            for push in pushes:
                self.assertEqual(push["head"], commit)
                self.assertEqual(push["args"], [
                    "push", f"--force-with-lease={REF}:{fixture.base}", "origin", f"HEAD:{REF}",
                ])
        else:
            self.assertEqual(fixture.sha(), fixture.base)
        if not success:
            self.assertEqual(fixture.git("for-each-ref", cwd=fixture.remote), refs)
        return result

    def assert_rejected(self, fixture, reason):
        result = self.invoke(fixture, success=False, attempts=0)
        self.assertIn(reason, result.stdout)
        self.assertEqual(fixture.tip(), fixture.base)

    def assert_stale(self, fixture, expected_tip):
        result = self.invoke(fixture, success=False)
        self.assertIn(b"start a new generation run", result.stdout)
        self.assertEqual(fixture.tip(), expected_tip)

    def test_valid_text_binary_and_deletions(self):
        with Fixture() as fixture:
            changes = {
                OUTPUT: b"generated bindings\n", BINARY: bytes(range(256)) * 2,
                REMOVED: None, REMOVED_BINARY: None,
                "aws-lc-fips-sys/src/added.rs": b"new bindings\n",
            }
            fixture.make_patch(changes)
            self.assertIn(b"GIT binary patch", fixture.patch.read_bytes())
            self.invoke(fixture)
            commit = fixture.sha()
            self.assertEqual(fixture.tip(), commit)
            for name, expected in changes.items():
                if expected is None:
                    self.assertEqual(fixture.git(
                        "ls-tree", "--name-only", commit, "--", name, cwd=fixture.remote,
                    ), b"")
                else:
                    self.assertEqual(fixture.git("show", f"{commit}:{name}", cwd=fixture.remote), expected)

    def test_no_change_patch_still_commits_original_tree(self):
        with Fixture() as fixture:
            fixture.patch.write_bytes(b"")
            self.invoke(fixture)
            self.assertEqual(fixture.tip(), fixture.sha())
            self.assertEqual(fixture.git("rev-parse", "HEAD^{tree}"),
                             fixture.git("rev-parse", f"{fixture.base}^{{tree}}"))

    def test_rejects_paths_outside_allowlist(self):
        with Fixture() as fixture:
            fixture.make_patch({"generator-input.txt": b"untrusted input edit\n"})
            self.assert_rejected(fixture, b"Patches change files outside of:")

    def test_rejects_executable_files(self):
        with Fixture() as fixture:
            fixture.make_patch({OUTPUT: b"executable bindings\n"})
            (fixture.generator / OUTPUT).chmod(0o755)
            fixture.git("add", OUTPUT, cwd=fixture.generator)
            fixture.export_patch()
            self.assert_rejected(fixture, b"Patches add unexpected file types or modes:")

    def test_rejects_symlinks(self):
        with Fixture() as fixture:
            path = fixture.generator / OUTPUT
            path.unlink()
            path.symlink_to("../../generator-input.txt")
            fixture.git("add", OUTPUT, cwd=fixture.generator)
            fixture.export_patch()
            self.assert_rejected(fixture, b"Patches add unexpected file types or modes:")

    def test_rejects_gitlinks(self):
        with Fixture() as fixture:
            fixture.git("update-index", "--add", "--cacheinfo",
                        f"160000,{fixture.base},aws-lc-sys/src/submodule", cwd=fixture.generator)
            fixture.export_patch()
            self.assert_rejected(fixture, b"Patches add unexpected file types or modes:")

    def test_rejects_git_metadata_paths(self):
        for name in (".gitignore", ".gitattributes", ".gitmodules", ".gitconfig", ".github/config"):
            with self.subTest(path=name), Fixture() as fixture:
                fixture.make_patch({f"aws-lc-sys/src/{name}": b"untrusted metadata\n"})
                self.assert_rejected(fixture, b"Patches add unexpected file types or modes:")

    def test_unrelated_input_advance_requires_fresh_generation(self):
        with Fixture() as fixture:
            fixture.make_patch({OUTPUT: b"generated from original input\n"})
            actor = fixture.root / "actor"
            fixture.git("clone", "--quiet", str(fixture.remote), str(actor), cwd=fixture.root)
            (actor / "generator-input.txt").write_bytes(b"new generation input\n")
            fixture.git("add", "generator-input.txt", cwd=actor)
            fixture.git("commit", "--quiet", "-m", "Advance unrelated input", cwd=actor)
            fixture.git("push", "--quiet", "origin", f"HEAD:{REF}", cwd=actor)
            advanced = fixture.tip()
            # Disjoint input/output edits would rebase cleanly, but invalidate generation.
            self.assertEqual(fixture.git("diff", "--name-only", fixture.base, advanced,
                                         cwd=fixture.remote), b"generator-input.txt\n")
            self.assert_stale(fixture, advanced)

    def test_rewind_is_not_overwritten(self):
        with Fixture() as fixture:
            fixture.make_patch({OUTPUT: b"generated bindings\n"})
            fixture.git("update-ref", REF, fixture.previous, fixture.base, cwd=fixture.remote)
            self.assert_stale(fixture, fixture.previous)

    def test_deleted_branch_is_not_recreated(self):
        with Fixture() as fixture:
            fixture.make_patch({OUTPUT: b"generated bindings\n"})
            fixture.git("update-ref", "-d", REF, fixture.base, cwd=fixture.remote)
            self.assert_stale(fixture, None)

    def test_transient_rejections_retry_identical_commit(self):
        for failed_queries in (0, 2):
            with self.subTest(query_failures=failed_queries), Fixture() as fixture:
                fixture.make_patch({OUTPUT: b"generated bindings\n"})
                self.invoke(fixture, attempts=3, sleeps=(5, 10),
                            rejections=2, query_failures=failed_queries)
                self.assertEqual(fixture.tip(), fixture.sha())

    def test_permanent_rejections_have_five_attempts_and_four_sleeps(self):
        for failed_queries in (0, 5):
            with self.subTest(query_failures=failed_queries), Fixture() as fixture:
                fixture.make_patch({OUTPUT: b"generated bindings\n"})
                self.invoke(fixture, success=False, attempts=5, sleeps=(5, 10, 15, 20),
                            rejections=5, query_failures=failed_queries)
                self.assertEqual(fixture.tip(), fixture.base)

    def test_lost_acknowledgement_is_success_without_retry(self):
        with Fixture() as fixture:
            fixture.make_patch({OUTPUT: b"generated bindings\n"})
            self.invoke(fixture, lost_ack=True)
            queries = [event for event in fixture.events()
                       if event["program"] == "git" and event["args"][0] == "ls-remote"]
            self.assertEqual(len(queries), 1)
            self.assertEqual(fixture.tip(), fixture.sha())


if __name__ == "__main__":
    unittest.main()
