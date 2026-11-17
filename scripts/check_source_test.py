#!/usr/bin/env python3
"""Isolated regression tests for source-publication checks."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check-source.py")
SPEC = importlib.util.spec_from_file_location("source_check", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class SourceCheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="source check ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name, "source tree")
        self.root.mkdir()

    def write(self, name: str, value: str = "fixture\n") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def git(self, *args: str):
        result = subprocess.run(
            ["git", "-C", str(self.root), *args], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, "temporary Git command failed")

    def init_git(self):
        if shutil.which("git") is None:
            self.skipTest("Git is unavailable")
        self.git("init", "--quiet")

    def run_cli(self, *args: str):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = CHECKER.main(["--root", str(self.root), *args])
        return status, stdout.getvalue() + stderr.getvalue()

    def rules(self):
        return {finding.rule for finding in CHECKER.check(self.root)[0]}

    def test_clean_archive_with_spaces_and_generic_config(self):
        self.write("README.md", "[Guide](<docs/User guide.md#setup>)\n")
        self.write("docs/User guide.md", "# Setup\n")
        self.write("configs/agent.yaml", "mode: monitor\nallow_terminate: false\n")
        self.write(".env.example", "SERVER=https://central.example.invalid\n")
        status, output = self.run_cli()
        self.assertEqual(status, 0, output)
        self.assertIn("4 files checked (source archive), 0 issue(s)", output)

    def test_git_without_first_commit_honors_ignored_private_files(self):
        self.init_git()
        self.write(".gitignore", ".local/\n*.key\n")
        self.write("README.md", "# Public source\n")
        self.write(".local/private.txt", "must never be opened\n")
        self.write("runtime.key", "must never be opened\n")
        original = CHECKER.read_source

        def public_only(root, path):
            self.assertNotIn(path, {".local/private.txt", "runtime.key"})
            return original(root, path)

        with mock.patch.object(CHECKER, "read_source", side_effect=public_only):
            findings, count, mode = CHECKER.check(self.root)
        self.assertEqual(findings, [])
        self.assertEqual(count, 2)
        self.assertEqual(mode, "Git candidates")

    def test_force_tracked_ignored_private_file_is_flagged_without_reading(self):
        self.init_git()
        self.write(".gitignore", "*.key\n.local/\n")
        self.write("runtime.key", "must never be opened\n")
        self.write(".local/private.txt", "must never be opened\n")
        self.git("add", "-f", "runtime.key", ".local/private.txt")
        original = CHECKER.read_source

        def public_only(root, path):
            self.assertNotIn(path, {"runtime.key", ".local/private.txt"})
            return original(root, path)

        with mock.patch.object(CHECKER, "read_source", side_effect=public_only):
            findings, _, _ = CHECKER.check(self.root)
        self.assertEqual({item.rule for item in findings}, {
            "runtime-or-binary-artifact", "protected-directory",
        })

    def test_archive_flags_private_directories_and_files_but_skips_build(self):
        self.write("README.md", "# Public source\n")
        self.write(".aws/credentials", "must never be opened\n")
        self.write("configs/hosts/site.yaml", "must never be opened\n")
        self.write("operator-token", "must never be opened\n")
        self.write("build/generated.key", "excluded generated output\n")
        self.write(".git/internal", "excluded Git metadata\n")
        original = CHECKER.read_source

        def public_only(root, path):
            self.assertEqual(path, "README.md")
            return original(root, path)

        with mock.patch.object(CHECKER, "read_source", side_effect=public_only):
            findings, count, mode = CHECKER.check(self.root)
        self.assertEqual(count, 1)
        self.assertEqual(mode, "source archive")
        self.assertEqual({item.rule for item in findings}, {
            "protected-directory", "private-host-config", "runtime-credential-file",
        })
        self.assertNotIn(".aws/credentials", {item.path for item in findings})

    def test_symlink_files_and_directories_are_not_followed(self):
        outside = Path(self.temporary.name, "outside")
        outside.mkdir()
        (outside / "payload.txt").write_text("gh" + "p_" + "Z" * 36, encoding="utf-8")
        (self.root / "linked.txt").symlink_to(outside / "payload.txt")
        (self.root / "linked-dir").symlink_to(outside, target_is_directory=True)
        findings, count, _ = CHECKER.check(self.root)
        self.assertEqual(count, 0)
        self.assertEqual({item.rule for item in findings}, {"unreadable-or-symlink-source"})
        self.assertEqual({item.path for item in findings}, {"linked.txt", "linked-dir"})

    def test_git_tracked_parent_replaced_with_symlink_is_not_followed(self):
        self.init_git()
        path = self.write("docs/file.md", "# Public source\n")
        self.git("add", "docs/file.md")
        path.unlink()
        path.parent.rmdir()
        outside = Path(self.temporary.name, "outside")
        outside.mkdir()
        (outside / "file.md").write_text("gh" + "p_" + "Z" * 36, encoding="utf-8")
        path.parent.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.rules(), {"unreadable-or-symlink-source"})

    def test_content_rules_report_only_locations_and_categories(self):
        fixtures = {
            "private-key": "-----BEGIN " + "PRIVATE KEY-----",
            "github-token": "gh" + "p_" + "Z" * 36,
            "aws-access-key": "AK" + "IA" + "A" * 16,
            "slack-token": "xo" + "xb-" + "A" * 32,
            "jwt-token": "ey" + "J" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20,
            "bearer-token": "Bear" + "er " + "a" * 32,
        }
        for number, value in enumerate(fixtures.values(), 1):
            self.write(f"samples/sample{number}.txt", "safe line\n" + value + "\n")
        status, output = self.run_cli()
        self.assertEqual(status, 1)
        for rule, value in fixtures.items():
            self.assertIn(":2: " + rule, output)
            self.assertNotIn(value, output)

    def test_docker_scope_inventory_is_detected_without_printing_id(self):
        identifier = "0123456789abcdef" * 4
        self.write("inventory.yaml", "origin: docker-" + identifier + ".scope\n")
        status, output = self.run_cli()
        self.assertEqual(status, 1)
        self.assertIn("docker-host-inventory", output)
        self.assertNotIn(identifier, output)

    def test_invalid_url_userinfo_fixture_is_not_a_secret_rule(self):
        self.write("url_test.go", 'var invalid = "https://operator:fixture@invalid.example"\n')
        self.assertEqual(self.rules(), set())

    def test_markdown_missing_ignored_and_escaping_documents(self):
        self.init_git()
        self.write(".gitignore", "local.md\n")
        self.write("local.md", "# Private local document\n")
        self.write("README.md", (
            "[Missing](missing.md)\n[Local](local.md)\n[Escape](../outside.md)\n"
            "[External](https://example.invalid/missing.md)\n"
            "`[Inline example](ignored-example.md)`\n"
            "```markdown\n[Fenced example](ignored-example.md)\n```\n"
            "[ref]: another-missing.md\n"
        ))
        findings, _, _ = CHECKER.check(self.root)
        self.assertEqual([(item.line, item.rule) for item in findings], [
            (1, "missing-publishable-document"),
            (2, "missing-publishable-document"),
            (3, "markdown-path-escape"),
            (9, "missing-publishable-document"),
        ])

    def test_optional_private_patterns_are_literal_and_never_printed(self):
        self.init_git()
        self.write(".gitignore", ".local/\n")
        private = "validation" + "-host[42]"
        patterns = self.write(".local/patterns.txt", "# Local patterns\n" + private + "\n")
        self.write("README.md", "Inventory: " + private.upper() + "\n")
        status, output = self.run_cli("--private-patterns-file", str(patterns))
        self.assertEqual(status, 1)
        self.assertIn("private-literal", output)
        self.assertNotIn(private, output)
        self.assertNotIn(private.upper(), output)

    def test_all_relative_file_types_and_directories_require_candidates(self):
        self.init_git()
        self.write(".gitignore", "local.yaml\n")
        self.write("local.yaml", "private: local\n")
        self.write("configs/agent.yaml", "mode: monitor\n")
        self.write("cmd/main.go", "package main\n")
        self.write("docs/diagram.svg", "<svg/>\n")
        self.write("README.md", (
            "[Config](configs/agent.yaml)\n[Code](cmd/main.go)\n"
            "[Image](docs/diagram.svg)\n[Directory](docs/)\n[Root](.)\n"
            "[Missing](missing.yaml)\n[Ignored](local.yaml)\n"
            "[Absolute](/private/file.go)\n[File URL](file:///private/file.go)\n"
            "[Windows](C:/private/file.go)\n[Encoded](%2Fprivate/file.go)\n"
        ))
        findings, _, _ = CHECKER.check(self.root)
        self.assertEqual([(item.line, item.rule) for item in findings], [
            (6, "missing-publishable-document"),
            (7, "missing-publishable-document"),
            (8, "absolute-local-document-link"),
            (9, "absolute-local-document-link"),
            (10, "absolute-local-document-link"),
            (11, "absolute-local-document-link"),
        ])

    def test_private_patterns_errors_do_not_print_values_or_path(self):
        patterns = self.write("sensitive-pattern-name", "x\n")
        status, output = self.run_cli("--private-patterns-file", str(patterns))
        self.assertEqual(status, 2)
        self.assertEqual(output, "source check: cannot read private pattern configuration\n")

    def test_no_git_executable_uses_archive_candidates(self):
        self.write("README.md", "# Public source\n")
        with mock.patch.object(CHECKER.subprocess, "run", side_effect=FileNotFoundError):
            findings, count, mode = CHECKER.check(self.root)
        self.assertEqual((findings, count, mode), ([], 1, "source archive"))

    def test_binary_content_and_oversized_files_fail_closed(self):
        self.write("binary.data").write_bytes(b"text\0binary")
        self.write("large.data", "x" * 32)
        with mock.patch.object(CHECKER, "MAX_SOURCE_BYTES", 16):
            self.assertEqual(self.rules(), {"binary-source-file", "oversized-source-file"})

    def test_runtime_inventory_paths_are_forbidden(self):
        for name in (
            "devdocs/analysis/host-install.md", "devdocs/analysis/host-validation.md",
            "packaging/systemd/sentinel-central-local-ports.conf", "runtime/data.sqlite-wal",
            "runtime/offline-recovery.txt", "runtime/web-auth.json", "runtime/panel-auth.json",
        ):
            self.write(name)
        self.assertEqual(self.rules(), {
            "private-deployment-record", "private-host-override", "runtime-or-binary-artifact",
            "runtime-credential-file",
        })


if __name__ == "__main__":
    unittest.main()
