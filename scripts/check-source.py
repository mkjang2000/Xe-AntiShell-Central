#!/usr/bin/env python3
"""Check publishable source without printing matching source or secret values."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


MAX_SOURCE_BYTES = 4 * 1024 * 1024
PROTECTED_DIRS = frozenset({
    ".aws", ".ssh", ".gnupg", ".codex", ".agents", ".local", ".kube",
    ".azure", ".docker",
})
GENERATED_DIRS = frozenset({
    "build", "dist", "release", "coverage", "cache", ".cache", "node_modules",
    "__pycache__", ".venv",
})
PRIVATE_NAMES = frozenset({
    "web-auth.json", "panel-auth.json", "state.json", "operator-token", "policy-key", "id_rsa",
    "id_ed25519", "id_ecdsa", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    "auth.json", "credentials", "credentials.json", "token", "recovery-key",
    "recovery-code", "recovery-codes", "totp-secret", "bootstrap-token",
})
PRIVATE_GLOBS = (
    "*enrollment-token*", "*initial-password*", "*offline-recovery*",
    "*admin.headers", "*.rpmnew", "*.rpmsave",
)
PRIVATE_SUFFIXES = (
    ".db", ".db-shm", ".db-wal", ".sqlite", ".sqlite3", ".sqlite-shm",
    ".sqlite-wal", ".sqlite3-shm", ".sqlite3-wal", ".sock", ".log", ".pem",
    ".key", ".ppk", ".p12", ".pfx", ".crt", ".csr", ".rpm", ".tar", ".tar.gz",
    ".tar.xz", ".tgz", ".zip", ".deb", ".exe", ".dll", ".so", ".dylib",
    ".o", ".a", ".pyc",
)
CONTENT_RULES = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----")),
    ("private-key", re.compile(r"-----BEGIN PGP (?:PRIVATE) KEY BLOCK-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"\bBearer[ \t]+[A-Za-z0-9._~+/-]{20,}", re.IGNORECASE)),
    ("docker-host-inventory", re.compile(r"\bdocker-[0-9a-f]{64}\.scope\b", re.IGNORECASE)),
)


class CheckError(Exception):
    """An operational error with a fixed, non-sensitive diagnostic."""


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str


def path_rule(path: str) -> str | None:
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or ".." in parts:
        return "invalid-source-path"
    if any(part in PROTECTED_DIRS for part in parts):
        return "protected-directory"
    if any(part in GENERATED_DIRS for part in parts):
        return "generated-artifact"
    if path.startswith("configs/hosts/") or path == "configs/hosts":
        return "private-host-config"
    if (path.startswith("devdocs/analysis/") and
            path.endswith(("-install.md", "-validation.md"))):
        return "private-deployment-record"
    if path == "packaging/systemd/sentinel-central-local-ports.conf":
        return "private-host-override"
    name = parts[-1].lower()
    if (name in PRIVATE_NAMES or (name.startswith(".env") and name != ".env.example") or
            any(fnmatch.fnmatchcase(name, pattern) for pattern in PRIVATE_GLOBS)):
        return "runtime-credential-file"
    if name.endswith(PRIVATE_SUFFIXES):
        return "runtime-or-binary-artifact"
    return None


def git_candidates(root: Path) -> list[str] | None:
    try:
        probe = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise CheckError("cannot select source candidates") from None
    if probe.returncode != 0:
        return None
    try:
        if Path(os.fsdecode(probe.stdout.rstrip(b"\n"))).resolve() != root:
            return None
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
    except OSError:
        raise CheckError("cannot select source candidates") from None
    if result.returncode != 0:
        raise CheckError("cannot select source candidates")
    return sorted({os.fsdecode(path) for path in result.stdout.split(b"\0") if path})


def archive_candidates(root: Path) -> list[str]:
    candidates = []

    def walk_error(_error: OSError) -> None:
        raise CheckError("cannot enumerate source archive")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in list(dirs):
            path = Path(directory, name)
            relative = path.relative_to(root).as_posix()
            if name == ".git" or name in GENERATED_DIRS:
                dirs.remove(name)
            elif name in PROTECTED_DIRS or path.is_symlink():
                # Record the directory name, but never enter or read its contents.
                candidates.append(relative)
                dirs.remove(name)
        for name in files:
            if name != ".git":
                candidates.append(Path(directory, name).relative_to(root).as_posix())
    return sorted(candidates)


def read_source(root: Path, relative: str) -> bytes:
    """Open each component without following symlinks, including parent dirs."""
    descriptors = []
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(current)
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=current)
            descriptors.append(current)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=current)
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CheckError("non-regular-source-file")
        if info.st_size > MAX_SOURCE_BYTES:
            raise CheckError("oversized-source-file")
        chunks = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_SOURCE_BYTES:
            raise CheckError("oversized-source-file")
        return data
    except OSError:
        # Do not expose the OS error: it may embed a private path or file value.
        raise CheckError("unreadable-or-symlink-source") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def load_private_patterns(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    try:
        data = read_source(path.absolute().parent, path.name)
        if len(data) > 65536:
            raise ValueError
        lines = data.decode("utf-8").splitlines()
        patterns = [line.strip().casefold() for line in lines
                    if line.strip() and not line.lstrip().startswith("#")]
        if len(patterns) > 256 or any(not 4 <= len(value) <= 256 for value in patterns):
            raise ValueError
        return tuple(dict.fromkeys(patterns))
    except (OSError, UnicodeError, ValueError, CheckError):
        raise CheckError("cannot read private pattern configuration") from None


def content_findings(path: str, source: str, private_patterns: tuple[str, ...]) -> list[Finding]:
    findings = set()
    for rule, expression in CONTENT_RULES:
        for match in expression.finditer(source):
            findings.add(Finding(path, source.count("\n", 0, match.start()) + 1, rule))
    if private_patterns:
        for number, line in enumerate(source.splitlines(), 1):
            if any(pattern in line.casefold() for pattern in private_patterns):
                findings.add(Finding(path, number, "private-literal"))
    return sorted(findings)


def markdown_targets(source: str):
    """Yield relative link syntax outside fenced and inline code."""
    fence = None
    for number, line in enumerate(source.splitlines(), 1):
        start = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if start:
            marker = start.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence:
            continue
        line = re.sub(r"(`+).*?\1", "", line)
        for match in re.finditer(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^)\n]+)\)", line):
            target = match.group(1).strip()
            if target.startswith("<"):
                yield number, target[1:-1]
            else:
                yield number, re.split(r'\s+[\'\"]', target, maxsplit=1)[0].strip()
        definition = re.match(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)", line)
        if definition:
            yield number, definition.group(1).strip("<>")


def markdown_findings(path: str, source: str, candidates: set[str]) -> list[Finding]:
    findings = []
    for line, target in markdown_targets(source):
        try:
            parsed = urlsplit(target)
        except ValueError:
            findings.append(Finding(path, line, "invalid-markdown-link"))
            continue
        if parsed.scheme.lower() == "file" or re.match(r"^[A-Za-z]:[\\/]", target):
            findings.append(Finding(path, line, "absolute-local-document-link"))
            continue
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        target_path = unquote(parsed.path)
        if target_path.startswith(("/", "\\")):
            findings.append(Finding(path, line, "absolute-local-document-link"))
            continue
        normalized = posixpath.normpath(posixpath.join(posixpath.dirname(path), target_path))
        if normalized == ".." or normalized.startswith("../"):
            findings.append(Finding(path, line, "markdown-path-escape"))
        elif (normalized not in candidates and normalized != "." and
              not any(candidate.startswith(normalized.rstrip("/") + "/")
                      for candidate in candidates)):
            findings.append(Finding(path, line, "missing-publishable-document"))
    return findings


def check(root: Path, private_patterns: tuple[str, ...] = ()) -> tuple[list[Finding], int, str]:
    selected = git_candidates(root)
    mode = "Git candidates" if selected is not None else "source archive"
    if selected is None:
        selected = archive_candidates(root)
    candidates = {path for path in selected if ".git" not in PurePosixPath(path).parts}
    findings = []
    checked = 0
    for path in sorted(candidates):
        rule = path_rule(path)
        if rule:
            findings.append(Finding(path, 0, rule))
            continue
        try:
            data = read_source(root, path)
            if b"\0" in data:
                raise CheckError("binary-source-file")
            try:
                source = data.decode("utf-8")
            except UnicodeDecodeError:
                raise CheckError("binary-source-file") from None
        except CheckError as error:
            findings.append(Finding(path, 0, str(error)))
            continue
        checked += 1
        findings.extend(content_findings(path, source, private_patterns))
        if path.lower().endswith(".md"):
            findings.extend(markdown_findings(path, source, candidates))
    return sorted(set(findings)), checked, mode


class QuietParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "source check: invalid arguments\n")


def main(argv: list[str] | None = None) -> int:
    parser = QuietParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="source root (defaults to this script's project)")
    parser.add_argument("--private-patterns-file", type=Path,
                        help="local-only file containing one private literal per line")
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise CheckError("source root is not a directory")
        patterns = load_private_patterns(args.private_patterns_file)
        findings, checked, mode = check(root, patterns)
    except (OSError, RuntimeError):
        print("source check: cannot access source root", file=sys.stderr)
        return 2
    except CheckError as error:
        print("source check: " + str(error), file=sys.stderr)
        return 2
    for finding in findings:
        print(f"{json.dumps(finding.path, ensure_ascii=True)}:{finding.line}: {finding.rule}")
    print(f"source check: {checked} files checked ({mode}), {len(findings)} issue(s)")
    return int(bool(findings))


if __name__ == "__main__":
    sys.exit(main())
