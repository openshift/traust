#!/usr/bin/env python3
"""Tag and release helper for this repo. Operates on cwd only.

For workspace-wide stack releases, use tools/release.py in the mono-checkout.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

VERSION_FILE = "VERSION"
PYPROJECT_FILE = "pyproject.toml"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
VERSION_LINE = re.compile(r"(?m)^version = \"[^\"]+\"")
PYPROJECT_VERSION = re.compile(r"(?m)^version = \"([^\"]+)\"")
BUMP_PARTS = frozenset({"major", "minor", "patch"})


class ReleaseError(Exception):
    pass


def semver_tuple(version: str) -> tuple[int, int, int]:
    return tuple(map(int, version.split(".")))


def bump_version(current: str, part: str) -> str:
    if part in BUMP_PARTS:
        major, minor, patch = map(int, current.split("."))
        if part == "major":
            return f"{major + 1}.0.0"
        if part == "minor":
            return f"{major}.{minor + 1}.0"
        return f"{major}.{minor}.{patch + 1}"
    if SEMVER.match(part):
        return part
    raise ReleaseError(f"bump must be major, minor, patch, or X.Y.Z; got {part!r}")


# --- Git ---


@dataclass(frozen=True)
class GitOpts:
    force: bool = False
    allow_dirty: bool = False


class Git:
    def __init__(self, cwd: Path, opts: GitOpts | None = None) -> None:
        self.cwd = cwd
        self.opts = opts or GitOpts()

    def _run(
        self,
        *args: str,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, cwd=self.cwd, check=check, text=True, capture_output=capture)

    def status(self) -> str:
        return self._run("git", "status", "--porcelain", capture=True).stdout.strip()

    def branch(self) -> str:
        return self._run("git", "rev-parse", "--abbrev-ref", "HEAD", capture=True).stdout.strip()

    def head(self) -> str:
        return self._run("git", "rev-parse", "--short", "HEAD", capture=True).stdout.strip()

    def tags(self, pattern: str = "v*") -> list[str]:
        out = self._run(
            "git", "tag", "--list", pattern, "--sort=-v:refname", capture=True
        ).stdout.strip()
        return out.splitlines() if out else []

    def tag_exists(self, tag: str) -> bool:
        return (
            self._run(
                "git",
                "rev-parse",
                "--verify",
                f"refs/tags/{tag}",
                check=False,
                capture=True,
            ).returncode
            == 0
        )

    def create_tag(self, tag: str, message: str) -> None:
        if self.opts.force and self.tag_exists(tag):
            self._run("git", "tag", "-d", tag)
        self._run("git", "tag", "-a", tag, "-m", message)

    def push(self, *refs: str) -> None:
        cmd = ["git", "push"]
        if self.opts.force:
            cmd.append("--force")
        cmd.append("origin")
        for ref in refs:
            self._run(*cmd, ref)

    @property
    def dirty(self) -> bool:
        return bool(self.status())

    def require_clean(self) -> None:
        if not self.opts.allow_dirty and self.dirty:
            raise ReleaseError("working tree is not clean")


# --- Repo ---


class Repo:
    def __init__(self, path: Path, opts: GitOpts) -> None:
        self.path = path
        self.git = Git(path, opts)

    @property
    def name(self) -> str:
        return self.path.name

    def version(self) -> str:
        vf = self.path / VERSION_FILE
        pj = self.path / PYPROJECT_FILE
        if not vf.is_file() or not pj.is_file():
            raise ReleaseError(f"missing {VERSION_FILE} or {PYPROJECT_FILE}")
        v_file, text = vf.read_text().strip(), pj.read_text()
        m = PYPROJECT_VERSION.search(text)
        if not m:
            raise ReleaseError(f"no [project] version in {PYPROJECT_FILE}")
        if v_file != m.group(1):
            raise ReleaseError(f"VERSION ({v_file}) != pyproject.toml ({m.group(1)})")
        return v_file

    def set_version(self, version: str) -> None:
        if not SEMVER.match(version):
            raise ReleaseError(f"invalid semver: {version!r}")
        self._require_tag_missing(version)
        pj = self.path / PYPROJECT_FILE
        text = pj.read_text()
        if not VERSION_LINE.search(text):
            raise ReleaseError(f"could not find version field in {PYPROJECT_FILE}")
        (self.path / VERSION_FILE).write_text(f"{version}\n")
        pj.write_text(VERSION_LINE.sub(f'version = "{version}"', text, count=1))

    def tag_name(self, version: str | None = None) -> str:
        return f"v{version or self.version()}"

    def status(self) -> None:
        v = self.version()
        tags = self.git.tags()
        tagged = self.git.tag_exists(self.tag_name(v))
        latest = tags[0] if tags else "none"
        print(
            f"{self.name}: {v} ({'tagged' if tagged else 'not tagged'}, "
            f"tree {'dirty' if self.git.dirty else 'clean'}, "
            f"branch {self.git.branch()}@{self.git.head()}, latest tag {latest})"
        )

    def check(self) -> None:
        self.git.require_clean()
        self._require_tag_missing(self.version())

    def test(self) -> None:
        env = os.environ.copy()
        subprocess.run(("uv", "sync"), cwd=self.path, check=True, env=env)
        subprocess.run(
            ("uv", "run", "pytest", "tests/", "-q", "-m", "not integration"),
            cwd=self.path,
            check=True,
            env=env,
        )

    def build(self) -> None:
        subprocess.run(("uv", "build"), cwd=self.path, check=True)

    def tag(self, message: str | None = None) -> str:
        v = self.version()
        tag = self.tag_name(v)
        self._require_tag_missing(v)
        self.git.create_tag(tag, message or f"{self.name} {v}")
        return tag

    def push(self) -> None:
        v = self.version()
        tag = self.tag_name(v)
        if not self.git.tag_exists(tag):
            raise ReleaseError(f"tag {tag} does not exist locally")
        self.git.push(self.git.branch(), tag)

    def release(
        self,
        *,
        skip_test: bool = False,
        message: str | None = None,
        push: bool = False,
    ) -> str:
        self.check()
        if not skip_test:
            print(f"==> test {self.name}")
            self.test()
        print(f"==> build {self.name}")
        self.build()
        tag = self.tag(message)
        print(f"{self.name}: release ready at {tag}")
        if push:
            self.push()
            print(f"{self.name}: pushed {tag}")
        return tag

    def latest_tag_version(self) -> str | None:
        tags = self.git.tags()
        if not tags:
            return None
        tag = tags[0]
        return tag[1:] if tag.startswith("v") else tag

    def release_if_ready(self, *, message: str | None = None, push: bool = False) -> str | None:
        current = self.version()
        latest = self.latest_tag_version()

        if self.git.tag_exists(self.tag_name(current)):
            print(f"{self.name}: {self.tag_name(current)} already exists")
            return None

        if latest is not None and semver_tuple(current) == semver_tuple(latest):
            print(f"{self.name}: no pending release (VERSION {current} matches latest tag)")
            return None

        if latest is not None and semver_tuple(current) < semver_tuple(latest):
            raise ReleaseError(f"VERSION {current} is behind latest tag v{latest}")

        return self.release(skip_test=True, message=message or f"{self.name} {current}", push=push)

    def _require_tag_missing(self, version: str) -> None:
        tag = self.tag_name(version)
        if self.git.tag_exists(tag) and not self.git.opts.force:
            raise ReleaseError(f"tag {tag} already exists")


# --- CLI ---


def main(argv: list[str] | None = None) -> int:
    import argparse

    flags = argparse.ArgumentParser(add_help=False)
    flags.add_argument("-m", "--message")
    flags.add_argument("--skip-test", action="store_true")
    flags.add_argument("--allow-dirty", action="store_true")
    flags.add_argument("--push", action="store_true")
    flags.add_argument("--force", action="store_true")

    p = argparse.ArgumentParser(description="Release helper (repo-local)", parents=[flags])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", parents=[flags])
    bump = sub.add_parser("bump", parents=[flags])
    bump.add_argument("part", help="major, minor, patch, or X.Y.Z")
    sub.add_parser("check", parents=[flags])
    sub.add_parser("test", parents=[flags])
    sub.add_parser("build", parents=[flags])
    sub.add_parser("tag", parents=[flags])
    sub.add_parser("push", parents=[flags])
    sub.add_parser("release", parents=[flags])
    sub.add_parser("release-if-ready", parents=[flags])

    args = p.parse_args(argv)
    opts = GitOpts(force=args.force, allow_dirty=args.allow_dirty)
    repo = Repo(Path.cwd(), opts)

    try:
        match args.cmd:
            case "status":
                repo.status()
            case "bump":
                current = repo.version()
                new = bump_version(current, args.part)
                if new == current:
                    print(f"{repo.name}: already at {current}")
                else:
                    repo.set_version(new)
                    print(f"{repo.name}: bumped {current} -> {new}")
            case "check":
                repo.check()
                print(f"{repo.name}: ok ({repo.tag_name()})")
            case "test":
                repo.test()
            case "build":
                repo.build()
                print(f"{repo.name}: wheel built in dist/")
            case "tag":
                repo.git.require_clean()
                print(f"{repo.name}: created {repo.tag(args.message)}")
            case "push":
                repo.push()
                print(f"{repo.name}: pushed {repo.tag_name()}")
            case "release":
                repo.release(skip_test=args.skip_test, message=args.message, push=args.push)
            case "release-if-ready":
                repo.release_if_ready(message=args.message, push=args.push)
    except ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"error: command failed ({exc.cmd})", file=sys.stderr)
        return exc.returncode or 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
