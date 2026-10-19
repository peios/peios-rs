#!/usr/bin/env python3
"""Verify or refresh the kernel-owned SDK inputs from an exact local Git commit."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

REPOSITORY = "https://github.com/peios/kernel"
SOURCE_PATHS = (
    "include/uapi/pkm",
    "peios/rust/peios-uapi",
    "security/pkm/kacs/peios_uapi.rs",
)
LICENSE_PATHS = (
    "LICENSES/preferred/MIT",
    "LICENSES/dual/Apache-2.0",
    "LICENSES/preferred/GPL-2.0",
    "LICENSES/exceptions/Linux-syscall-note",
)
INPUT_PATHS = SOURCE_PATHS + LICENSE_PATHS
DEFAULT_SNAPSHOT = Path(__file__).absolute().parent.parent / "vendor/kernel"
OWNERSHIP = (
    "Kernel-owned snapshot; update from the source repository, do not edit semantic code here."
)


class SnapshotError(ValueError):
    """The snapshot or requested Git revision cannot be used safely."""


def git(kernel_root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    """Run a local Git read; none of the supported commands contacts a remote."""
    result = subprocess.run(
        ["git", "-C", str(kernel_root), *args],
        input=input_bytes,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise SnapshotError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def exact_commit(kernel_root: Path, commit: str) -> str:
    """Accept a complete commit object ID, never a moving ref or abbreviated ID."""
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise SnapshotError("--commit must be a complete lowercase commit object ID")
    resolved = git(kernel_root, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if resolved.decode().strip() != commit:
        raise SnapshotError("--commit must identify the commit itself, not a tag object")
    return commit


def checked_path(name: str, roots: tuple[str, ...]) -> str:
    """Reject paths that can escape the selected kernel input roots."""
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or str(path) != name:
        raise SnapshotError(f"noncanonical snapshot path: {name!r}")
    if not any(name == root or name.startswith(root + "/") for root in roots):
        raise SnapshotError(f"path outside kernel inputs: {name!r}")
    return name


def tree_entries(kernel_root: Path, commit: str) -> list[tuple[str, str, str]]:
    """Select regular Git blobs, preserving their paths and executable bits."""
    listing = git(kernel_root, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *INPUT_PATHS)
    entries = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        path = checked_path(raw_path.decode("utf-8"), INPUT_PATHS)
        if kind != "blob" or mode not in ("100644", "100755"):
            raise SnapshotError(f"kernel input is not a regular file: {path}")
        entries.append((path, mode, object_id))
    for root in INPUT_PATHS:
        if not any(path == root or path.startswith(root + "/") for path, _, _ in entries):
            raise SnapshotError(f"kernel revision is missing required input: {root}")
    return entries


def export_files(kernel_root: Path, commit: str, destination: Path) -> dict[str, Any]:
    """Copy committed blobs directly, ignoring dirty files and archive attributes."""
    entries = tree_entries(kernel_root, commit)
    batch = "".join(object_id + "\n" for _, _, object_id in entries).encode("ascii")
    contents = git(kernel_root, "cat-file", "--batch", input_bytes=batch)
    offset = 0
    hashes = {}
    modes = {}
    for name, mode, expected_id in entries:
        end = contents.find(b"\n", offset)
        header = contents[offset:end].decode("ascii").split()
        if end < 0 or len(header) != 3 or header[:2] != [expected_id, "blob"]:
            raise SnapshotError(f"unexpected Git blob response for {name}")
        size = int(header[2])
        start = end + 1
        blob = contents[start : start + size]
        offset = start + size + 1
        if len(blob) != size or contents[offset - 1 : offset] != b"\n":
            raise SnapshotError(f"truncated Git blob response for {name}")
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(blob)
        output.chmod(int(mode, 8) & 0o777)
        hashes[name] = hashlib.sha256(blob).hexdigest()
        modes[name] = mode
    if offset != len(contents):
        raise SnapshotError("unexpected trailing data in Git blob response")
    return {
        "repository": REPOSITORY,
        "commit": commit,
        "paths": list(INPUT_PATHS),
        "ownership": OWNERSHIP,
        "files": dict(sorted(hashes.items())),
        "file_modes": dict(sorted(modes.items())),
    }


def load_origin(snapshot: Path, *, allow_legacy: bool, bazel_inputs: bool) -> dict[str, Any]:
    """Validate the metadata before using any of its paths or hashes."""
    origin = snapshot / "ORIGIN.json"
    if (
        not bazel_inputs and (snapshot.is_symlink() or origin.is_symlink())
    ) or not origin.is_file():
        raise SnapshotError("snapshot and ORIGIN.json must be real directories/files")
    try:
        data = json.loads(origin.read_text())
    except (ValueError, UnicodeError) as error:
        raise SnapshotError(f"invalid ORIGIN.json: {error}") from error
    if not isinstance(data, dict) or data.get("repository") != REPOSITORY:
        raise SnapshotError("ORIGIN.json does not identify the Peios kernel repository")
    commit = data.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise SnapshotError("ORIGIN.json has no exact commit ID")
    paths = data.get("paths")
    legacy = allow_legacy and paths == list(SOURCE_PATHS)
    if paths != list(INPUT_PATHS) and not legacy:
        raise SnapshotError("ORIGIN.json input roots do not match this updater")
    hashes = data.get("files")
    if not isinstance(hashes, dict) or not hashes:
        raise SnapshotError("ORIGIN.json must contain file hashes")
    for name, digest in hashes.items():
        checked_path(name, tuple(paths))
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SnapshotError(f"invalid SHA-256 for {name}")
    modes = data.get("file_modes")
    if modes is None and legacy:
        return data
    if not isinstance(modes, dict) or modes.keys() != hashes.keys():
        raise SnapshotError("ORIGIN.json file modes must cover every file")
    if any(mode not in ("100644", "100755") for mode in modes.values()):
        raise SnapshotError("ORIGIN.json contains an unsupported file mode")
    return data


def check_snapshot(
    snapshot: Path, *, allow_legacy: bool = False, bazel_inputs: bool = False
) -> dict[str, Any]:
    """Verify the file set, hashes and Git modes; do not trust symlink targets."""
    data = load_origin(snapshot, allow_legacy=allow_legacy, bazel_inputs=bazel_inputs)
    actual = set()
    for path in snapshot.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) and bazel_inputs and path.is_file():
            # Bazel file symlinks are declared input transport. Directory links
            # remain forbidden so no hidden subtree can bypass file-set checks.
            mode = path.stat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise SnapshotError(f"snapshot contains a nonregular input: {path}")
        if stat.S_ISREG(mode) and path != snapshot / "ORIGIN.json":
            actual.add(path.relative_to(snapshot).as_posix())
    expected = set(data["files"])
    if actual != expected:
        raise SnapshotError(
            f"snapshot file set differs: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    for name, digest in data["files"].items():
        path = snapshot / name
        with path.open("rb") as source:
            actual_digest = hashlib.file_digest(source, "sha256").hexdigest()
        if actual_digest != digest:
            raise SnapshotError(f"kernel-owned input was changed: {name}")
        # Git records executable status, not checkout permissions from umask.
        expected_mode = data.get("file_modes", {}).get(name)
        if (
            expected_mode
            and not bazel_inputs
            and bool(path.stat().st_mode & stat.S_IXUSR) != (expected_mode == "100755")
        ):
            raise SnapshotError(f"kernel-owned file mode was changed: {name}")
    for root in data["paths"]:
        if not any(name == root or name.startswith(root + "/") for name in expected):
            raise SnapshotError(f"snapshot is missing required input: {root}")
    return data


def install_snapshot(staged: Path, destination: Path, backup: Path) -> None:
    """Replace only a verified snapshot and restore it if installation fails."""
    had_previous = destination.exists()
    if had_previous:
        os.replace(destination, backup)
    try:
        os.replace(staged, destination)
    except BaseException:
        if had_previous:
            os.replace(backup, destination)
        raise


def update_snapshot(kernel_root: Path, commit: str, destination: Path) -> dict[str, Any]:
    """Stage and validate a complete replacement before touching the current copy."""
    commit = exact_commit(kernel_root, commit)
    if destination.exists() or destination.is_symlink():
        # The original migration snapshot predates license/mode metadata. It can
        # be upgraded only when its existing source hashes and file set are intact.
        check_snapshot(destination, allow_legacy=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".kernel-update-", dir=destination.parent))
    staged = temporary / "staged"
    backup = temporary / "previous"
    staged.mkdir()
    installed = False
    try:
        metadata = export_files(kernel_root, commit, staged)
        (staged / "ORIGIN.json").write_text(json.dumps(metadata, indent=2) + "\n")
        check_snapshot(staged)
        install_snapshot(staged, destination, backup)
        installed = True
        return metadata
    finally:
        # If rollback itself fails, retain the backup instead of deleting the
        # only copy. An interruption between the two renames is recovered from
        # this same .kernel-update-*/previous directory.
        if installed or not backup.exists():
            shutil.rmtree(temporary)
        else:
            print(f"previous snapshot preserved at {backup}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check the stored hashes, modes and exact file set")
    check.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    check.add_argument(
        "--bazel-inputs",
        action="store_true",
        help="verify declared runfiles hashes/set while allowing file symlinks and cache modes",
    )
    update = commands.add_parser("update", help="replace inputs with an exact local kernel commit")
    update.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    update.add_argument("--kernel-root", type=Path, required=True)
    update.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "check":
            result = check_snapshot(args.snapshot, bazel_inputs=args.bazel_inputs)
        else:
            result = update_snapshot(args.kernel_root, args.commit, args.snapshot)
    except (OSError, SnapshotError) as error:
        print(f"kernel inputs: {error}", file=sys.stderr)
        return 1
    print(f"{len(result['files'])} kernel-owned inputs verified at {result['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
