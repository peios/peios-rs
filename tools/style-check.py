#!/usr/bin/env python3
"""Check or format maintained source with the pinned PSC tools."""

import argparse
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED = {
    ".git",
    ".ci-sdk",
    "vendor",
    "target",
    "dist",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    "archive",
}


def sources() -> list[Path]:
    """Enumerate owned source without following build-output symlinks."""
    found = []
    for parent, directories, names in os.walk(ROOT):
        directories[:] = [
            name
            for name in directories
            if name not in EXCLUDED
            and not name.startswith("bazel-")
            and not (Path(parent) == ROOT / "build")
        ]
        for name in names:
            path = Path(parent) / name
            if path.is_symlink() or path.parts[-3:-1] == ("internal", "uapi"):
                continue
            found.append(path.relative_to(ROOT))
    return sorted(found)


def main() -> None:
    """Run the language checks, writing only when --fix is requested."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true")
    args = parser.parse_args()
    paths = sources()
    # These repositories share the pinned formatter profiles; verify the tool
    # identities before accepting output from an arbitrary PATH directory.

    directory = Path(os.environ.get("PEIOS_STYLE_BIN", "/usr/local/bin"))

    expected_versions = {
        "ruff": "ruff 0.17.0",
        "shellcheck": "version: 0.11.0",
        "shfmt": "v3.14.1",
        "buildifier": "buildifier version: 10.1.0",
        "clang-format": "clang-format version 18.1.8",
        "prettier": "3.9.10",
    }
    for name, expected in expected_versions.items():
        output = subprocess.check_output([str(directory / name), "--version"], text=True)
        if expected not in [line.strip() for line in output.splitlines()]:
            raise SystemExit(f"unexpected {name} version; use tools/prepare-style-tools.py")

    def run(command: list[str]) -> None:
        subprocess.run(command, cwd=ROOT, check=True)

    python = [str(p) for p in paths if p.suffix == ".py" or p == Path("tools/check-docs")]
    run(
        [
            str(directory / "ruff"),
            "check",
            "--no-cache",
            "--config",
            "tools/ruff.toml",
            *(["--fix"] if args.fix else []),
            *python,
        ]
    )
    run(
        [
            str(directory / "ruff"),
            "format",
            "--no-cache",
            "--config",
            "tools/ruff.toml",
            *([] if args.fix else ["--check"]),
            *python,
        ]
    )
    shell = [
        str(p)
        for p in paths
        if p.suffix == ".sh" or p.name in {"bazel", "check", "offline-build", "prepare-dev-sdk"}
    ]
    run([str(directory / "shellcheck"), *shell])
    run([str(directory / "shfmt"), "-i", "4", "-w" if args.fix else "-d", *shell])
    starlark = [str(p) for p in paths if p.suffix == ".bzl" or p.name.endswith(".bazel")]
    run(
        [
            str(directory / "buildifier"),
            "-mode=fix" if args.fix else "-mode=check",
            "-lint=warn",
            "-warnings=load,unused-variable,function-docstring",
            *starlark,
        ]
    )
    rust = [str(p) for p in paths if p.suffix == ".rs"]
    if rust:
        run(
            [
                "rustup",
                "run",
                "1.98.1",
                "rustfmt",
                "--config-path",
                "tools/rustfmt.toml",
                *([] if args.fix else ["--check"]),
                *rust,
            ]
        )
    c = [str(p) for p in paths if p.suffix in {".c", ".h"}]
    if c:
        run(
            [
                str(directory / "clang-format"),
                "--style=file:tools/clang-format.yaml",
                *(["-i"] if args.fix else ["--dry-run", "--Werror"]),
                *c,
            ]
        )
    go = [str(p) for p in paths if p.suffix == ".go"]
    if go:
        if args.fix:
            run(["gofmt", "-w", *go])
        elif subprocess.check_output(["gofmt", "-l", *go], cwd=ROOT).strip():
            raise SystemExit("Go formatting differs; run tools/style-check.py --fix")
    data = [
        str(p)
        for p in paths
        if p.suffix in {".json", ".yaml", ".yml"}
        and p.name not in {"package-lock.json", "MODULE.bazel.lock"}
    ]
    if data:
        run(
            [
                str(directory / "prettier"),
                "--config",
                "tools/prettier.json",
                "--write" if args.fix else "--check",
                *data,
            ]
        )


if __name__ == "__main__":
    main()
