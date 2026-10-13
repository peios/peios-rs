#!/usr/bin/env python3
"""Exercise the real Cargo build script against isolated pkg-config fixtures.

Requires Python 3.11+, pkg-config, and a compatible libpeios SDK. Select that SDK
with PEIOS_LIB_DIR, PEIOS_INCLUDE and PKM_UAPI. Cargo's target directory can be
set with CARGO_TARGET_DIR; temporary pkg-config files are removed automatically.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = tomllib.loads((ROOT / "peios-sys/Cargo.toml").read_text())
FLOOR = MANIFEST["package"]["metadata"]["libpeios"]["minimum-version"]
parts = list(map(int, FLOOR.split(".")))
index = max(index for index, value in enumerate(parts) if value)
parts[index] -= 1
OLD = ".".join(map(str, parts))
CRATE_VERSION = MANIFEST["package"]["version"]
SDK = {key: os.environ[key] for key in ("PEIOS_LIB_DIR", "PEIOS_INCLUDE", "PKM_UAPI")}


def check(directory, label, version, static=False, override=False):
    """Run Cargo, and check rejection happens before binding generation."""
    pc_dir = directory / label
    pc_dir.mkdir()
    if version is not None:
        # The rejected SDK deliberately has no headers. Its version diagnostic
        # must precede any clang/missing-symbol failure.
        include = SDK["PEIOS_INCLUDE"] if version != OLD else str(pc_dir / "absent")
        (pc_dir / "peios.pc").write_text(
            f"Name: peios\nDescription: version-check fixture\nVersion: {version}\n"
            f"Libs: -L{SDK['PEIOS_LIB_DIR']} -lpeios\n"
            f"Cflags: -I{include} -I{SDK['PKM_UAPI']}\n"
        )
    env = os.environ.copy()
    for key in SDK:
        env.pop(key, None)
    # Prevent an installed host SDK or target-specific overrides from replacing
    # the fixture. The test itself is a native host build.
    for key in list(env):
        if key.startswith(("PKG_CONFIG", "HOST_PKG_CONFIG", "TARGET_PKG_CONFIG", "PEIOS_")):
            env.pop(key, None)
    env["PKG_CONFIG_PATH"] = str(pc_dir)
    env["PKG_CONFIG_LIBDIR"] = str(pc_dir)
    if override:
        env.update(SDK)
    command = ["cargo", "check", "--offline", "--workspace"]
    if static:
        command += ["--features", "static"]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    rejected = not override and version in (None, OLD)
    if rejected:
        detected = version if version is not None else "not found"
        message = f"peios-sys {CRATE_VERSION} requires libpeios >= {FLOOR}; detected: {detected}."
        assert result.returncode != 0 and message in result.stderr, result.stderr
        assert "bindgen failed" not in result.stderr, result.stderr
        assert "cannot find function" not in result.stderr, result.stderr
    else:
        assert result.returncode == 0, result.stderr
    print(f"PASS {label}", flush=True)
    if rejected:
        print(message, flush=True)


def main():
    major, minor, patch = map(int, FLOOR.split("."))
    newer = f"{major}.{minor}.{patch + 1}"
    with tempfile.TemporaryDirectory(prefix="peios-sdk-version-") as temporary:
        directory = Path(temporary)
        for static in (False, True):
            mode = "static" if static else "dynamic"
            check(directory, f"{mode}-old", OLD, static)
            check(directory, f"{mode}-missing", None, static)
            check(directory, f"{mode}-minimum", FLOOR, static)
            check(directory, f"{mode}-newer", newer, static)
            # An incompatible pc must not override the explicit development SDK.
            check(directory, f"{mode}-explicit-override", OLD, static, True)


if __name__ == "__main__":
    main()
