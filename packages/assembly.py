"""Validate paths in declared source manifests."""

from pathlib import Path


def relative(value: str | Path) -> Path:
    """Return a nonempty relative path without parent-directory components."""
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe package path: {value!r}")
    return path
