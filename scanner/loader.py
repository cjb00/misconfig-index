from __future__ import annotations

from pathlib import Path
from typing import Iterator, Tuple


def walk_files(root: Path) -> Iterator[Tuple[Path, str]]:
    """
    Walk a directory and yield (path, content). Ignores binary read errors.
    """
    for path in root.rglob("*"):
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            yield path, content
