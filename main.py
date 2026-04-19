#!/usr/bin/env python3

import sys
from pathlib import Path


def _prepend_src_to_path() -> None:
    project_root = Path(__file__).resolve().parent
    src_path = str((project_root / "src").resolve())
    normalized_paths = {str(Path(existing).resolve()) for existing in sys.path if existing}
    if src_path not in normalized_paths:
        sys.path.insert(0, src_path)


def main() -> int:
    _prepend_src_to_path()
    from web_scanner.main import run_scanner

    return run_scanner()


if __name__ == "__main__":
    raise SystemExit(main())
