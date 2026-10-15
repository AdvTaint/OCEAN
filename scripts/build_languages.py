#!/usr/bin/env python3
"""Build the combined tree-sitter language bundle (my-languages.so).

Usage:
    python scripts/build_languages.py --grammars /path/to/tree-sitter-c /path/to/tree-sitter-cpp \
        --output my-languages.so

Requires the pinned tree-sitter Python package (see requirements.txt); its
Language.build_library API drives the bundled C compiler toolchains.
"""
from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grammars", nargs="+", required=True,
                        help="Directories containing tree-sitter grammar repos.")
    parser.add_argument("--output", required=True,
                        help="Output .so path for the combined library.")
    args = parser.parse_args()

    for path in args.grammars:
        if not os.path.isdir(path):
            parser.error(f"grammar directory not found: {path}")

    from tree_sitter import Language

    Language.build_library(args.output, args.grammars)
    print(f"Built {args.output} from: {', '.join(args.grammars)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
