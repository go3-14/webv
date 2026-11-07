#!/usr/bin/env python3
"""Thin entry point — all real logic lives in the webv/ package."""

import sys

from webv.cli import main

if __name__ == "__main__":
    sys.exit(main())
