#!/usr/bin/env python3
# Copyright 2026 GG Advanced IT Security UG
# SPDX-License-Identifier: Apache-2.0
"""Compatibility launcher for GGFW 0.7.0 beta."""
import sys
import ggfw as _package
from ggfw import *
from ggfw.cli import execute_main as _execute_main

_EXPECTED_VERSION = "0.7.0-beta"
if TOOL_VERSION != _EXPECTED_VERSION:
    raise RuntimeError(
        f"Launcher expects GGFW {_EXPECTED_VERSION}, package provides {TOOL_VERSION}"
    )

__all__ = list(_package.__all__)

def main() -> int:
    return _execute_main(run_audit)

if __name__ == "__main__":
    sys.exit(main())
