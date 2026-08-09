#!/usr/bin/env python3
# Copyright 2026 GG Advanced IT Security UG
# Developed by Maciej Gojny for GGSEC
# SPDX-License-Identifier: Apache-2.0
"""Version-pinned entry point for the GGFW 0.7.0 regression suite."""
import importlib.util
import os
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ["GGFW_MODULE_PATH"] = str(HERE / "GGFWPi_v0.7.0-beta.py")
SUITE_PATH = HERE / "test_GGFWPi_latest.py"
spec = importlib.util.spec_from_file_location("ggfw_regression_suite", SUITE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load regression suite: {SUITE_PATH}")
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)

if __name__ == "__main__":
    unittest.main(module=suite, verbosity=2)
