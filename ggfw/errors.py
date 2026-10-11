# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
"""Extracted GGFW component: errors."""


class GGFWRuntimeError(RuntimeError):
    """A controlled tool/runtime failure that must exit with status 1."""

class SummaryInvariantError(GGFWRuntimeError):
    """Raised when report summary accounting is internally inconsistent."""
