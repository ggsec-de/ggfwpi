"""Extracted GGFW component: errors."""


class GGFWRuntimeError(RuntimeError):
    """A controlled tool/runtime failure that must exit with status 1."""

class SummaryInvariantError(GGFWRuntimeError):
    """Raised when report summary accounting is internally inconsistent."""
