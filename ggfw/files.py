# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
"""Extracted GGFW component: files."""
from ggfw._compat import Optional, hashlib

def sha256_file(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None
