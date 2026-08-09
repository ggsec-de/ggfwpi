"""Shared standard-library and optional dependency imports."""
import argparse
import base64
import binascii
import struct
import ctypes
import ctypes.util
try:
    import grp
    import pwd
except ImportError:
    grp = None
    pwd = None
import platform as py_platform
import json
import os
import re
import shlex
import sys
import subprocess
import hashlib
import hmac
import glob
import shutil
import logging
import time
import zipfile
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from urllib.parse import urlparse

try:
    from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt
    PASSLIB_AVAILABLE = True
except ImportError:
    sha512_crypt = sha256_crypt = md5_crypt = None
    PASSLIB_AVAILABLE = False

try:
    import crypt
    CRYPT_AVAILABLE = True
except ImportError:
    crypt = None
    CRYPT_AVAILABLE = False

try:
    import cryptography as _cryptography
    from cryptography.exceptions import InvalidSignature as _CryptographyInvalidSignature
    from cryptography.hazmat.primitives import hashes as _cryptography_hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _cryptography_padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _cryptography_rsa
    from cryptography.hazmat.primitives.asymmetric import utils as _cryptography_utils
    CRYPTOGRAPHY_AVAILABLE = True
    CRYPTOGRAPHY_VERSION = getattr(_cryptography, '__version__', 'unknown')
except ImportError:
    _cryptography = None
    class _CryptographyInvalidSignature(Exception):
        pass
    _cryptography_hashes = None
    _cryptography_padding = None
    _cryptography_rsa = None
    _cryptography_utils = None
    CRYPTOGRAPHY_AVAILABLE = False
    CRYPTOGRAPHY_VERSION = None

LIBCRYPT_AVAILABLE = False
_LIBCRYPT = None
try:
    _libcrypt_name = ctypes.util.find_library("crypt")
    if _libcrypt_name:
        _LIBCRYPT = ctypes.CDLL(_libcrypt_name)
        _LIBCRYPT.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _LIBCRYPT.crypt.restype = ctypes.c_char_p
        LIBCRYPT_AVAILABLE = True
except (OSError, AttributeError):
    _LIBCRYPT = None
    LIBCRYPT_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger("ggfw")

__all__ = [name for name in globals() if not name.startswith('__')]
