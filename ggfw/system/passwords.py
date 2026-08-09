"""Extracted GGFW component: system.passwords."""
from ggfw._compat import (
    Any, CRYPT_AVAILABLE, Dict, LIBCRYPT_AVAILABLE, List, Optional, PASSLIB_AVAILABLE, Path,
    Tuple, _LIBCRYPT, crypt, hashlib, logger, md5_crypt, sha256_crypt, sha512_crypt,
)
from ggfw.errors import GGFWRuntimeError

def verify_password_against_hash(password: str, hash_str: str) -> bool:
    """
    Verify a candidate password against a shadow hash (passlib, then crypt).
    """
    if not hash_str or hash_str in ['!', '*', '']:
        return False

    # Prefer passlib.
    if PASSLIB_AVAILABLE:
        try:
            # Select the matching hash handler.
            if hash_str.startswith('$6$'):  # SHA512
                return sha512_crypt.verify(password, hash_str)
            elif hash_str.startswith('$5$'):  # SHA256
                return sha256_crypt.verify(password, hash_str)
            elif hash_str.startswith('$1$'):  # MD5
                return md5_crypt.verify(password, hash_str)
        except Exception as e:
            logger.debug(f"passlib verification error: {e}")

    # Fall back to the Python crypt module for formats such as yescrypt.
    if CRYPT_AVAILABLE:
        try:
            test_hash = crypt.crypt(password, hash_str)
            return test_hash == hash_str
        except Exception as e:
            logger.debug(f"crypt verification error: {e}")

    # Python 3.13 may omit the crypt module while libxcrypt is still present.
    if LIBCRYPT_AVAILABLE and _LIBCRYPT is not None:
        try:
            encoded = _LIBCRYPT.crypt(password.encode(), hash_str.encode())
            if encoded:
                return encoded.decode(errors='replace') == hash_str
        except Exception as e:
            logger.debug(f"libcrypt verification error: {e}")

    return False

BUILTIN_WEAK_PASSWORDS = (
    'raspberry', 'password', 'password1', 'admin', 'root',
    'toor', 'kali', '123456', '12345678', 'changeme',
)

MAX_WEAK_PASSWORD_FILE_BYTES = 64 * 1024

MAX_EXTERNAL_WEAK_PASSWORDS = 2048

MAX_WEAK_PASSWORD_BYTES = 256

def load_weak_password_dictionary(path: Optional[str]) -> Tuple[Tuple[str, ...], Dict[str, Any]]:
    """Load a bounded UTF-8 wordlist without exposing candidate values."""
    candidates = list(BUILTIN_WEAK_PASSWORDS)
    metadata: Dict[str, Any] = {
        'kind': 'BUILTIN',
        'builtin_count': len(BUILTIN_WEAK_PASSWORDS),
        'external_candidate_count': 0,
        'external_added_count': 0,
        'total_count': len(BUILTIN_WEAK_PASSWORDS),
        'external_file_sha256': None,
    }
    if path is None:
        return tuple(candidates), metadata

    wordlist_path = Path(path).expanduser().resolve()
    try:
        with wordlist_path.open('rb') as handle:
            raw = handle.read(MAX_WEAK_PASSWORD_FILE_BYTES + 1)
    except OSError as exc:
        raise GGFWRuntimeError(
            f'Unable to read --weak-password-file {wordlist_path}: {exc}'
        ) from exc
    if len(raw) > MAX_WEAK_PASSWORD_FILE_BYTES:
        raise GGFWRuntimeError(
            f'--weak-password-file exceeds {MAX_WEAK_PASSWORD_FILE_BYTES} bytes: {wordlist_path}'
        )
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise GGFWRuntimeError(
            f'--weak-password-file is not valid UTF-8 at byte {exc.start}: {wordlist_path}'
        ) from exc

    external: List[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        encoded = line.encode('utf-8')
        if b'\x00' in encoded:
            raise GGFWRuntimeError(
                f'--weak-password-file contains NUL at line {line_number}: {wordlist_path}'
            )
        if len(encoded) > MAX_WEAK_PASSWORD_BYTES:
            raise GGFWRuntimeError(
                f'--weak-password-file line {line_number} exceeds '
                f'{MAX_WEAK_PASSWORD_BYTES} bytes: {wordlist_path}'
            )
        external.append(line)
        if len(external) > MAX_EXTERNAL_WEAK_PASSWORDS:
            raise GGFWRuntimeError(
                f'--weak-password-file exceeds {MAX_EXTERNAL_WEAK_PASSWORDS} candidates: '
                f'{wordlist_path}'
            )

    seen = set(candidates)
    added = 0
    for candidate in external:
        if candidate not in seen:
            candidates.append(candidate)
            seen.add(candidate)
            added += 1
    metadata.update({
        'kind': 'BUILTIN_PLUS_EXTERNAL',
        'external_candidate_count': len(external),
        'external_added_count': added,
        'total_count': len(candidates),
        'external_file_sha256': hashlib.sha256(raw).hexdigest(),
    })
    return tuple(candidates), metadata
