"""Extracted GGFW component: dependencies."""
from ggfw._compat import (
    CRYPT_AVAILABLE, Dict, LIBCRYPT_AVAILABLE, List, Optional, PASSLIB_AVAILABLE, Tuple, os,
    shutil,
)

def _find_executable(name: str, candidates: List[str]) -> Optional[str]:
    """Find an executable without depending on sudo's reduced PATH."""
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which(name)

def check_dependencies() -> Dict[str, Tuple[bool, str]]:
    deps = {
        'vcgencmd': {
            'paths': [
                '/usr/local/bin/vcgencmd', '/usr/bin/vcgencmd',
                '/opt/vc/bin/vcgencmd'
            ],
            'package': 'libraspberrypi-bin',
        },
        'rpi-eeprom-config': {
            'paths': [
                '/usr/local/bin/rpi-eeprom-config',
                '/usr/bin/rpi-eeprom-config',
                '/opt/rpi-eeprom/rpi-eeprom-config'
            ],
            'package': 'rpi-eeprom',
        },
        'rpi-eeprom-update': {
            'paths': [
                '/usr/local/bin/rpi-eeprom-update',
                '/usr/bin/rpi-eeprom-update',
                '/opt/rpi-eeprom/rpi-eeprom-update'
            ],
            'package': 'rpi-eeprom',
        },
        'rpi-eeprom-ab': {
            'paths': [
                '/usr/local/bin/rpi-eeprom-ab',
                '/usr/bin/rpi-eeprom-ab',
                '/usr/sbin/rpi-eeprom-ab'
            ],
            'package': 'rpieepromab',
        },
        'flashrom': {
            'paths': [
                '/usr/local/sbin/flashrom', '/usr/local/bin/flashrom',
                '/usr/sbin/flashrom', '/usr/bin/flashrom'
            ],
            'package': 'flashrom',
        },
    }

    results: Dict[str, Tuple[bool, str]] = {}
    for tool, info in deps.items():
        path = _find_executable(tool, info['paths'])
        results[tool] = (bool(path), path if path else info['package'])

    if PASSLIB_AVAILABLE:
        results['password_verification'] = (True, 'passlib (available)')
    elif CRYPT_AVAILABLE:
        results['password_verification'] = (True, 'crypt (available)')
    elif LIBCRYPT_AVAILABLE:
        results['password_verification'] = (True, 'libcrypt via ctypes (available)')
    else:
        results['password_verification'] = (False, 'disabled')

    return results
