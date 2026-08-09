"""Extracted GGFW component: hardware.interrogator."""
from ggfw._compat import (
    Any, Dict, List, Optional, Tuple, py_platform, re, subprocess,
)
from ggfw.cache import CacheManager
from ggfw.dependencies import _find_executable
from ggfw.files import sha256_file

def parse_version_tuple(value: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r'(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?', value or '')
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
    )

class HardwareInterrogator:
    VCGENCMD_CANDIDATES = [
        '/usr/local/bin/vcgencmd', '/usr/bin/vcgencmd', '/opt/vc/bin/vcgencmd'
    ]
    RPI_EEPROM_CONFIG_CANDIDATES = [
        '/usr/local/bin/rpi-eeprom-config', '/usr/bin/rpi-eeprom-config',
        '/opt/rpi-eeprom/rpi-eeprom-config'
    ]
    RPI_EEPROM_UPDATE_CANDIDATES = [
        '/usr/local/bin/rpi-eeprom-update', '/usr/bin/rpi-eeprom-update',
        '/opt/rpi-eeprom/rpi-eeprom-update'
    ]
    RPI_EEPROM_AB_CANDIDATES = [
        '/usr/local/bin/rpi-eeprom-ab', '/usr/bin/rpi-eeprom-ab',
        '/usr/sbin/rpi-eeprom-ab'
    ]
    FLASHROM_CANDIDATES = [
        '/usr/local/sbin/flashrom', '/usr/local/bin/flashrom',
        '/usr/sbin/flashrom', '/usr/bin/flashrom'
    ]

    def __init__(self):
        self.vcgencmd_path = _find_executable('vcgencmd', self.VCGENCMD_CANDIDATES)
        self.rpi_eeprom_config_path = _find_executable(
            'rpi-eeprom-config', self.RPI_EEPROM_CONFIG_CANDIDATES
        )
        self.rpi_eeprom_update_path = _find_executable(
            'rpi-eeprom-update', self.RPI_EEPROM_UPDATE_CANDIDATES
        )
        self.rpi_eeprom_ab_path = _find_executable(
            'rpi-eeprom-ab', self.RPI_EEPROM_AB_CANDIDATES
        )
        self.flashrom_path = _find_executable('flashrom', self.FLASHROM_CANDIDATES)
        self.cache = CacheManager()

    @staticmethod
    def _run_completed(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    def _run_cmd(self, cmd: List[str], timeout: int = 30, cache: bool = True) -> str:
        cache_key = ' '.join(cmd)
        if cache:
            cached = self.cache.get(cache_key)
            if cached:
                return cached
        try:
            result = self._run_completed(cmd, timeout=timeout)
            output = '\n'.join(
                part.strip() for part in (result.stdout, result.stderr) if part and part.strip()
            )
            if result.returncode != 0:
                return f'ERROR_EXEC: {output}'
            if cache:
                self.cache.set(cache_key, output)
            return output
        except subprocess.TimeoutExpired:
            return f'ERROR_TIMEOUT: command exceeded {timeout}s'
        except FileNotFoundError:
            return 'ERROR_MISSING: Command not found'

    def get_otp_dump(self) -> Dict[str, str]:
        if not self.vcgencmd_path:
            return {}
        raw_output = self._run_cmd([self.vcgencmd_path, 'otp_dump'])
        otp_map: Dict[str, str] = {}
        if raw_output.startswith('ERROR'):
            return otp_map
        for line in raw_output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                otp_map[key.strip()] = value.strip()
        return otp_map

    def get_eeprom_config(self) -> str:
        if not self.rpi_eeprom_config_path:
            return 'ERROR_MISSING: rpi-eeprom-config not found'
        return self._run_cmd([self.rpi_eeprom_config_path])

    def get_bootloader_version(self) -> str:
        if not self.vcgencmd_path:
            return 'UNKNOWN'
        return self._run_cmd([self.vcgencmd_path, 'bootloader_version'])

    def get_tool_metadata(self) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            'kernel_release': py_platform.release(),
            'python_version': py_platform.python_version(),
        }

        if self.flashrom_path:
            output = self._run_cmd([self.flashrom_path, '--version'], cache=False)
            if output.startswith('ERROR'):
                output = self._run_cmd([self.flashrom_path, '-V'], cache=False)
            version = parse_version_tuple(output)
            metadata['flashrom'] = {
                'path': self.flashrom_path,
                'version_output': output[:1000],
                'version': '.'.join(map(str, version)) if version else None,
                'wp_cli_expected': bool(version and version >= (1, 3, 0)),
                'upstream_1_4_to_1_6_write_caution': bool(
                    version and (1, 4, 0) <= version < (1, 7, 0)
                ),
                'ggfw_usage': 'probe/read/wp-status only',
            }
        else:
            metadata['flashrom'] = {'path': None, 'version': None}

        if self.vcgencmd_path:
            metadata['vcgencmd'] = {
                'path': self.vcgencmd_path,
                'firmware_version': self._run_cmd(
                    [self.vcgencmd_path, 'version'], cache=False
                )[:2000],
            }
        else:
            metadata['vcgencmd'] = {'path': None}

        for name, path in (
            ('rpi-eeprom-config', self.rpi_eeprom_config_path),
            ('rpi-eeprom-update', self.rpi_eeprom_update_path),
            ('rpi-eeprom-ab', self.rpi_eeprom_ab_path),
        ):
            entry: Dict[str, Any] = {'path': path}
            if path:
                entry['sha256'] = sha256_file(path)
                if name == 'rpi-eeprom-ab':
                    entry['version_output'] = self._run_cmd(
                        [path, 'version'], cache=False
                    )[:1000]
            metadata[name] = entry

        return metadata
