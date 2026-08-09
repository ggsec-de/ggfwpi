"""Extracted GGFW component: boot.integrity."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, Set, datetime, json, os, timezone,
)
from ggfw.cache import CacheManager
from ggfw.constants import TOOL_VERSION
from ggfw.files import sha256_file
from ggfw.hardware.platform import get_soc_generation

class BootIntegrityChecker:
    BASELINE_SCHEMA = 'ggfw-boot-baseline/v2'

    def __init__(
        self,
        boot_dir: str,
        platform: str,
        config: Optional[Dict[str, Dict[str, str]]] = None,
        baseline_path: Optional[str] = None,
        boot_graph: Optional[Dict[str, Any]] = None,
    ):
        self.boot_dir = str(Path(boot_dir).resolve())
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.config = config or {}
        self.boot_graph = boot_graph or {}
        self.cache = CacheManager()
        self.baseline_path = baseline_path
        self.baseline: Optional[Dict[str, Any]] = None
        self.baseline_error: Optional[str] = None
        self.baseline_legacy: bool = False
        if baseline_path:
            self._load_baseline(baseline_path)

    def _load_baseline(self, path: str):
        try:
            payload = json.loads(Path(path).read_text(encoding='utf-8'))
            schema = payload.get('schema')
            if schema not in {self.BASELINE_SCHEMA, 'ggfw-boot-baseline/v1'}:
                raise ValueError(f"Unsupported baseline schema: {schema!r}")
            self.baseline_legacy = schema == 'ggfw-boot-baseline/v1'
            if not isinstance(payload.get('files'), dict):
                raise ValueError('Baseline does not contain a files object')
            self.baseline = payload
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.baseline_error = str(exc)

    def _all_config_values(self) -> Dict[str, str]:
        merged: Dict[str, str] = {}
        for values in self.config.values():
            merged.update(values)
        return merged

    @staticmethod
    def _safe_relative_name(name: str) -> Optional[str]:
        candidate = name.strip().replace('\\', '/')
        if not candidate or candidate.startswith('/'):
            return None
        normalised = os.path.normpath(candidate)
        if normalised == '..' or normalised.startswith('../'):
            return None
        return normalised

    def get_files_to_check(self) -> List[str]:
        files: Set[str] = set(self.boot_graph.get('active_files', []))
        if not files:
            files.update({'config.txt', 'cmdline.txt'})
            values = self._all_config_values()
            if self.soc == 'BCM2711':
                files.update({'start4.elf', 'fixup4.dat', 'kernel8.img', 'bcm2711-rpi-4-b.dtb'})
            elif self.soc == 'BCM2712':
                files.update({'kernel_2712.img', 'bcm2712-rpi-5-b.dtb'})
            else:
                files.update({'start.elf', 'fixup.dat', 'kernel7.img'})
            for key in ('kernel', 'device_tree', 'armstub'):
                value = values.get(key)
                if value and value.strip().lower() not in {'-', 'none', 'disable'}:
                    safe_name = self._safe_relative_name(value)
                    if safe_name:
                        files.add(safe_name)

        if self.baseline:
            for name in self.baseline.get('files', {}):
                safe_name = self._safe_relative_name(name)
                if safe_name:
                    files.add(safe_name)
        return sorted(name for name in files if self._safe_relative_name(name))

    def calculate_sha256(self, filepath: str) -> Optional[str]:
        cache_key = f'sha256_{filepath}'
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = sha256_file(filepath)
        if result:
            self.cache.set(cache_key, result)
        return result

    def verify_integrity(self) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        baseline_files = self.baseline.get('files', {}) if self.baseline else {}

        for filename in self.get_files_to_check():
            filepath = os.path.join(self.boot_dir, filename)
            file_hash = self.calculate_sha256(filepath)
            expected = baseline_files.get(filename)

            if file_hash is None:
                status = 'MISSING'
                results[filename] = {
                    'status': status,
                    'sha256': None,
                    'size': 0,
                    'expected_sha256': expected.get('sha256') if isinstance(expected, dict) else None,
                    'expected_size': expected.get('size') if isinstance(expected, dict) else None,
                }
                continue

            file_size = os.path.getsize(filepath)
            if isinstance(expected, dict):
                hash_matches = file_hash == expected.get('sha256')
                size_matches = file_size == expected.get('size')
                status = 'BASELINE_MATCH' if hash_matches and size_matches else 'BASELINE_MISMATCH'
            elif self.baseline:
                status = 'BASELINE_MISSING_ENTRY'
            else:
                status = 'PRESENT_HASHED'

            results[filename] = {
                'status': status,
                'sha256': file_hash,
                'size': file_size,
                'expected_sha256': expected.get('sha256') if isinstance(expected, dict) else None,
                'expected_size': expected.get('size') if isinstance(expected, dict) else None,
            }

        return results

    def build_baseline(self, integrity_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        files = {
            name: {
                'sha256': data['sha256'],
                'size': data['size'],
            }
            for name, data in integrity_results.items()
            if data.get('sha256') is not None
        }
        missing = sorted(
            name for name, data in integrity_results.items()
            if data.get('status') == 'MISSING'
        )
        return {
            'schema': self.BASELINE_SCHEMA,
            'tool_version': TOOL_VERSION,
            'created_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            'platform': self.platform,
            'soc': self.soc,
            'boot_path': self.boot_dir,
            'files': files,
            'resolved_chain': {
                'schema': self.boot_graph.get('schema'),
                'fingerprint': self.boot_graph.get('fingerprint'),
                'active_files': self.boot_graph.get('active_files', []),
            },
            'missing_at_creation': missing,
            'trust_note': (
                'This is a device-specific measured baseline, not an official vendor '
                'signature or a universal Raspberry Pi hash database.'
            ),
        }

    def write_baseline(
        self,
        path: str,
        integrity_results: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        payload = self.build_baseline(integrity_results)
        destination = Path(path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + '.tmp')
        temporary.write_text(
            json.dumps(payload, indent=4, ensure_ascii=False) + '\n',
            encoding='utf-8',
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        return payload
