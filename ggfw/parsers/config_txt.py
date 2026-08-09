"""Extracted GGFW component: parsers.config_txt."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, re,
)

def parse_simple_config(text: str) -> Dict[str, str]:
    """Parse simple KEY=VALUE configuration while ignoring sections/comments."""
    values: Dict[str, str] = {}
    if not text or text.startswith('ERROR'):
        return values
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith('[') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip().upper()] = value.strip()
    return values

BOOT_MODE_MAP = {
    '0': 'SD_CARD_DETECT',
    '1': 'SD_CARD',
    '2': 'NETWORK',
    '3': 'RPIBOOT',
    '4': 'USB_MSD',
    '5': 'BCM_USB_MSD',
    '6': 'NVME',
    '7': 'HTTP',
    'e': 'STOP',
    'f': 'RESTART',
}

def decode_boot_order(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {'raw': value, 'valid': False, 'sequence': [], 'unknown_digits': []}
    cleaned = value.strip().lower()
    if cleaned.startswith('0x'):
        cleaned = cleaned[2:]
    sequence = []
    unknown = []
    for digit in reversed(cleaned):
        mode = BOOT_MODE_MAP.get(digit)
        if mode:
            sequence.append({'digit': digit, 'mode': mode})
        else:
            unknown.append(digit)
            sequence.append({'digit': digit, 'mode': 'UNKNOWN'})
    return {
        'raw': value,
        'read_direction': 'right-to-left',
        'valid': bool(cleaned) and not unknown,
        'sequence': sequence,
        'unknown_digits': unknown,
        'contains_network': any(item['mode'] in {'NETWORK', 'HTTP'} for item in sequence),
        'contains_rpiboot': any(item['mode'] == 'RPIBOOT' for item in sequence),
        'contains_external_media': any(item['mode'] in {'USB_MSD', 'BCM_USB_MSD', 'NVME'} for item in sequence),
    }

class ConfigTxtParser:
    """Parse config.txt while preserving order, duplicates, includes and provenance."""

    MAX_INCLUDE_DEPTH = 8

    @staticmethod
    def _section_applicability(section: str, platform: str) -> str:
        name = section.strip().lower()
        platform_lower = platform.lower()
        if name in {'all', ''}:
            return 'ACTIVE'
        if name == 'pi5':
            return 'ACTIVE' if 'raspberry pi 5' in platform_lower else 'INACTIVE'
        if name == 'pi4':
            return 'ACTIVE' if 'raspberry pi 4' in platform_lower else 'INACTIVE'
        if name == 'cm5':
            return 'ACTIVE' if 'compute module 5' in platform_lower else 'INACTIVE'
        if name == 'cm4':
            return 'ACTIVE' if 'compute module 4' in platform_lower else 'INACTIVE'
        if name.startswith('none'):
            return 'INACTIVE'
        # Board-revision and EDID filters require more context than model detection.
        return 'UNKNOWN'

    @classmethod
    def parse_detailed(
        cls,
        filepath: str,
        boot_dir: str = '',
        platform: str = 'Unknown Raspberry Pi',
    ) -> Dict[str, Any]:
        root = Path(filepath).expanduser().resolve()
        boot_root = Path(boot_dir or root.parent).expanduser().resolve()
        directives: List[Dict[str, Any]] = []
        includes: List[Dict[str, Any]] = []
        errors: List[str] = []
        parsed_files: List[str] = []
        sequence = 0

        def parse_file(path: Path, depth: int, inherited_section: str = 'all', stack: Optional[List[Path]] = None):
            nonlocal sequence
            stack = list(stack or [])
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if depth > cls.MAX_INCLUDE_DEPTH:
                errors.append(f'include depth exceeded at {resolved}')
                return
            if resolved in stack:
                errors.append(f'include cycle detected: {resolved}')
                return
            if not resolved.exists():
                errors.append(f'config file not found: {resolved}')
                return
            stack.append(resolved)
            parsed_files.append(str(resolved))
            section = inherited_section
            try:
                lines = resolved.read_text(encoding='utf-8', errors='replace').splitlines()
            except OSError as exc:
                errors.append(f'{resolved}: {exc}')
                return

            for line_number, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                section_match = re.match(r'^\[([^\]]+)\]$', line)
                if section_match:
                    section = section_match.group(1).strip().lower()
                    continue

                include_match = re.match(r'^include\s+(.+)$', line, re.IGNORECASE)
                if include_match:
                    include_name = include_match.group(1).strip()
                    include_path = (boot_root / include_name).resolve()
                    applicability = cls._section_applicability(section, platform)
                    includes.append({
                        'source': str(resolved),
                        'line': line_number,
                        'section': section,
                        'applicability': applicability,
                        'target': str(include_path),
                        'exists': include_path.exists(),
                    })
                    # Raspberry Pi includes inherit the current conditional context.
                    if applicability != 'INACTIVE':
                        parse_file(include_path, depth + 1, section, stack)
                    continue

                if '=' in line:
                    key, value = line.split('=', 1)
                else:
                    parts = line.split(None, 1)
                    key = parts[0]
                    value = parts[1] if len(parts) > 1 else ''

                sequence += 1
                directives.append({
                    'sequence': sequence,
                    'source': str(resolved),
                    'line': line_number,
                    'section': section,
                    'applicability': cls._section_applicability(section, platform),
                    'key': key.strip().lower(),
                    'value': value.strip(),
                    'raw': raw_line.rstrip('\n'),
                })

        parse_file(root, 0)

        sections: Dict[str, Dict[str, str]] = {'all': {}}
        active_config: Dict[str, Dict[str, str]] = {'all': {}}
        active_directives: List[Dict[str, Any]] = []
        for directive in directives:
            section = directive['section']
            sections.setdefault(section, {})[directive['key']] = directive['value']
            if directive['applicability'] == 'ACTIVE':
                active_config.setdefault(section, {})[directive['key']] = directive['value']
                active_directives.append(directive)

        return {
            'root_file': str(root),
            'boot_root': str(boot_root),
            'sections': sections,
            'active_config': active_config,
            'directives': directives,
            'active_directives': active_directives,
            'includes': includes,
            'parsed_files': list(dict.fromkeys(parsed_files)),
            'errors': errors,
        }

    @classmethod
    def parse(cls, filepath: str, boot_dir: str = '') -> Dict[str, Dict[str, str]]:
        return cls.parse_detailed(filepath, boot_dir).get('sections', {'all': {}})
