"""Extracted GGFW component: parsers.eeprom_image."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, hashlib, struct,
)

RPI_EEPROM_MAGIC = 0x55AAF00F

RPI_EEPROM_FILE_MAGIC = 0x55AAF11F

RPI_EEPROM_MAGIC_MASK = 0xFFFFF00F

RPI_EEPROM_FILE_HEADER_LEN = 20

RPI_EEPROM_FILENAME_LEN = 12

class RaspberryPiEEPROMImage:
    """Read-only parser for the section format used by rpi-eeprom-config."""

    def __init__(self, path: str):
        self.path = str(Path(path).expanduser().resolve())
        self.data = Path(self.path).read_bytes()
        self.sections: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self._parse()

    def _parse(self) -> None:
        offset = 0
        max_sections = 4096
        while offset + 8 <= len(self.data) and len(self.sections) < max_sections:
            magic, length = struct.unpack_from('>II', self.data, offset)
            if magic in {0, 0xFFFFFFFF}:
                break
            if (magic & RPI_EEPROM_MAGIC_MASK) != RPI_EEPROM_MAGIC:
                self.errors.append(f'Invalid section magic 0x{magic:08x} at 0x{offset:x}')
                break
            section_end = offset + 8 + length
            if length < 0 or section_end > len(self.data):
                self.errors.append(f'Section at 0x{offset:x} exceeds EEPROM image')
                break
            filename = ''
            content_offset = offset + 8
            content_length = length
            if magic == RPI_EEPROM_FILE_MAGIC:
                if length < 16 or offset + 24 > len(self.data):
                    self.errors.append(f'Truncated file section at 0x{offset:x}')
                    break
                filename = self.data[offset + 8:offset + 20].decode('ascii', errors='replace').rstrip('\x00')
                content_offset = offset + 24
                content_length = length - 16
            self.sections.append({
                'magic': f'0x{magic:08x}',
                'offset': offset,
                'section_length': length,
                'filename': filename,
                'content_offset': content_offset,
                'content_length': content_length,
                'sha256': hashlib.sha256(
                    self.data[content_offset:content_offset + content_length]
                ).hexdigest(),
            })
            offset = (section_end + 7) & ~7
        if len(self.sections) >= max_sections:
            self.errors.append('Section-count safety limit reached')

    def get_all(self, filename: str) -> List[bytes]:
        return [
            self.data[item['content_offset']:item['content_offset'] + item['content_length']]
            for item in self.sections if item.get('filename') == filename
        ]

    def get_first(self, filename: str) -> Optional[bytes]:
        values = self.get_all(filename)
        return values[0] if values else None

    def summary(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'size': len(self.data),
            'sha256': hashlib.sha256(self.data).hexdigest(),
            'sections': self.sections,
            'errors': self.errors,
        }
