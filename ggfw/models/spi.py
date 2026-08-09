"""Extracted GGFW component: models.spi."""
from ggfw._compat import (
    Any, Dict, List, Optional, dataclass, field,
)

@dataclass
class SPIReadResult:
    attempted: bool = False
    source_type: str = "OS_MEDIATED_SPI_READ"
    trust_level: str = "MEDIUM"
    flashrom_path: Optional[str] = None
    device: Optional[str] = None
    programmer: Optional[str] = None
    expected_size: Optional[int] = None
    probe_ok: bool = False
    probe_returncode: Optional[int] = None
    probe_output: str = ""
    detected_chip: Optional[str] = None
    output_path: Optional[str] = None
    read_ok: bool = False
    read_returncode: Optional[int] = None
    read_output: str = ""
    size: Optional[int] = None
    size_matches_expected: Optional[bool] = None
    sha256: Optional[str] = None
    bootconf_path: Optional[str] = None
    bootconf: Optional[str] = None
    config_matches_live: Optional[bool] = None
    config_comparison: Dict[str, Any] = field(default_factory=dict)
    wp_attempted: bool = False
    wp_returncode: Optional[int] = None
    wp_output: str = ""
    wp_supported: Optional[bool] = None
    wp_enabled: Optional[bool] = None
    wp_start: Optional[int] = None
    wp_length: Optional[int] = None
    wp_full_chip: Optional[bool] = None
    wp_assessment: str = "NOT_TESTED"
    raw_status_registers_available: bool = False
    raw_status_registers: Dict[str, Any] = field(default_factory=dict)
    physical_wp_state: str = "NOT_MEASURED"
    ab_layout_magic_detected: Optional[bool] = None
    ab_layout_offsets: List[int] = field(default_factory=list)
    error: Optional[str] = None
