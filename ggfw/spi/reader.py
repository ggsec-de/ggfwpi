"""Extracted GGFW component: spi.reader."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, Tuple, datetime, hashlib, json, os, re, subprocess,
)
from ggfw.hardware.platform import get_soc_generation
from ggfw.models.evidence import EvidenceRecord
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport
from ggfw.models.spi import SPIReadResult

class SPIEEPROMReader:
    """Read-only acquisition of the Raspberry Pi boot EEPROM via flashrom."""

    DEFAULT_DEVICES = {
        "BCM2711": ["/dev/spidev0.0"],
        "BCM2712": ["/dev/spidev10.0"],
    }
    EXPECTED_SIZES = {
        "BCM2711": 512 * 1024,
        "BCM2712": 2 * 1024 * 1024,
    }

    def __init__(
        self,
        platform: str,
        flashrom_path: Optional[str],
        rpi_eeprom_config_path: Optional[str],
        report: GGFWReport,
        device_override: Optional[str] = None,
        spi_speed_khz: int = 16000,
    ):
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.flashrom_path = flashrom_path
        self.rpi_eeprom_config_path = rpi_eeprom_config_path
        self.report = report
        self.device_override = device_override
        self.spi_speed_khz = spi_speed_khz

    @staticmethod
    def _combined_output(result: subprocess.CompletedProcess) -> str:
        parts = []
        if result.stdout:
            parts.append(result.stdout.strip())
        if result.stderr:
            parts.append(result.stderr.strip())
        return "\n".join(part for part in parts if part)

    @staticmethod
    def _sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _detect_ab_layout_magic(path: str) -> Tuple[Optional[bool], List[int]]:
        """Heuristically identify BCM2712 A/B metadata markers in a 2 MiB dump."""
        marker = bytes.fromhex('55 aa f5 5f')
        try:
            size = os.path.getsize(path)
            offsets = [size - 0x2000, size - 0x1000]
            matched: List[int] = []
            with open(path, 'rb') as handle:
                for offset in offsets:
                    if offset < 0:
                        continue
                    handle.seek(offset)
                    if handle.read(len(marker)) == marker:
                        matched.append(offset)
            if len(matched) == len(offsets):
                return True, matched
            if matched:
                return None, matched
            return False, []
        except OSError:
            return None, []

    @staticmethod
    def _normalise_config(config: Optional[str]) -> str:
        if not config:
            return ""
        lines = []
        for line in config.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                lines.append(stripped)
        return "\n".join(lines)

    @staticmethod
    def _config_map(config: Optional[str]) -> Dict[str, str]:
        if not config:
            return {}
        parsed: Dict[str, str] = {}
        for raw_line in config.splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#') or line.startswith('[') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            parsed[key.strip().upper()] = value.strip()
        return parsed

    @classmethod
    def _compare_configs(cls, raw_config: Optional[str], live_config: Optional[str]) -> Dict[str, Any]:
        raw_map = cls._config_map(raw_config)
        live_map = cls._config_map(live_config)
        common = sorted(set(raw_map) & set(live_map))
        matching = [key for key in common if raw_map[key] == live_map[key]]
        different = [
            {'field': key, 'raw_spi': raw_map[key], 'live': live_map[key]}
            for key in common if raw_map[key] != live_map[key]
        ]
        only_raw = {key: raw_map[key] for key in sorted(set(raw_map) - set(live_map))}
        only_live = {key: live_map[key] for key in sorted(set(live_map) - set(raw_map))}
        if not raw_map or not live_map:
            result = 'NOT_COMPARABLE'
        elif not different and not only_raw and not only_live:
            result = 'FULL_MATCH'
        elif different:
            result = 'MISMATCH'
        else:
            result = 'PARTIAL_MATCH'
        return {
            'mode': 'NORMALIZED_KEY_VALUE',
            'raw_spi_source': 'bootconf extracted from OS-mediated SPI dump',
            'live_source': 'rpi-eeprom-config live firmware report',
            'compared_fields': common,
            'matching_fields': matching,
            'different_fields': different,
            'only_in_raw': only_raw,
            'only_in_live': only_live,
            'result': result,
        }

    @staticmethod
    def _unique_path(requested_path: str) -> str:
        path = Path(requested_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            return str(path)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return str(path.with_name(f"{path.stem}-{timestamp}{path.suffix}"))

    def _select_device(self) -> Optional[str]:
        if self.device_override:
            return self.device_override

        for device in self.DEFAULT_DEVICES.get(self.soc, []):
            if os.path.exists(device):
                return device
        return None

    @staticmethod
    def _extract_chip_name(output: str) -> Optional[str]:
        patterns = [
            r'Found\s+[^\n]*?flash chip\s+"([^"]+)"',
            r'Found\s+flash chip\s+"([^"]+)"',
            r'Found\s+([^\n]+?)\s+flash chip',
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def _parse_wp_status(output: str, expected_size: Optional[int]) -> Dict[str, Any]:
        """Parse flashrom --wp-status output, including the flashrom 1.6 format."""
        lowered = output.lower()
        unsupported_markers = (
            'not supported', 'unsupported', 'untested for operations: wp',
            'write protection is not supported', 'failed to get write protection',
            'cannot get write protection'
        )

        enabled: Optional[bool] = None
        if re.search(
            r'(?:write\s+)?protection(?:\s+mode)?\s*(?::|is)?\s*enabled',
            lowered,
        ):
            enabled = True
        elif re.search(
            r'(?:write\s+)?protection(?:\s+mode)?\s*(?::|is)?\s*disabled',
            lowered,
        ):
            enabled = False
        elif re.search(r'write\s+protect(?:ion)?\s+is\s+enabled', lowered):
            enabled = True
        elif re.search(r'write\s+protect(?:ion)?\s+is\s+disabled', lowered):
            enabled = False

        start: Optional[int] = None
        length: Optional[int] = None
        range_match = re.search(
            r'(?:(?:write\s+)?protection|write\s+protect|wp)'
            r'(?:\s+range)?\s*:\s*'
            r'start\s*=\s*(0x[0-9a-f]+|[0-9]+)'
            r'(?:\s*,?\s*)'
            r'(?:len|length)\s*=\s*(0x[0-9a-f]+|[0-9]+)',
            output,
            re.IGNORECASE,
        )
        if range_match:
            start = int(range_match.group(1), 0)
            length = int(range_match.group(2), 0)

        has_wp_data = (
            enabled is not None
            or range_match is not None
            or 'wp: status' in lowered
            or 'write protection mode' in lowered
            or 'protection mode:' in lowered
            or 'protection range:' in lowered
        )
        supported = has_wp_data and not any(marker in lowered for marker in unsupported_markers)

        full_chip: Optional[bool] = None
        if start is not None and length is not None and expected_size is not None:
            full_chip = start == 0 and length >= expected_size

        if not supported:
            assessment = 'UNKNOWN'
        elif full_chip and enabled is not False:
            assessment = 'FULL'
        elif length == 0 or enabled is False:
            assessment = 'DISABLED'
        elif length is not None and length > 0:
            assessment = 'PARTIAL'
        else:
            assessment = 'UNKNOWN'

        return {
            'supported': supported,
            'enabled': enabled,
            'start': start,
            'length': length,
            'full_chip': full_chip,
            'assessment': assessment,
        }

    def _record_wp_assessment(self, result: SPIReadResult):
        evidence = result.wp_output[-3000:] or 'No flashrom --wp-status output'

        if result.wp_assessment == 'FULL':
            self.report.add_check(
                'RPI-SPI-WP-PASS', 'BOOT_AND_EEPROM',
                'SPI EEPROM full-chip status-register protection is enabled.',
                source_type='OS_MEDIATED_SPI_READ',
                start=result.wp_start, length=result.wp_length,
                expected_size=result.expected_size,
                physical_wp_state=result.physical_wp_state,
            )
            return
        if result.wp_assessment == 'DISABLED':
            self.report.add_finding(Finding(
                rule_id="RPI-SPI-WP-001", severity="HIGH", category="HARDWARE",
                description="SPI EEPROM data range is not effectively write-protected.",
                evidence=evidence,
                remediation="Use the Raspberry Pi recovery process with eeprom_write_protect=1 to configure full-chip status-register protection, then verify it with flashrom --wp-status. Do not enable write operations from GGFW.",
                domain="BOOT_AND_EEPROM", status="DISABLED", confidence="HIGH",
                expected="Required: full-chip status-register protection; recommended additional hardware enforcement: physical #WP asserted",
                observed=(
                    f"range_start={result.wp_start}; range_length={result.wp_length}; "
                    f"mode_enabled={result.wp_enabled}; physical_wp={result.physical_wp_state}"
                ),
                rationale=("The zero-length status-register protection range conclusively means that no EEPROM address range is protected. "
                           "This finding remains valid regardless of the unmeasured physical #WP signal state; #WP cannot enforce "
                           "data-range protection when the status registers define no protected range."),
                evidence_items=[EvidenceRecord(
                    source_type="OS_MEDIATED_SPI_READ",
                    source_path=result.device or "",
                    acquisition_method="flashrom --wp-status via linux_spi",
                    trust_level="MEDIUM",
                    raw=evidence,
                    normalized={
                        "assessment": result.wp_assessment,
                        "enabled": result.wp_enabled,
                        "start": result.wp_start,
                        "length": result.wp_length,
                        "expected_size": result.expected_size,
                        "raw_status_registers_available": result.raw_status_registers_available,
                        "physical_wp_state": result.physical_wp_state,
                    },
                )],
            ))
            return
        if result.wp_assessment == 'PARTIAL':
            self.report.add_finding(Finding(
                rule_id="RPI-SPI-WP-002", severity="MEDIUM", category="HARDWARE",
                description="SPI EEPROM write protection covers only part of the flash chip.",
                evidence=(
                    f"start={result.wp_start!r}; length={result.wp_length!r}; "
                    f"expected_size={result.expected_size!r}\n{evidence}"
                ),
                remediation="Use the Raspberry Pi recovery process to configure full-chip EEPROM protection and verify the final range with flashrom --wp-status.",
                domain="BOOT_AND_EEPROM", status="PARTIAL", confidence="HIGH",
                expected="The entire EEPROM address range is protected",
                observed=f"start={result.wp_start}; length={result.wp_length}; size={result.expected_size}",
            ))
            return

        self.report.add_finding(Finding(
            rule_id="RPI-SPI-WP-000", severity="INFO", category="HARDWARE",
            description="SPI EEPROM write-protection state could not be conclusively determined.",
            evidence=evidence,
            remediation="Use a flashrom build and programmer combination that supports --wp-status for this chip."
        ))

    def _add_limitation(self, rule_id: str, description: str, evidence: str, remediation: str):
        self.report.add_finding(Finding(
            rule_id=rule_id,
            severity="INFO",
            category="HARDWARE",
            description=description,
            evidence=evidence,
            remediation=remediation,
        ))

    def acquire(self, output_path: str, live_config: Optional[str]) -> SPIReadResult:
        result = SPIReadResult(
            attempted=True,
            flashrom_path=self.flashrom_path,
            expected_size=self.EXPECTED_SIZES.get(self.soc),
        )

        if os.geteuid() != 0:
            result.error = "SPI acquisition requires root privileges"
            self._add_limitation(
                "RPI-SPI-000",
                "SPI EEPROM acquisition skipped because GGFW is not running as root.",
                "Effective UID is not 0",
                "Run GGFW with sudo for read-only SPI acquisition.",
            )
            return result

        if not self.flashrom_path:
            result.error = "flashrom not found"
            self._add_limitation(
                "RPI-SPI-001",
                "SPI EEPROM acquisition skipped because flashrom is unavailable.",
                "flashrom executable not found",
                "Install the flashrom package.",
            )
            return result

        device = self._select_device()
        result.device = device
        if not device:
            expected = ", ".join(self.DEFAULT_DEVICES.get(self.soc, [])) or "unknown"
            result.error = "Expected SPI device not present"
            self._add_limitation(
                "RPI-SPI-002",
                "Expected Raspberry Pi boot EEPROM SPI device is not available.",
                f"SoC={self.soc}; expected device={expected}",
                "Verify the SPI device node and platform-specific boot configuration.",
            )
            return result

        programmer = f"linux_spi:dev={device},spispeed={self.spi_speed_khz}"
        result.programmer = programmer

        probe_cmd = [self.flashrom_path, "-p", programmer]
        try:
            probe = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            result.probe_returncode = probe.returncode
            result.probe_output = self._combined_output(probe)
            result.probe_ok = probe.returncode == 0
            result.detected_chip = self._extract_chip_name(result.probe_output)
        except subprocess.TimeoutExpired:
            result.error = "flashrom probe timed out"
            result.probe_output = "Probe exceeded 45 seconds"
            self._add_limitation(
                "RPI-SPI-003",
                "SPI EEPROM probe timed out.",
                result.probe_output,
                "Check SPI device availability and flashrom compatibility.",
            )
            return result

        if not result.probe_ok:
            result.error = "flashrom probe failed"
            self._add_limitation(
                "RPI-SPI-003",
                "flashrom could not identify the boot EEPROM.",
                result.probe_output[-2000:] or "No flashrom output",
                "Verify the selected spidev node and use a flashrom build compatible with the EEPROM.",
            )
            return result

        result.wp_attempted = True
        wp_cmd = [self.flashrom_path, "-p", programmer, "--wp-status"]
        try:
            wp_result = subprocess.run(
                wp_cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            result.wp_returncode = wp_result.returncode
            result.wp_output = self._combined_output(wp_result)
            parsed_wp = self._parse_wp_status(result.wp_output, result.expected_size)
            result.wp_supported = parsed_wp['supported']
            result.wp_enabled = parsed_wp['enabled']
            result.wp_start = parsed_wp['start']
            result.wp_length = parsed_wp['length']
            result.wp_full_chip = parsed_wp['full_chip']
            result.wp_assessment = parsed_wp['assessment']
        except subprocess.TimeoutExpired:
            result.wp_output = "flashrom --wp-status exceeded 45 seconds"
            result.wp_supported = None
            result.wp_assessment = 'UNKNOWN'

        self._record_wp_assessment(result)

        final_output = self._unique_path(output_path)
        result.output_path = final_output
        read_cmd = [self.flashrom_path, "-p", programmer, "-r", final_output]

        try:
            read = subprocess.run(
                read_cmd,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            result.read_returncode = read.returncode
            result.read_output = self._combined_output(read)
            result.read_ok = read.returncode == 0 and os.path.isfile(final_output)
        except subprocess.TimeoutExpired:
            result.error = "flashrom read timed out"
            result.read_output = "Read exceeded 180 seconds"
            self._add_limitation(
                "RPI-SPI-004",
                "SPI EEPROM read timed out.",
                result.read_output,
                "Check SPI stability or reduce the SPI clock.",
            )
            return result

        if not result.read_ok:
            result.error = "flashrom read failed"
            self._add_limitation(
                "RPI-SPI-004",
                "SPI EEPROM read failed.",
                result.read_output[-2000:] or "No flashrom output",
                "Check flashrom compatibility, permissions and SPI signal stability.",
            )
            return result

        result.size = os.path.getsize(final_output)
        result.sha256 = self._sha256_file(final_output)
        if self.soc == "BCM2712":
            (
                result.ab_layout_magic_detected,
                result.ab_layout_offsets,
            ) = self._detect_ab_layout_magic(final_output)
        if result.expected_size is not None:
            result.size_matches_expected = result.size == result.expected_size
            if not result.size_matches_expected:
                self.report.add_finding(Finding(
                    rule_id="RPI-SPI-005",
                    severity="MEDIUM",
                    category="HARDWARE",
                    description="SPI EEPROM dump size differs from the expected platform size.",
                    evidence=(
                        f"SoC={self.soc}; observed={result.size} bytes; "
                        f"expected={result.expected_size} bytes"
                    ),
                    remediation="Confirm the detected flash chip and SPI mapping before analysing the dump.",
                ))

        if self.rpi_eeprom_config_path:
            bootconf_path = str(Path(final_output).with_suffix(".bootconf.txt"))
            config_cmd = [
                self.rpi_eeprom_config_path,
                final_output,
                "--out",
                bootconf_path,
            ]
            try:
                config_result = subprocess.run(
                    config_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if config_result.returncode == 0 and os.path.isfile(bootconf_path):
                    result.bootconf_path = bootconf_path
                    result.bootconf = Path(bootconf_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                    if live_config and not live_config.startswith("ERROR"):
                        result.config_comparison = self._compare_configs(result.bootconf, live_config)
                        result.config_matches_live = result.config_comparison['result'] == 'FULL_MATCH'
                        if result.config_comparison['result'] == 'MISMATCH':
                            self.report.add_finding(Finding(
                                rule_id="RPI-SPI-006",
                                severity="MEDIUM",
                                category="INTEGRITY",
                                description=(
                                    "Configuration parsed from the raw SPI dump differs "
                                    "from the live EEPROM configuration."
                                ),
                                evidence=json.dumps(result.config_comparison, ensure_ascii=False),
                                remediation=(
                                    "Review the field-level differences and confirm which EEPROM "
                                    "bank and boot path are active."
                                ),
                                expected="Raw SPI boot configuration and live firmware-reported configuration match",
                                observed=result.config_comparison['result'],
                                rationale="A mismatch can indicate a bank-selection difference, stale view or tampering.",
                            ))
                else:
                    result.read_output += (
                        "\nEEPROM config extraction failed: "
                        + self._combined_output(config_result)
                    )
            except subprocess.TimeoutExpired:
                result.read_output += "\nEEPROM config extraction timed out"

        return result
