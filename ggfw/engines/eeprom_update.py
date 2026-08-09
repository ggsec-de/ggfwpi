"""Extracted GGFW component: engines.eeprom_update."""
from ggfw._compat import (
    Any, Dict, Optional, Path, datetime, json, re, shutil, subprocess,
)
from ggfw.hardware.interrogator import HardwareInterrogator
from ggfw.hardware.platform import get_soc_generation
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport
from ggfw.models.spi import SPIReadResult
from ggfw.parsers.config_txt import decode_boot_order, parse_simple_config

class EEPROMUpdatePolicyEngine:
    def __init__(
        self,
        platform: str,
        eeprom_conf: str,
        report: GGFWReport,
        interrogator: HardwareInterrogator,
    ):
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.eeprom_conf = eeprom_conf
        self.config = parse_simple_config(eeprom_conf)
        self.report = report
        self.interrogator = interrogator
        self.defaults = self._read_update_defaults()
        self.service_state = self._read_service_state()

    @staticmethod
    def _read_update_defaults() -> Dict[str, str]:
        path = Path('/etc/default/rpi-eeprom-update')
        values: Dict[str, str] = {}
        try:
            for raw_line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip().strip('"\'')
        except OSError:
            pass
        return values

    @staticmethod
    def _systemctl_state(action: str, unit: str) -> str:
        systemctl = shutil.which('systemctl')
        if not systemctl:
            return 'UNAVAILABLE'
        try:
            result = subprocess.run(
                [systemctl, action, unit],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            output = (result.stdout or result.stderr).strip()
            return output or f'RETURNCODE_{result.returncode}'
        except (OSError, subprocess.TimeoutExpired):
            return 'UNKNOWN'

    def _read_service_state(self) -> Dict[str, str]:
        return {
            'enabled': self._systemctl_state('is-enabled', 'rpi-eeprom-update.service'),
            'active': self._systemctl_state('is-active', 'rpi-eeprom-update.service'),
        }

    def run_pre_spi(self):
        freeze_raw = self.config.get('FREEZE_VERSION')
        self_update_raw = self.config.get('ENABLE_SELF_UPDATE')
        freeze_state = (
            'ENABLED' if freeze_raw == '1'
            else 'DISABLED' if freeze_raw == '0'
            else 'UNSET_OR_DEFAULT'
        )
        self_update_state = (
            'ENABLED' if self_update_raw == '1'
            else 'DISABLED' if self_update_raw == '0'
            else 'UNSET_OR_DEFAULT'
        )

        boot_order_raw = self.config.get('BOOT_ORDER')
        boot_order_decoded = decode_boot_order(boot_order_raw)
        policy = {
            'freeze_version': freeze_state,
            'enable_self_update': self_update_state,
            'boot_order': boot_order_raw,
            'boot_order_decoded': boot_order_decoded,
            'boot_uart': self.config.get('BOOT_UART'),
            'net_install_at_power_on': self.config.get('NET_INSTALL_AT_POWER_ON'),
            'net_install_enabled': self.config.get('NET_INSTALL_ENABLED'),
            'update_defaults': self.defaults,
            'update_service': self.service_state,
        }
        self.report.raw_artifacts['eeprom_update_policy'] = policy

        if freeze_state != 'ENABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-UPDATE-001', severity='INFO', category='HARDWARE',
                description='EEPROM bootloader version is not explicitly frozen.',
                evidence=f'FREEZE_VERSION={freeze_raw!r}; state={freeze_state}',
                remediation=(
                    'Set FREEZE_VERSION=1 only when policy requires pinned firmware. '
                    'Otherwise retain a controlled and authenticated update process.'
                ),
            ))

        if self_update_state == 'ENABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-UPDATE-002', severity='INFO', category='HARDWARE',
                description='EEPROM self-update is explicitly enabled.',
                evidence='ENABLE_SELF_UPDATE=1',
                remediation='Confirm that self-update is required and that update artifacts are authenticated.',
            ))


        if self.config.get('BOOT_UART') == '1':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-DEBUG-001', severity='INFO', category='HARDWARE',
                description='EEPROM bootloader UART debug output is enabled.',
                evidence='BOOT_UART=1; GPIO14/GPIO15; default baud 115200 unless UART_BAUD overrides it',
                remediation='Disable BOOT_UART on production systems unless early boot diagnostics are required.',
                domain='BOOT_AND_EEPROM',
                status='OBSERVED',
                finding_class='CONFIGURATION_OBSERVATION',
                expected='Bootloader UART disabled unless explicitly required by policy',
                observed='BOOT_UART=1',
            ))

        if self.config.get('NET_INSTALL_AT_POWER_ON') == '1':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-NETINSTALL-001', severity='INFO', category='HARDWARE',
                description='Network Install UI is enabled briefly after cold power-on.',
                evidence='NET_INSTALL_AT_POWER_ON=1',
                remediation='Disable the power-on Network Install UI for locked appliances when it is not required.',
                domain='BOOT_AND_EEPROM',
                status='OBSERVED',
                finding_class='CONFIGURATION_OBSERVATION',
                expected='Network Install exposure matches the deployment policy',
                observed='NET_INSTALL_AT_POWER_ON=1',
            ))

        if boot_order_raw:
            self.report.add_check(
                'RPI-BOOT-ORDER-000', 'BOOT_AND_EEPROM',
                'EEPROM BOOT_ORDER was decoded.',
                raw=boot_order_raw, decoded=boot_order_decoded,
            )
            if boot_order_decoded.get('contains_network') or boot_order_decoded.get('contains_rpiboot'):
                self.report.add_finding(Finding(
                    rule_id='RPI-BOOT-ORDER-001', severity='INFO', category='HARDWARE',
                    description='EEPROM boot order includes a network or provisioning boot path.',
                    evidence=json.dumps(boot_order_decoded, ensure_ascii=False),
                    remediation='Confirm that every alternative boot path is required and compatible with Secure Boot policy.',
                    domain='BOOT_AND_EEPROM',
                    finding_class='CONFIGURATION_OBSERVATION',
                    expected='Only approved boot sources are present in BOOT_ORDER',
                    observed=', '.join(item['mode'] for item in boot_order_decoded.get('sequence', [])),
                ))

    def _assess_ab_with_tool(self) -> Dict[str, Any]:
        path = self.interrogator.rpi_eeprom_ab_path
        if not path:
            return {'status': 'TOOL_UNAVAILABLE', 'assessment_method': 'TOOL_LOOKUP', 'authoritative_runtime_state': False}
        try:
            result = subprocess.run(
                [path, 'committed'],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            output = '\n'.join(
                part.strip() for part in (result.stdout, result.stderr) if part and part.strip()
            )
            if result.returncode == 0 and re.fullmatch(r'\d+', result.stdout.strip()):
                return {
                    'status': 'ENABLED',
                    'assessment_method': 'RPI_EEPROM_AB_COMMITTED',
                    'authoritative_runtime_state': True,
                    'committed_partition': int(result.stdout.strip()),
                    'output': output,
                }
            if 'ab partitioning is not being used' in output.lower():
                return {
                    'status': 'DISABLED',
                    'assessment_method': 'RPI_EEPROM_AB_COMMITTED',
                    'authoritative_runtime_state': True,
                    'output': output,
                }
            return {
                'status': 'UNKNOWN',
                'assessment_method': 'RPI_EEPROM_AB_COMMITTED',
                'authoritative_runtime_state': False,
                'returncode': result.returncode,
                'output': output,
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {'status': 'UNKNOWN', 'assessment_method': 'RPI_EEPROM_AB_COMMITTED', 'authoritative_runtime_state': False, 'output': str(exc)}

    def _bootloader_release_date(self) -> Optional[datetime]:
        output = str(self.report.raw_artifacts.get('bootloader_version', ''))
        match = re.search(r'(20\d{2})[/-](\d{2})[/-](\d{2})', output)
        if not match:
            return None
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return None

    def run_post_spi(self, spi_result: SPIReadResult):
        if self.soc != 'BCM2712':
            self.report.raw_artifacts['eeprom_ab_assessment'] = {
                'status': 'NOT_APPLICABLE',
                'applicability': 'NOT_APPLICABLE',
                'reason': 'A/B bootloader EEPROM updates are BCM2712-specific.',
            }
            return

        assessment = self._assess_ab_with_tool()
        if assessment['status'] in {'TOOL_UNAVAILABLE', 'UNKNOWN'}:
            if spi_result.ab_layout_magic_detected is True:
                assessment = {
                    'status': 'HEURISTIC_ENABLED',
                    'assessment_method': 'SPI_TRAILER_MARKER_HEURISTIC',
                    'authoritative_runtime_state': False,
                    'confidence': 'MEDIUM',
                    'offsets': spi_result.ab_layout_offsets,
                }
            elif spi_result.ab_layout_magic_detected is False:
                release_date = self._bootloader_release_date()
                ab_support_date = datetime(2026, 5, 13)
                if release_date and release_date < ab_support_date:
                    assessment = {
                        'status': 'UNSUPPORTED_BY_FIRMWARE',
                        'assessment_method': 'RELEASE_CAPABILITY_MAP',
                        'authoritative_runtime_state': False,
                        'confidence': 'HIGH',
                        'installed_release_date': release_date.date().isoformat(),
                        'ab_support_release_date': ab_support_date.date().isoformat(),
                    }
                else:
                    assessment = {
                        'status': 'UNKNOWN',
                        'assessment_method': 'SPI_TRAILER_ABSENCE',
                        'authoritative_runtime_state': False,
                        'confidence': 'LOW',
                        'reason': 'No A/B trailer markers found; absence is not authoritative.',
                    }

        self.report.raw_artifacts['eeprom_ab_assessment'] = assessment

        if assessment['status'] == 'DISABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-001', severity='INFO', category='HARDWARE',
                description='A/B EEPROM bootloader updates are not enabled.',
                evidence=assessment.get('output', 'rpi-eeprom-ab reported disabled'),
                domain='BOOT_AND_EEPROM', status='DISABLED', finding_class='CAPABILITY_GAP',
                expected='A/B availability matches the resilience policy', observed='DISABLED',
                remediation='Consider A/B EEPROM updates on supported BCM2712 systems where update resilience is required.',
            ))
        elif assessment['status'] == 'UNSUPPORTED_BY_FIRMWARE':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-003', severity='INFO', category='HARDWARE',
                description='Installed bootloader firmware predates BCM2712 A/B EEPROM update support.',
                evidence=json.dumps(assessment, ensure_ascii=False),
                domain='BOOT_AND_EEPROM', status='UNSUPPORTED', finding_class='CAPABILITY_GAP',
                expected='A/B capability only when required by resilience policy', observed='UNSUPPORTED_BY_FIRMWARE',
                remediation='Update the bootloader through an approved process before considering A/B EEPROM enablement.',
            ))
        elif assessment['status'] == 'HEURISTIC_ENABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-002', severity='INFO', category='HARDWARE',
                description='A/B EEPROM layout markers were detected heuristically.',
                evidence=f"marker_offsets={assessment.get('offsets')}",
                domain='BOOT_AND_EEPROM', status='HEURISTIC_ENABLED', finding_class='CAPABILITY_GAP',
                expected='Runtime A/B state reported by rpi-eeprom-ab', observed='HEURISTIC_ENABLED',
                remediation='Install rpi-eeprom-ab and query the committed partition for authoritative confirmation.',
            ))
        elif assessment['status'] == 'UNKNOWN':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-000', severity='INFO', category='HARDWARE',
                description='A/B EEPROM update state could not be conclusively determined.',
                evidence=json.dumps(assessment, ensure_ascii=False),
                domain='BOOT_AND_EEPROM', status='UNVERIFIED', finding_class='COVERAGE_GAP',
                coverage_gap=True, expected='A/B runtime state established', observed='UNKNOWN',
                remediation='Install a compatible rpi-eeprom-ab tool or validate the EEPROM layout independently.',
            ))

        immediate = self.defaults.get('RPI_EEPROM_IMMEDIATE_UPDATE') == '1'
        flash_meta = self.report.raw_artifacts.get('tool_metadata', {}).get('flashrom', {})
        risky_flashrom = bool(flash_meta.get('upstream_1_4_to_1_6_write_caution'))
        ab_enabled = assessment['status'] in {'ENABLED', 'HEURISTIC_ENABLED'}
        if immediate and risky_flashrom and not ab_enabled:
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-UPDATE-003', severity='HIGH', category='HARDWARE',
                description='Immediate EEPROM updates may use a flashrom version with known upstream erase-path cautions.',
                evidence=(
                    f"RPI_EEPROM_IMMEDIATE_UPDATE=1; flashrom={flash_meta.get('version')}; "
                    f"A/B={assessment['status']}"
                ),
                remediation=(
                    'Disable immediate flashrom updates, use the staged recovery path, '
                    'or install a Raspberry Pi-patched/newer flashrom build.'
                ),
            ))
