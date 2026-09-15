"""Extracted GGFW component: packaging.ggcap."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, asdict, datetime, json, os, shutil, timezone, zipfile,
)
from ggfw.constants import EVIDENCE_SCHEMA, TOOL_VERSION, TOOL_VERSION_DISPLAY
from ggfw.files import sha256_file
from ggfw.errors import GGFWRuntimeError
from ggfw.models.report import GGFWReport
from ggfw.models.spi import SPIReadResult

class EvidencePackageBuilder:
    """Create a timestamped evidence directory and ZIP-based .ggcap package."""

    def __init__(self, evidence_root: str, scan_id: str):
        self.root = Path(evidence_root).expanduser().resolve()
        self.scan_id = scan_id
        self.scan_dir = self.root / scan_id
        if not scan_id or scan_id in {'.', '..'} or any(c in scan_id for c in '/\\:'):
            raise GGFWRuntimeError('scan_id must be a single directory name')
        try:
            # Exclusive creation is the boundary for direct and concurrent callers.
            self.scan_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError as exc:
            raise GGFWRuntimeError(f'Cannot allocate fresh evidence directory: {self.scan_dir}') from exc
        try:
            os.chmod(self.scan_dir, 0o700)
        except OSError:
            pass

    def path(self, relative: str) -> Path:
        destination = self.scan_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        return destination

    def write_text(self, relative: str, content: str) -> Path:
        destination = self.path(relative)
        destination.write_text(content, encoding='utf-8')
        return destination

    def write_bytes(self, relative: str, content: bytes) -> Path:
        destination = self.path(relative)
        destination.write_bytes(content)
        return destination

    def write_json(self, relative: str, payload: Any) -> Path:
        return self.write_text(relative, json.dumps(payload, indent=4, ensure_ascii=False) + '\n')

    def copy_file(self, source: Optional[str], relative: str) -> Optional[Path]:
        if not source:
            return None
        src = Path(source).expanduser().resolve()
        if not src.is_file():
            return None
        destination = self.path(relative)
        try:
            if src == destination.resolve():
                return destination
        except OSError:
            pass
        shutil.copy2(src, destination)
        return destination

    def collect(
        self,
        report: GGFWReport,
        boot_path: str,
        config_detail: Dict[str, Any],
        baseline_path: Optional[str],
        spi_result: Optional[SPIReadResult],
    ) -> None:
        boot_root = Path(boot_path).expanduser().resolve()

        # Boot configuration and resolved chain.
        for parsed in config_detail.get('parsed_files', []):
            source = Path(parsed)
            try:
                relative = source.resolve().relative_to(boot_root)
            except (OSError, ValueError):
                continue
            self.copy_file(str(source), f'evidence/boot/{relative}')
        self.copy_file(str(boot_root / 'cmdline.txt'), 'evidence/boot/cmdline.txt')
        self.write_json('evidence/boot/config-parse.json', config_detail)
        if 'boot_resolution_graph' in report.raw_artifacts:
            graph = report.raw_artifacts['boot_resolution_graph']
            self.write_json('evidence/boot/resolved-chain.json', graph)
            self.write_text('evidence/boot/resolved-chain.txt', graph.get('text', '') + '\n')
        if 'boot_integrity' in report.raw_artifacts:
            self.write_json('evidence/boot/file-hashes.json', report.raw_artifacts['boot_integrity'])
        if baseline_path:
            self.copy_file(baseline_path, 'evidence/boot/baseline.json')
        public_key_path = report.execution.get('secure_boot_public_key')
        if public_key_path:
            self.copy_file(public_key_path, 'evidence/boot/customer-public-key.pem')

        # Platform and firmware-reported evidence.
        self.write_json('evidence/platform/otp-raw.json', report.raw_artifacts.get('otp_raw', {}))
        self.write_json('evidence/platform/otp-decoded.json', report.raw_artifacts.get('otp_decoded', {}))
        self.write_json('evidence/platform/otp-decoder-metadata.json', report.raw_artifacts.get('otp_decoder_metadata', {}))
        self.write_json('evidence/platform/rpiboot-metadata.json', report.raw_artifacts.get('otp_metadata', {}))
        self.write_text(
            'evidence/platform/bootloader-version.txt',
            str(report.raw_artifacts.get('bootloader_version', '')) + '\n',
        )
        self.write_text(
            'evidence/platform/eeprom-config-live.txt',
            str(report.raw_artifacts.get('eeprom_config', '')) + '\n',
        )
        self.write_json(
            'evidence/platform/tool-metadata.json',
            report.raw_artifacts.get('tool_metadata', {}),
        )
        self.write_json(
            'evidence/boot/secure-boot-evidence.json',
            report.raw_artifacts.get('secure_boot_evidence', report.raw_artifacts.get('secure_boot_assessment', {})),
        )
        secure_validation = report.raw_artifacts.get('secure_boot_validation', {})
        self.write_json('evidence/boot/secure-boot-validation.json', secure_validation)
        self.write_json('evidence/spi/eeprom-files.json', secure_validation.get('eeprom', {}))
        pubkey_hex = secure_validation.get('eeprom', {}).get('pubkey_bin_hex')
        if isinstance(pubkey_hex, str):
            try:
                self.write_bytes('evidence/spi/pubkey.bin', bytes.fromhex(pubkey_hex))
            except ValueError:
                pass
        self.write_json(
            'evidence/platform/eeprom-update-policy.json',
            report.raw_artifacts.get('eeprom_update_policy', {}),
        )
        self.write_json(
            'evidence/platform/eeprom-ab-assessment.json',
            report.raw_artifacts.get('eeprom_ab_assessment', {}),
        )

        # SPI evidence. The acquisition remains OS-mediated.
        if spi_result:
            self.copy_file(spi_result.output_path, 'evidence/spi/eeprom.bin')
            self.copy_file(spi_result.bootconf_path, 'evidence/spi/bootconf.txt')
            self.write_text('evidence/spi/probe.txt', spi_result.probe_output + '\n')
            self.write_text('evidence/spi/read.txt', spi_result.read_output + '\n')
            self.write_text('evidence/spi/wp-status.txt', spi_result.wp_output + '\n')
            self.write_json('evidence/spi/config-comparison.json', spi_result.config_comparison)
            self.write_json('evidence/spi/acquisition.json', asdict(spi_result))

        # Human-readable semantics for reviewers and CI integrators.
        evidence_model = report.raw_artifacts.get('evidence_model', {})
        readme_lines = [
            f"GGFW {TOOL_VERSION_DISPLAY} evidence package",
            "",
            "Exit codes:",
            "  0 = scan completed and the selected policy gate was not triggered",
            "  1 = tool, runtime, argument, acquisition, baseline, or packaging failure",
            "  2 = scan completed successfully but --fail-on policy was triggered",
            "",
            "OTP / Secure Boot decoder semantics:",
            "  BCM2711 public runtime rows are decoded from vcgencmd otp_dump.",
            "  BCM2712 customer-key hash and JTAG lock are not inferred from undocumented runtime rows.",
            "  Supply rpiboot -j metadata with --otp-metadata to add independent provisioning evidence.",
            f"  GGFW {TOOL_VERSION_DISPLAY} verifies boot.img/boot.sig, EEPROM bootconf signatures, key-to-OTP binding,",
            "  and BCM2712 customer bootsys counter-signatures when the required evidence is available.",
            "  Raspberry Pi vendor-root signatures remain BootROM-enforced and are not independently replay-verified.",
            "",
            "Cryptographic engine self-test:",
            "  Run --crypto-self-test to execute embedded known-answer tests without accessing platform state.",
            "  The KAT covers valid/tampered boot.img, wrong key, malformed boot.sig, bootconf, and BCM2712 bootsys.",
            "",
            "Cryptographic validation states:",
            "  VALID      = the required artifact and key were available and verification succeeded",
            "  INVALID    = verification was actually performed or the signed format was parsed and a mismatch was proven",
            "  UNVERIFIED = a required key, binding, signature, or artifact was unavailable; this is not proof of invalidity",
            "  Empty, 0x00-filled, 0xff-erased, padding-only, and digest-only .sig sections are",
            "  classified as SIGNATURE_NOT_PRESENT. FORMAT_INVALID requires non-placeholder content",
            "  that represents an attempted signature file but cannot be parsed correctly.",
            "",
            "Secure Boot policy semantics:",
            "  secure-boot-required separates confirmed policy-control failures from evidence limitations.",
            "  Severity-based --fail-on gates use leaf SECURITY_FINDING/POLICY_FAILURE findings by default.",
            "  COVERAGE_GAP findings remain visible but require --fail-on-coverage or --fail-on COVERAGE_GAP to gate.",
            "",
            "Gate semantics:",
            "  Aggregate findings never trigger process exit; only leaf findings are evaluated.",
            "  --fail-on-coverage opts coverage gaps into severity-based gates.",
            "  --gate-exclude remains available for explicit additional filtering.",
            "  Exclusions affect only process gating; they do not suppress findings, counts, evidence, or remediation groups.",
            "",
            "Finding relations:",
            "  aggregate=true marks an outcome-level finding rather than an independent root task.",
            "  blocked_by lists findings that must be resolved before the aggregate can close.",
            "  remediation_group de-duplicates related findings into independent remediation tasks.",
            "",
            "Evidence trust:",
            "  HIGH   = independently acquired offline/external evidence or a verified trusted artifact",
            "  MEDIUM = evidence mediated by the examined operating system, firmware interface, or local baseline",
            "  LOW    = indirect, heuristic, or incomplete evidence",
            "",
            "For an in-band scan, MEDIUM is normally the maximum attainable trust level. HIGH generally",
            "requires an external SPI programmer, offline media acquisition, or a separately verified signed artifact.",
            "",
            "Acquisition context:",
            f"  {json.dumps(report.summary.get('evidence_context', {}), ensure_ascii=False)}",
            "",
            "Policy gate:",
            f"  {json.dumps(report.execution, ensure_ascii=False)}",
        ]
        self.write_text('README.txt', '\n'.join(readme_lines) + '\n')
        self.write_json('evidence/evidence-model.json', evidence_model)

        # OS/runtime posture evidence already normalised by the scanner.
        for key, filename in (
            ('local_accounts', 'accounts.json'),
            ('network_listeners', 'listeners.json'),
            ('apt_sources', 'apt-sources.json'),
            ('loaded_modules', 'loaded-modules.json'),
        ):
            if key in report.raw_artifacts:
                self.write_json(f'evidence/os/{filename}', report.raw_artifacts[key])

    def _manifest_entries(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for path in sorted(self.scan_dir.rglob('*')):
            if not path.is_file() or path.name == 'manifest.json':
                continue
            entries.append({
                'path': str(path.relative_to(self.scan_dir)),
                'size': path.stat().st_size,
                'sha256': sha256_file(str(path)),
            })
        return entries

    def finalise(self, report: GGFWReport, package_path: str) -> Dict[str, Any]:
        package = Path(package_path).expanduser().resolve()
        package.parent.mkdir(parents=True, exist_ok=True)
        report.raw_artifacts['evidence_package'] = {
            'schema': EVIDENCE_SCHEMA,
            'scan_directory': str(self.scan_dir),
            'package_path': str(package),
            'format': 'ZIP',
            'spi_source_type': 'OS_MEDIATED_SPI_READ',
        }
        self.write_text('report.json', report.to_json() + '\n')
        manifest = {
            'schema': EVIDENCE_SCHEMA,
            'tool_version': TOOL_VERSION,
            'scan_id': self.scan_id,
            'created_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            'platform': report.platform_guess,
            'policy_profile': report.policy_profile,
            'files': self._manifest_entries(),
        }
        self.write_json('manifest.json', manifest)

        temporary = package.with_name(package.name + '.tmp')
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in sorted(self.scan_dir.rglob('*')):
                if path.is_file():
                    archive.write(path, arcname=str(path.relative_to(self.scan_dir)))
        os.replace(temporary, package)
        try:
            os.chmod(package, 0o600)
        except OSError:
            pass
        package_hash = sha256_file(str(package))
        Path(str(package) + '.sha256').write_text(f'{package_hash}  {package.name}\n', encoding='utf-8')
        return {
            'scan_directory': str(self.scan_dir),
            'package_path': str(package),
            'package_sha256': package_hash,
            'manifest_entries': len(manifest['files']),
        }
