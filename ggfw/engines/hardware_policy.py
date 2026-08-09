"""Extracted GGFW component: engines.hardware_policy."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, Tuple, json,
)
from ggfw.constants import OTP_DECODER_SCHEMA, TOOL_VERSION_DISPLAY, VALIDATION_INVALID, VALIDATION_VALID
from ggfw.crypto.validation import build_secure_boot_evidence
from ggfw.hardware.otp import OFFICIAL_OTP_REFERENCES, decode_otp_state, load_rpiboot_metadata
from ggfw.hardware.platform import get_soc_generation
from ggfw.models.evidence import EvidenceRecord
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport

class HardwarePolicyEngine:
    def __init__(
        self,
        platform: str,
        otp: Dict[str, str],
        eeprom_conf: str,
        report: GGFWReport,
        otp_tool_available: bool = True,
        otp_metadata_bundle: Optional[Dict[str, Any]] = None,
    ):
        self.platform = platform
        self.otp = otp
        self.eeprom_conf = eeprom_conf
        self.report = report
        self.otp_tool_available = otp_tool_available
        self.otp_metadata_bundle = otp_metadata_bundle or load_rpiboot_metadata(None)
        self.decoded: Dict[str, Any] = {}
        self.secure_boot: Dict[str, Any] = {}

    def run_all_checks(self, defer_secure_boot: bool = False) -> Dict[str, Any]:
        self.check_otp_read()
        self.decode_otp()
        self.check_otp_security_fields()
        if not defer_secure_boot:
            self.check_secure_boot()
        self.check_eeprom_tool_availability()
        return self.secure_boot

    def _profile_severity(self, default: str = "INFO", hardened: str = "MEDIUM", required: str = "HIGH") -> Tuple[str, bool]:
        profile = self.report.policy_profile
        if profile == "secure-boot-required":
            return required, True
        if profile == "hardened":
            return hardened, True
        return default, default in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _otp_evidence_items(self) -> List[EvidenceRecord]:
        items = [EvidenceRecord(
            source_type="FIRMWARE_REPORTED", source_path="vcgencmd otp_dump",
            acquisition_method="firmware mailbox query", trust_level="MEDIUM",
            raw=f"OTP words collected: {len(self.otp)}",
            normalized={"otp_words_collected": len(self.otp), "decoder_profile": self.decoded.get("decoder_profile")},
        )]
        if self.otp_metadata_bundle.get("loaded"):
            items.append(EvidenceRecord(
                source_type="EXTERNAL_PROVISIONING_METADATA",
                source_path=self.otp_metadata_bundle.get("path", ""),
                acquisition_method="operator-supplied rpiboot -j recovery metadata",
                trust_level="HIGH",
                raw=json.dumps(self.otp_metadata_bundle.get("metadata", {}), ensure_ascii=False),
                normalized={
                    "files": self.otp_metadata_bundle.get("files", []),
                    "provenance_asserted_by_operator": True,
                    "cryptographically_authenticated": False,
                },
            ))
        return items

    def check_otp_read(self):
        if not self.otp_tool_available:
            return
        if not self.otp:
            self.report.add_finding(Finding(
                rule_id="HW-OTP-000", severity="INFO", category="HARDWARE",
                description="OTP state could not be read.",
                evidence="vcgencmd otp_dump returned no decoded OTP words",
                remediation="Run as root and verify that the installed vcgencmd supports otp_dump on this platform.",
                coverage_gap=True, finding_class="COVERAGE_GAP",
            ))

    def decode_otp(self):
        self.decoded = decode_otp_state(self.platform, self.otp, self.otp_metadata_bundle)
        self.report.raw_artifacts["otp_decoded"] = self.decoded
        self.report.raw_artifacts["otp_decoder_metadata"] = {
            "schema": OTP_DECODER_SCHEMA,
            "profile": self.decoded.get("decoder_profile"),
            "version": self.decoded.get("decoder_version"),
            "status": self.decoded.get("decoder_status"),
            "public_mapping": self.decoded.get("public_mapping"),
            "references": OFFICIAL_OTP_REFERENCES,
            "principle": "Undefined OTP rows and bits are never inferred.",
        }
        if self.decoded.get("decoder_status") in {"SUPPORTED", "PARTIAL"}:
            self.report.add_check(
                "RPI-OTP-DECODE-PASS", "PLATFORM_HARDWARE",
                "The model-specific public OTP mapping was decoded without inferring undocumented bits.",
                source_type="FIRMWARE_REPORTED", trust_level="MEDIUM",
                decoder_profile=self.decoded.get("decoder_profile"),
                decoder_status=self.decoded.get("decoder_status"),
            )

    def check_otp_security_fields(self):
        security = self.decoded.get("security", {})
        key = security.get("customer_key_hash", {})
        key_status = key.get("status", "UNKNOWN")
        jtag = security.get("vc_jtag_lock", {})
        jtag_status = jtag.get("status", "UNKNOWN")

        if key_status == "UNKNOWN":
            severity, actionable = self._profile_severity()
            self.report.add_finding(Finding(
                rule_id="RPI-OTP-002", severity=severity, category="HARDWARE",
                description="Customer Secure Boot key state could not be decoded from the available OTP evidence.",
                evidence=json.dumps(key, ensure_ascii=False),
                remediation=("For BCM2712, collect external provisioning metadata with `rpiboot -j` and pass it with "
                             "--otp-metadata. Do not infer undocumented OTP rows."),
                domain="BOOT_AND_EEPROM", status="EVIDENCE_INCOMPLETE", confidence="HIGH",
                coverage_gap=True, actionable=actionable, finding_class="COVERAGE_GAP",
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="Customer public-key hash state conclusively established",
                observed=key.get("note", "Customer key state unavailable"),
                rationale="The public BCM2712 runtime otp_dump map does not disclose the customer-key-hash rows.",
                evidence_items=self._otp_evidence_items(),
            ))
        elif key_status == "UNPROGRAMMED":
            severity, actionable = self._profile_severity()
            self.report.add_finding(Finding(
                rule_id="RPI-OTP-001", severity=severity, category="HARDWARE",
                description="The customer Secure Boot public-key hash is not programmed in OTP.",
                evidence=json.dumps(key, ensure_ascii=False),
                remediation="Provision customer-key Secure Boot only through the approved rpiboot recovery workflow.",
                domain="BOOT_AND_EEPROM", status="UNPROGRAMMED", actionable=actionable,
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="Customer public-key hash programmed when Secure Boot is required",
                observed="Customer key hash is all zero / reported unprogrammed",
                rationale="Without a programmed customer key hash, customer-key Secure Boot cannot be enforced.",
                evidence_items=self._otp_evidence_items(),
            ))
        elif key_status == "PROGRAMMED":
            self.report.add_check(
                "RPI-OTP-KEY-PASS", "BOOT_AND_EEPROM",
                "Customer Secure Boot public-key hash evidence is programmed.",
                source_type=("EXTERNAL_PROVISIONING_METADATA" if self.otp_metadata_bundle.get("loaded") else "FIRMWARE_REPORTED"),
                trust_level=("HIGH" if self.otp_metadata_bundle.get("loaded") else "MEDIUM"),
                decoder_profile=self.decoded.get("decoder_profile"),
            )

        if jtag_status in {"UNLOCKED", "PARTIAL"}:
            severity = "MEDIUM" if self.report.policy_profile in {"hardened", "secure-boot-required"} else "INFO"
            actionable = severity != "INFO"
            self.report.add_finding(Finding(
                rule_id="RPI-OTP-003", severity=severity, category="DEBUG",
                description="VideoCore JTAG is not fully locked.",
                evidence=json.dumps(jtag, ensure_ascii=False),
                remediation="Permanently lock JTAG only as part of an approved irreversible provisioning procedure.",
                domain="PLATFORM_HARDWARE", status=jtag_status, actionable=actionable,
                expected="VC JTAG locked for a production locked-appliance profile",
                observed=f"VC JTAG state: {jtag_status}",
                rationale="An unlocked debug path increases physical attack and post-compromise capability.",
                evidence_items=self._otp_evidence_items(),
            ))
        elif jtag_status == "LOCKED":
            self.report.add_check(
                "RPI-OTP-JTAG-PASS", "PLATFORM_HARDWARE", "VideoCore JTAG lock is asserted.",
                source_type=("EXTERNAL_PROVISIONING_METADATA" if self.otp_metadata_bundle.get("loaded") else "FIRMWARE_REPORTED"),
                trust_level=("HIGH" if self.otp_metadata_bundle.get("loaded") else "MEDIUM"),
            )

    def check_secure_boot(self, chain_validation: Optional[Dict[str, Any]] = None):
        boot_root = Path(self.report.target_path)
        self.secure_boot = build_secure_boot_evidence(
            self.platform, boot_root, self.decoded, self.otp_metadata_bundle,
            self.report.policy_profile, chain_validation=chain_validation,
        )
        self.report.raw_artifacts["secure_boot_assessment"] = self.secure_boot
        self.report.raw_artifacts["secure_boot_evidence"] = self.secure_boot
        overall = self.secure_boot.get("overall")
        pair = self.secure_boot.get("completeness")
        enable_status = self.secure_boot.get("evidence", {}).get("secure_boot_enablement", {}).get("status", "UNKNOWN")

        if pair == "INCONSISTENT":
            self.report.add_finding(Finding(
                rule_id="RPI-SB-002", severity="HIGH", category="BOOT",
                description="Secure Boot artifact evidence is internally inconsistent.",
                evidence=json.dumps(self.secure_boot, ensure_ascii=False),
                remediation="Restore a matching boot.img/boot.sig pair from an approved signed image.",
                domain="BOOT_AND_EEPROM", status="INCONSISTENT",
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="boot.img and boot.sig both present or both intentionally absent",
                observed=f"Secure Boot artifact pair: {pair}",
                rationale="A partial signed-boot artifact pair cannot establish an authenticated boot ramdisk.",
                evidence_items=self._otp_evidence_items() + [EvidenceRecord(
                    source_type="OS_MEDIATED_FILE_MEASURED", source_path=str(boot_root),
                    acquisition_method="boot filesystem presence check", trust_level="MEDIUM",
                    raw=json.dumps(self.secure_boot.get("evidence", {}), ensure_ascii=False),
                )],
            ))

        if overall == "DISABLED" and self.report.policy_profile != "secure-boot-required":
            severity, actionable = self._profile_severity(default="INFO", hardened="MEDIUM", required="HIGH")
            self.report.add_finding(Finding(
                rule_id="RPI-SB-001", severity=severity, category="BOOT",
                description="Customer-key Secure Boot is not enforced.",
                evidence=json.dumps(self.secure_boot, ensure_ascii=False),
                remediation="Provision and validate customer-key Secure Boot through the official irreversible workflow if policy requires it.",
                domain="BOOT_AND_EEPROM", status="DISABLED", actionable=actionable,
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="Customer-key Secure Boot enabled when required by policy",
                observed=f"OTP/provisioning evidence reports {enable_status}",
                rationale="The key/provisioning evidence conclusively indicates that customer-key Secure Boot is not enforced.",
                evidence_items=self._otp_evidence_items(),
            ))
            return

        boot_img_status = self.secure_boot.get("evidence", {}).get("boot_img", {}).get("status")
        boot_sig_status = self.secure_boot.get("evidence", {}).get("boot_sig", {}).get("status")

        validation = self.secure_boot.get('chain_validation', {})
        public_key_validation = validation.get('public_key', {})
        boot_image_validation = validation.get('boot_image_signature', {})
        bootconf_validation = validation.get('bootconf_signature', {})
        bootsys_validation = validation.get('bootsys_customer_countersignature', {})

        if self.report.policy_profile == "secure-boot-required":
            missing_controls: List[str] = []
            evidence_limits: List[str] = []
            enable_status = str(self.secure_boot.get('secure_boot_enablement', 'UNKNOWN'))
            if enable_status not in {'ENABLED', 'PROVISIONED'}:
                if enable_status in {'DISABLED', 'UNPROGRAMMED'}:
                    missing_controls.append('customer Secure Boot enforcement')
                else:
                    evidence_limits.append('Secure Boot enablement not conclusively evidenced')
            if boot_img_status != 'PRESENT':
                missing_controls.append('boot.img')
            if boot_sig_status != 'PRESENT':
                missing_controls.append('boot.sig')
            if bootconf_validation.get('overall') != VALIDATION_VALID:
                missing_controls.append('EEPROM bootconf customer signature')
            if get_soc_generation(self.platform) == 'BCM2712' and bootsys_validation.get('overall') != VALIDATION_VALID:
                missing_controls.append('BCM2712 bootsys customer countersignature')
            key_state = self.secure_boot.get('otp_customer_key', 'UNKNOWN')
            if key_state not in {'PROGRAMMED', 'MATCH'}:
                evidence_limits.append('customer OTP/provisioning key state unavailable')
            if public_key_validation.get('otp_binding') != 'MATCH':
                evidence_limits.append('public key to OTP binding not verified')

            missing_controls = list(dict.fromkeys(missing_controls))
            evidence_limits = list(dict.fromkeys(evidence_limits))
            if missing_controls:
                self.report.add_finding(Finding(
                    rule_id='RPI-SB-001', severity='HIGH', category='BOOT',
                    description='The secure-boot-required policy is not satisfied.',
                    evidence=json.dumps({
                        'missing_policy_controls': missing_controls,
                        'evidence_limits': evidence_limits,
                        'secure_boot': self.secure_boot,
                    }, ensure_ascii=False),
                    remediation=(
                        'Satisfy the missing policy controls listed in observed, provide the requested external '
                        'provisioning evidence where applicable, and rerun cryptographic validation.'
                    ),
                    domain='BOOT_AND_EEPROM', status='POLICY_FAIL', actionable=True,
                    finding_class='POLICY_FAILURE', remediation_group='SECURE_BOOT_ENABLEMENT',
                    expected='All controls required by secure-boot-required are present and cryptographically valid',
                    observed=(
                        f"missing_policy_controls={','.join(missing_controls)}; "
                        f"evidence_limits={','.join(evidence_limits) if evidence_limits else 'none'}"
                    ),
                    rationale=(
                        'This leaf finding records confirmed absence of controls required by the selected policy. '
                        'Evidence limitations remain separate coverage-gap findings.'
                    ),
                    evidence_items=self._otp_evidence_items() + [EvidenceRecord(
                        source_type='OS_MEDIATED_FILE_MEASURED', source_path=str(boot_root),
                        acquisition_method='secure-boot policy matrix evaluation', trust_level='MEDIUM',
                        raw=json.dumps({'missing_controls': missing_controls, 'evidence_limits': evidence_limits}),
                    )],
                ))

        if public_key_validation.get('source_relationship') == 'SUPPLIED_MISMATCHES_EEPROM' or public_key_validation.get('otp_binding') == 'MISMATCH':
            self.report.add_finding(Finding(
                rule_id='RPI-SB-004', severity='CRITICAL', category='BOOT',
                description='The Secure Boot customer public key does not match the EEPROM or OTP binding evidence.',
                evidence=json.dumps(public_key_validation, ensure_ascii=False),
                remediation='Restore the EEPROM image and signed artifacts that correspond to the provisioned customer key. Do not replace OTP-bound keys.',
                domain='BOOT_AND_EEPROM', status='KEY_BINDING_MISMATCH', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='Supplied key, EEPROM pubkey.bin and OTP customer-key hash form one consistent identity',
                observed=f"relationship={public_key_validation.get('source_relationship')}; otp_binding={public_key_validation.get('otp_binding')}",
                rationale='A key-identity mismatch breaks the customer chain of trust even when individual signatures are syntactically valid.',
                evidence_items=self._otp_evidence_items(),
            ))
        elif public_key_validation.get('otp_binding') == 'MATCH':
            self.report.add_check(
                'RPI-SB-KEY-BINDING-PASS', 'BOOT_AND_EEPROM',
                'The verification public key matches the EEPROM key and provisioned customer-key hash.',
                source_type='SIGNED_TRUSTED_ARTIFACT', trust_level='HIGH',
                pubkey_bin_sha256=public_key_validation.get('computed_pubkey_bin_sha256') or (
                    public_key_validation.get('supplied', {}) or public_key_validation.get('eeprom', {})
                ).get('pubkey_bin_sha256'),
            )

        if boot_image_validation.get('overall') == VALIDATION_INVALID:
            self.report.add_finding(Finding(
                rule_id='RPI-SB-003', severity='CRITICAL', category='BOOT',
                description='Cryptographic validation of boot.img against boot.sig failed.',
                evidence=json.dumps(boot_image_validation, ensure_ascii=False),
                remediation='Replace boot.img and boot.sig with an approved matching pair signed by the provisioned customer key.',
                domain='BOOT_AND_EEPROM', status='SIGNATURE_INVALID', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='SHA-256 digest and RSA PKCS#1 v1.5 signature both verify',
                observed=(f"digest={boot_image_validation.get('digest_status')}; "
                          f"rsa={boot_image_validation.get('rsa_signature_status')}; "
                          f"target_soc={boot_image_validation.get('target_soc_status')}"),
                rationale='The official boot.sig format signs boot.img directly with RSA-2048/SHA-256.',
                evidence_items=[EvidenceRecord(
                    source_type='OS_MEDIATED_FILE_MEASURED', source_path=str(boot_root),
                    acquisition_method='SHA-256 and RSA PKCS#1 v1.5 verification', trust_level='MEDIUM',
                    raw=json.dumps(boot_image_validation, ensure_ascii=False),
                )],
            ))
        elif boot_image_validation.get('overall') == VALIDATION_VALID:
            self.report.add_check(
                'RPI-SB-BOOT-IMAGE-PASS', 'BOOT_AND_EEPROM',
                'boot.img digest and RSA PKCS#1 v1.5 signature verified.',
                source_type='SIGNED_TRUSTED_ARTIFACT',
                trust_level='HIGH' if public_key_validation.get('otp_binding') == 'MATCH' else 'MEDIUM',
                image_sha256=boot_image_validation.get('image_sha256'),
                timestamp=boot_image_validation.get('timestamp'),
            )

        if bootconf_validation.get('overall') == VALIDATION_INVALID:
            self.report.add_finding(Finding(
                rule_id='RPI-SB-005', severity='CRITICAL', category='BOOT',
                description='The EEPROM boot configuration signature is cryptographically invalid.',
                evidence=json.dumps(bootconf_validation, ensure_ascii=False),
                remediation='Restore a bootconf.txt/bootconf.sig pair signed by the OTP-bound customer key.',
                domain='BOOT_AND_EEPROM', status='BOOTCONF_SIGNATURE_INVALID', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='EEPROM bootconf.txt digest and customer RSA signature verify',
                observed=(f"bootconf validation={bootconf_validation.get('overall')}; "
                          f"reason={bootconf_validation.get('reason_code')}; "
                          f"content_classes={bootconf_validation.get('content_classes', [])}"),
                rationale='A parsed customer signature was present and failed format, digest, key, or RSA validation. Missing or placeholder signatures are reported as UNVERIFIED instead.',
                evidence_items=[EvidenceRecord(
                    source_type='OS_MEDIATED_SPI_READ', source_path=str(validation.get('eeprom', {}).get('path', '')),
                    acquisition_method='EEPROM section extraction and RSA verification', trust_level='MEDIUM',
                    raw=json.dumps(bootconf_validation, ensure_ascii=False),
                )],
            ))
        elif bootconf_validation.get('overall') == VALIDATION_VALID:
            self.report.add_check(
                'RPI-SB-BOOTCONF-PASS', 'BOOT_AND_EEPROM',
                'EEPROM bootconf.txt digest and customer signature verified.',
                source_type='SIGNED_TRUSTED_ARTIFACT',
                trust_level='HIGH' if public_key_validation.get('otp_binding') == 'MATCH' else 'MEDIUM',
            )

        if bootsys_validation.get('overall') == VALIDATION_INVALID:
            self.report.add_finding(Finding(
                rule_id='RPI-SB-006', severity='CRITICAL', category='BOOT',
                description='BCM2712 bootsys customer counter-signature validation failed.',
                evidence=json.dumps(bootsys_validation, ensure_ascii=False),
                remediation='Install a Raspberry Pi-signed bootsys that is counter-signed by the provisioned customer key.',
                domain='BOOT_AND_EEPROM', status='BOOTSYS_COUNTERSIGNATURE_INVALID', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='Every detected bootsys customer trailer verifies with key number 16',
                observed=(f"bootsys validation={bootsys_validation.get('overall')}; "
                          f"reason={bootsys_validation.get('reason_code')}"),
                rationale='BCM2712 Secure Boot requires the Raspberry Pi second stage to be counter-signed by the customer key.',
                evidence_items=[EvidenceRecord(
                    source_type='OS_MEDIATED_SPI_READ', source_path=str(validation.get('eeprom', {}).get('path', '')),
                    acquisition_method='BCM2712 signed-blob trailer parsing and RSA verification', trust_level='MEDIUM',
                    raw=json.dumps(bootsys_validation, ensure_ascii=False),
                )],
            ))
        elif bootsys_validation.get('overall') == VALIDATION_VALID:
            self.report.add_check(
                'RPI-SB-BOOTSYS-PASS', 'BOOT_AND_EEPROM',
                'BCM2712 bootsys customer counter-signature verified.',
                source_type='SIGNED_TRUSTED_ARTIFACT',
                trust_level='HIGH' if public_key_validation.get('otp_binding') == 'MATCH' else 'MEDIUM',
            )

        if self.secure_boot.get('overall') == 'PASS':
            self.report.add_check(
                'RPI-SB-CHAIN-PASS', 'BOOT_AND_EEPROM',
                'The complete customer Secure Boot chain was cryptographically validated.',
                source_type='SIGNED_TRUSTED_ARTIFACT', trust_level='HIGH',
                authenticity=self.secure_boot.get('authenticity'),
                freshness=self.secure_boot.get('freshness'),
            )

        if self.secure_boot.get("coverage_gap"):
            severity, actionable = self._profile_severity(default="INFO", hardened="MEDIUM", required="HIGH")
            secure_boot_blockers = [
                finding.rule_id for finding in self.report.findings
                if finding.rule_id in {
                    "RPI-OTP-001", "RPI-OTP-002", "RPI-SB-001", "RPI-SB-002",
                    "RPI-SB-003", "RPI-SB-004", "RPI-SB-005", "RPI-SB-006",
                }
            ]
            self.report.add_finding(Finding(
                rule_id="HW-SEC-001", severity=severity, category="HARDWARE",
                description="Secure Boot chain could not be conclusively evaluated.",
                evidence=json.dumps(self.secure_boot, ensure_ascii=False),
                remediation=("Resolve the leaf findings listed in blocked_by, then rerun cryptographic validation "
                             "until the chain is VERIFIED or a specific cryptographic INVALID finding is produced."),
                domain="BOOT_AND_EEPROM", status="UNVERIFIED", confidence="HIGH",
                coverage_gap=True, actionable=actionable,
                aggregate=True, blocked_by=secure_boot_blockers,
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="AUTHENTICITY, COMPLETENESS, FRESHNESS and POLICY conclusively evaluated",
                observed=(f"overall={overall}; authenticity={self.secure_boot.get('authenticity')}; "
                          f"completeness={self.secure_boot.get('completeness')}; "
                          f"chain_validation={self.secure_boot.get('chain_validation', {}).get('overall')}"),
                rationale=(f"GGFW {TOOL_VERSION_DISPLAY} validates available customer-chain signatures, but "
                           "returns UNVERIFIED whenever a required key, OTP binding, artifact, or BCM2712 counter-signature is unavailable."),
                finding_class="COVERAGE_GAP",
                evidence_items=self._otp_evidence_items() + [EvidenceRecord(
                    source_type="OS_MEDIATED_FILE_MEASURED", source_path=str(boot_root),
                    acquisition_method="boot filesystem presence check", trust_level="MEDIUM",
                    raw=f"boot.img={boot_img_status}; boot.sig={boot_sig_status}",
                )],
            ))

    def check_eeprom_tool_availability(self):
        if "ERROR_MISSING" in self.eeprom_conf:
            self.report.add_finding(Finding(
                rule_id="HW-EEPROM-002", severity="INFO", category="HARDWARE",
                description="EEPROM audit skipped: rpi-eeprom-config tool not available.",
                evidence="rpi-eeprom-config not found",
                remediation="This is an auditor limitation, not a device vulnerability."
            ))
