"""Extracted GGFW component: audit."""
from uuid import uuid4
from ggfw._compat import (
    Any, Dict, List, Optional, Path, asdict, datetime, json, os, timezone,
)
from ggfw.boot.integrity import BootIntegrityChecker
from ggfw.boot.resolution import BootResolutionGraphBuilder
from ggfw.cli import GGFWArgumentParser, preflight_explicit_external_inputs
from ggfw.constants import EVIDENCE_SCHEMA, TOOL_VERSION, TOOL_VERSION_DISPLAY
from ggfw.crypto.kat import run_crypto_self_test
from ggfw.crypto.validation import validate_secure_boot_chain
from ggfw.dependencies import check_dependencies
from ggfw.engines.eeprom_update import EEPROMUpdatePolicyEngine
from ggfw.engines.hardware_policy import HardwarePolicyEngine
from ggfw.engines.host_policy import FATPolicyEngine
from ggfw.engines.pi5_policy import Pi5PolicyEngine
from ggfw.errors import GGFWRuntimeError
from ggfw.hardware.interrogator import HardwareInterrogator
from ggfw.hardware.otp import load_rpiboot_metadata
from ggfw.hardware.platform import detect_platform, get_soc_generation
from ggfw.models.evidence import EvidenceRecord
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport
from ggfw.models.spi import SPIReadResult
from ggfw.packaging.ggcap import EvidencePackageBuilder
from ggfw.parsers.cmdline import CmdlineTxtParser
from ggfw.parsers.config_txt import ConfigTxtParser
from ggfw.reporting.console import print_otp_summary, print_positive_checks, print_remediation_summary, print_scan_summary, print_secure_boot_matrix, print_trust_model, sort_findings_for_display, terminal_excerpt
from ggfw.reporting.gates import build_gate_accounting, build_secure_boot_policy_rollup, print_gate_accounting, print_secure_boot_policy_rollup
from ggfw.spi.reader import SPIEEPROMReader
from ggfw.system.passwords import load_weak_password_dictionary

def run_audit():
    parser = GGFWArgumentParser(
        description='GGFW Raspberry Pi Unified Auditor (Kali compatible, read-only SPI)',
        epilog=(
            'Exit codes: 0=completed/no gate, 1=tool or runtime failure, 2=policy gate triggered. '
            'Severity gates evaluate leaf security/policy findings. Coverage gaps require --fail-on-coverage '
            'or --fail-on COVERAGE_GAP; aggregate findings never trigger exit.'
        ),
    )
    parser.add_argument('--boot-path', default='/boot/firmware', help='Mounted boot filesystem path')
    parser.add_argument(
        '--output', default=None,
        help='Output .ggcap package path. A legacy .json value writes JSON there and creates a sibling .ggcap.'
    )
    parser.add_argument('--json-output', help='Optional additional standalone report JSON path')
    parser.add_argument('--evidence-root', default='ggfw-evidence', help='Root directory for timestamped evidence')
    parser.add_argument(
        '--policy-profile', default='default',
        choices=('default', 'hardened', 'secure-boot-required', 'resilient-appliance'),
        help='Policy profile used for applicability and severity adjustments',
    )
    parser.add_argument(
        '--min-severity', default='INFO',
        choices=('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
        help='Minimum severity displayed in the detailed terminal listing',
    )
    parser.add_argument('--summary-only', action='store_true', help='Suppress the detailed terminal listing')
    parser.add_argument('--show-passed', action='store_true', help='Print recorded positive checks')
    parser.add_argument('--show-trust-model', action='store_true', help='Print evidence trust legend and acquisition context')
    parser.add_argument('--show-otp', action='store_true', help='Print the model-specific OTP decoder summary')
    parser.add_argument('--secure-boot-evidence', action='store_true', help='Print the Secure Boot evidence matrix')
    parser.add_argument('--crypto-self-test', action='store_true', help='Run embedded cryptographic known-answer tests and exit')
    parser.add_argument('--otp-only', action='store_true', help='Run OTP/Secure-Boot evidence collection without host posture, baseline or SPI acquisition')
    parser.add_argument(
        '--weak-password-file',
        help=(
            'UTF-8 file with one password candidate per line; extends the built-in list; '
            'contents are never written to reports'
        ),
    )
    parser.add_argument('--otp-metadata', help='rpiboot -j metadata JSON file or directory for external provisioning evidence')
    parser.add_argument(
        '--secure-boot-public-key',
        help='Customer RSA-2048 public key in PEM format used to validate boot.sig and EEPROM signatures',
    )
    parser.add_argument(
        '--max-boot-signature-age-days', type=int, default=None,
        help='Optional maximum accepted age of the boot.sig timestamp; stale signatures fail validation',
    )
    parser.add_argument(
        '--fail-on', default='NONE',
        choices=('NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ACTIONABLE', 'COVERAGE_GAP', 'ANY'),
        help='Exit with status 2 for matching leaf security/policy findings; coverage gaps are separate by default',
    )
    parser.add_argument('--fail-on-coverage', action='store_true', help='Include leaf COVERAGE_GAP findings in severity-based --fail-on gates')
    parser.add_argument(
        '--gate-exclude', action='append', default=[],
        choices=('COVERAGE_GAP', 'AGGREGATE'),
        help=(
            'Exclude a finding attribute from --fail-on evaluation without removing it from the report. '
            'Repeat for multiple exclusions.'
        ),
    )
    parser.add_argument('--skip-integrity', action='store_true', help='Skip boot measurement and baseline comparison')
    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument('--baseline', help='Compare boot files and resolved chain with a GGFW baseline')
    baseline_group.add_argument('--create-baseline', help='Create or replace a device-specific boot baseline')
    parser.add_argument('--skip-spi', action='store_true', help='Skip read-only SPI EEPROM acquisition')
    parser.add_argument('--spi-device', help='Override the platform-default spidev node')
    parser.add_argument('--spi-output', default=None, help='Optional external SPI dump path')
    parser.add_argument('--spi-speed', type=int, default=16000, help='flashrom linux_spi clock in kHz')
    args = parser.parse_args()
    # Preserve user order while de-duplicating repeatable gate exclusions.
    args.gate_exclude = list(dict.fromkeys(args.gate_exclude))

    if args.spi_speed <= 0:
        parser.error('--spi-speed must be a positive integer')
    if args.max_boot_signature_age_days is not None and args.max_boot_signature_age_days < 0:
        parser.error('--max-boot-signature-age-days must be zero or greater')
    if args.otp_only and (args.baseline or args.create_baseline):
        parser.error('--otp-only cannot be combined with --baseline or --create-baseline')
    if args.otp_only and args.weak_password_file:
        parser.error('--otp-only cannot be combined with --weak-password-file')
    if args.otp_only:
        args.skip_integrity = True
        args.skip_spi = True
    if args.skip_integrity and (args.baseline or args.create_baseline):
        parser.error('--skip-integrity cannot be combined with --baseline or --create-baseline')

    if args.crypto_self_test:
        return run_crypto_self_test()

    weak_passwords, weak_password_metadata = load_weak_password_dictionary(
        args.weak_password_file
    )
    preflight_otp_metadata, preflight_public_key = preflight_explicit_external_inputs(args)

    boot_path = str(Path(args.boot_path).expanduser().resolve())
    config_txt = os.path.join(boot_path, 'config.txt')
    cmdline_txt = os.path.join(boot_path, 'cmdline.txt')
    if not os.path.isdir(boot_path):
        raise GGFWRuntimeError(f'Boot path is not a directory: {boot_path}')
    if not os.path.isfile(config_txt) and not args.otp_only:
        raise GGFWRuntimeError(f'config.txt was not found at: {config_txt}')

    print(f'[*] GGFW {TOOL_VERSION_DISPLAY} Cryptographic Secure-Boot Chain Auditor starting...')
    print(f'[*] Target boot path: {boot_path}')
    print(f'[*] Policy profile: {args.policy_profile}')

    platform = detect_platform()
    soc = get_soc_generation(platform)
    print(f'[*] Detected platform: {platform}')

    now_utc = datetime.now(timezone.utc)
    scan_id = f"ggfw-{now_utc.strftime('%Y%m%dT%H%M%SZ')}-{soc.lower()}-{uuid4().hex}"
    evidence_builder = EvidencePackageBuilder(args.evidence_root, scan_id)

    legacy_json_output: Optional[Path] = None
    if args.output:
        requested_output = Path(args.output).expanduser().resolve()
        if requested_output.name.endswith('.json'):
            legacy_json_output = requested_output
            package_name = requested_output.name[:-5]
            if not package_name.endswith('.ggcap'):
                package_name += '.ggcap'
            package_path = requested_output.with_name(package_name)
        else:
            package_path = requested_output
    else:
        package_path = evidence_builder.root / f'{scan_id}.ggcap'

    report = GGFWReport(
        target_path=boot_path,
        platform_guess=platform,
        scan_timestamp=now_utc.isoformat(),
        scan_id=scan_id,
        policy_profile=args.policy_profile,
    )

    report.raw_artifacts['evidence_model'] = {
        'schema': EVIDENCE_SCHEMA,
        'acquisition_context': 'IN_BAND',
        'policy_gate_semantics': (
            'In secure-boot-required, an UNVERIFIED Secure Boot state is HIGH because the required control '
            'could not be demonstrated. This is a policy failure and coverage gap, not evidence that Secure Boot is disabled.'
        ),
        'gate_exclusion_semantics': {
            'COVERAGE_GAP': 'Do not let evidence-coverage gaps trigger the selected --fail-on gate.',
            'AGGREGATE': 'Do not let aggregate outcome findings trigger the selected --fail-on gate.',
            'scope': 'Exclusions affect process gating only; findings remain in reports and counts.',
        },
        'exit_codes': {
            '0': 'scan completed; policy gate not triggered',
            '1': 'tool/runtime/argument/acquisition/baseline/packaging failure',
            '2': 'scan completed; --fail-on policy triggered',
        },
        'trust_legend': {
            'HIGH': 'independent offline/external evidence or a verified trusted artifact',
            'MEDIUM': 'evidence mediated by the examined OS, firmware interface, or local baseline',
            'LOW': 'indirect, heuristic, or incomplete evidence',
        },
        'source_types': {
            'EXTERNAL_SPI_DUMP': {
                'trust_level': 'HIGH',
                'description': 'Independent programmer acquisition while the target platform is not mediating the read.',
            },
            'OFFLINE_FILE_MEASURED': {
                'trust_level': 'HIGH',
                'description': 'File measurement from offline or write-blocked media outside the examined runtime.',
            },
            'SIGNED_TRUSTED_ARTIFACT': {
                'trust_level': 'HIGH',
                'description': 'Artifact independently verified against a trusted signing key or attestation root.',
            },
            'EXTERNAL_PROVISIONING_METADATA': {
                'trust_level': 'HIGH',
                'description': 'Operator-supplied rpiboot recovery metadata acquired outside the examined OS; file provenance is asserted, not cryptographically authenticated.',
            },
            'OPERATOR_SUPPLIED_PUBLIC_KEY': {
                'trust_level': 'MEDIUM',
                'description': 'Customer public key supplied by the operator; becomes HIGH only after matching EEPROM and OTP binding evidence.',
            },
            'OS_MEDIATED_SPI_READ': {
                'trust_level': 'MEDIUM',
                'description': 'flashrom/linux_spi acquisition mediated by the running kernel.',
            },
            'FIRMWARE_REPORTED': {
                'trust_level': 'MEDIUM',
                'description': 'State reported by vcgencmd or rpi-eeprom tools.',
            },
            'OS_OBSERVED': {
                'trust_level': 'MEDIUM',
                'description': 'Runtime state observed through procfs, sysfs, NSS and local tools.',
            },
            'OS_MEDIATED_FILE_MEASURED': {
                'trust_level': 'MEDIUM',
                'description': 'File size, digest or resolved-chain measurement performed by the examined operating system.',
            },
            'USER_BASELINE': {
                'trust_level': 'MEDIUM',
                'description': 'Operator-created device-specific measured baseline.',
            },
        },
    }

    print('[*] Checking dependencies...')
    deps = check_dependencies()
    for tool, (found, info) in deps.items():
        status = 'OK' if found else 'MISSING'
        print(f'    [{status}] {tool}: {info}')
    report.raw_artifacts['dependencies'] = {
        tool: {'available': found, 'info': info}
        for tool, (found, info) in deps.items()
    }

    print('[*] Parsing config.txt and resolving the active boot chain...')
    if args.otp_only and not os.path.isfile(config_txt):
        config_detail = {"active_config": {"all": {}}, "sections": {}, "directives": [], "includes": [],
                         "parsed_files": [], "errors": [], "otp_only_without_boot_config": True}
    else:
        config_detail = ConfigTxtParser.parse_detailed(config_txt, boot_path, platform)
    config_data = config_detail.get('active_config', {'all': {}})
    cmdline_data = CmdlineTxtParser.parse(cmdline_txt)
    boot_graph = BootResolutionGraphBuilder(boot_path, platform, config_detail).build()

    report.raw_artifacts['config_txt_parsed'] = config_detail.get('sections', {})
    report.raw_artifacts['config_txt_active'] = config_data
    report.raw_artifacts['config_txt_directives'] = config_detail.get('directives', [])
    report.raw_artifacts['config_txt_includes'] = config_detail.get('includes', [])
    report.raw_artifacts['cmdline_txt_parsed'] = cmdline_data
    report.raw_artifacts['boot_resolution_graph'] = boot_graph
    report.add_check(
        'RPI-BOOT-GRAPH-000', 'BOOT_AND_EEPROM',
        'The active boot chain was resolved from config.txt.',
        source_type='OS_MEDIATED_FILE_MEASURED', trust_level='MEDIUM',
        fingerprint=boot_graph.get('fingerprint'),
        active_files=boot_graph.get('active_files', []),
    )
    report.raw_artifacts['baseline_assessment'] = {
        'requested': bool(args.baseline),
        'path': str(args.baseline or ''),
        'status': 'NOT_REQUESTED' if not args.baseline else 'PENDING',
        'file_match_count': 0,
        'file_mismatch_count': 0,
        'resolved_chain_match': None,
    }

    if config_detail.get('errors'):
        report.add_finding(Finding(
            rule_id='RPI-CONFIG-000', severity='MEDIUM', category='BOOT',
            description='One or more config.txt includes could not be resolved safely.',
            evidence='; '.join(config_detail['errors']),
            remediation='Correct missing, cyclic or excessively nested config.txt includes.',
            domain='BOOT_AND_EEPROM', status='INCOMPLETE', coverage_gap=True,
            expected='Every active config.txt include is parsed', observed='Include parsing errors',
            finding_class='COVERAGE_GAP',
        ))

    if not args.otp_only:
        fat_engine = FATPolicyEngine(
            config_data,
            cmdline_data,
            report,
            boot_path,
            weak_passwords=weak_passwords,
            weak_password_metadata=weak_password_metadata,
        )
        fat_engine.run_all_checks()
        print('[*] Running Pi5-specific checks...')
        Pi5PolicyEngine(config_data, report, platform).run_all_checks()
    else:
        print('[*] OTP-only mode: host posture and Pi5 runtime policy checks skipped.')

    integrity_checker: Optional[BootIntegrityChecker] = None
    integrity_results: Dict[str, Dict[str, Any]] = {}
    if not args.skip_integrity:
        action = 'Measuring resolved boot files'
        if args.baseline:
            action = f'Comparing resolved boot chain with baseline: {args.baseline}'
        elif args.create_baseline:
            action = f'Creating boot baseline: {args.create_baseline}'
        print(f'[*] {action}...')

        integrity_checker = BootIntegrityChecker(
            boot_path,
            platform,
            config=config_data,
            baseline_path=args.baseline,
            boot_graph=boot_graph,
        )
        integrity_results = integrity_checker.verify_integrity()
        report.raw_artifacts['boot_integrity'] = integrity_results

        if integrity_checker.baseline_error:
            report.add_finding(Finding(
                rule_id='RPI-INTEGRITY-000', severity='MEDIUM', category='INTEGRITY',
                description='Boot baseline could not be loaded or validated.',
                evidence=integrity_checker.baseline_error,
                remediation='Regenerate the baseline from a trusted system state and protect it from modification.',
                expected='Valid GGFW baseline', observed=integrity_checker.baseline_error,
            ))
        elif integrity_checker.baseline:
            if integrity_checker.baseline_legacy:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-005', severity='INFO', category='INTEGRITY',
                    description='A legacy v1 baseline was loaded without a resolved-chain fingerprint.',
                    evidence='schema=ggfw-boot-baseline/v1',
                    remediation=(f'Regenerate the baseline with GGFW {TOOL_VERSION} to cover the resolved boot graph.'),
                    status='LEGACY_BASELINE', finding_class='COVERAGE_GAP', coverage_gap=True,
                    expected='ggfw-boot-baseline/v2', observed='ggfw-boot-baseline/v1',
                ))
            baseline_platform = integrity_checker.baseline.get('platform')
            baseline_soc = integrity_checker.baseline.get('soc')
            if baseline_platform != platform or baseline_soc != soc:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-003', severity='MEDIUM', category='INTEGRITY',
                    description='Boot baseline platform metadata differs from the scanned device.',
                    evidence=(
                        f'baseline_platform={baseline_platform!r}; current_platform={platform!r}; '
                        f'baseline_soc={baseline_soc!r}; current_soc={soc!r}'
                    ),
                    remediation='Use a baseline created for this board class and intended software image.',
                ))

            mismatched = [name for name, result in integrity_results.items() if result['status'] == 'BASELINE_MISMATCH']
            if mismatched:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-001', severity='HIGH', category='INTEGRITY',
                    description='Boot files differ from the selected measured baseline.',
                    evidence=', '.join(mismatched),
                    remediation='Validate the changes against an approved update or restore the trusted image.',
                    expected='All measured boot files match the selected baseline',
                    observed=f'Mismatched files: {", ".join(mismatched)}',
                    evidence_items=[
                        EvidenceRecord(
                            source_type='OS_MEDIATED_FILE_MEASURED', source_path=boot_path,
                            acquisition_method='SHA-256 and size measurement through the running OS', trust_level='MEDIUM',
                            raw=', '.join(mismatched), normalized={'mismatched_files': mismatched},
                        ),
                        EvidenceRecord(
                            source_type='USER_BASELINE', source_path=str(args.baseline or ''),
                            acquisition_method='operator-selected baseline comparison', trust_level='MEDIUM',
                            raw=str(args.baseline or ''),
                        ),
                    ],
                ))

            untracked = [name for name, result in integrity_results.items() if result['status'] == 'BASELINE_MISSING_ENTRY']
            if untracked:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-004', severity='INFO', category='INTEGRITY',
                    description='Resolved boot files are present but absent from the selected baseline.',
                    evidence=', '.join(untracked),
                    remediation='Review the files and regenerate the baseline after approving the resolved boot chain.',
                    finding_class='COVERAGE_GAP', coverage_gap=True,
                    expected='Every resolved boot file represented in baseline',
                    observed=f'Untracked files: {", ".join(untracked)}',
                ))

            baseline_chain = integrity_checker.baseline.get('resolved_chain', {})
            baseline_fingerprint = baseline_chain.get('fingerprint')
            if baseline_fingerprint:
                if baseline_fingerprint == boot_graph.get('fingerprint'):
                    report.add_check(
                        'RPI-BOOT-GRAPH-001', 'BOOT_AND_EEPROM',
                        'Resolved boot-chain fingerprint matches the baseline.',
                        source_type='OS_MEDIATED_FILE_MEASURED', trust_level='MEDIUM',
                        fingerprint=baseline_fingerprint,
                    )
                else:
                    report.add_finding(Finding(
                        rule_id='RPI-BOOT-GRAPH-001', severity='HIGH', category='INTEGRITY',
                        description='The resolved boot chain differs from the selected baseline.',
                        evidence=(
                            f'baseline={baseline_fingerprint}; current={boot_graph.get("fingerprint")}'
                        ),
                        remediation='Review config.txt directives, includes and selected boot components.',
                        expected=baseline_fingerprint,
                        observed=str(boot_graph.get('fingerprint')),
                        evidence_items=[
                            EvidenceRecord(
                                source_type='OS_MEDIATED_FILE_MEASURED', source_path='config.txt/resolved-chain',
                                acquisition_method='resolved-chain fingerprint calculated through the running OS', trust_level='MEDIUM',
                                raw=str(boot_graph.get('fingerprint')),
                                normalized={'active_files': boot_graph.get('active_files', [])},
                            ),
                            EvidenceRecord(
                                source_type='USER_BASELINE', source_path=str(args.baseline or ''),
                                acquisition_method='baseline fingerprint lookup', trust_level='MEDIUM',
                                raw=str(baseline_fingerprint),
                            ),
                        ],
                    ))

        missing_files = [name for name, result in integrity_results.items() if result['status'] == 'MISSING']
        if missing_files:
            report.add_finding(Finding(
                rule_id='RPI-INTEGRITY-002', severity='MEDIUM', category='INTEGRITY',
                description='Expected or baseline-tracked boot files are missing.',
                evidence=', '.join(missing_files),
                remediation='Verify the active boot configuration and boot filesystem completeness.',
            ))

        matching_files = [name for name, result in integrity_results.items() if result['status'] == 'BASELINE_MATCH']
        if matching_files:
            report.add_check(
                'RPI-INTEGRITY-PASS', 'BOOT_AND_EEPROM',
                'Measured boot files match the selected baseline.',
                source_type='OS_MEDIATED_FILE_MEASURED', trust_level='MEDIUM',
                count=len(matching_files), files=matching_files,
            )

        if args.baseline:
            baseline_assessment = report.raw_artifacts['baseline_assessment']
            baseline_assessment['file_match_count'] = sum(
                1 for result in integrity_results.values() if result.get('status') == 'BASELINE_MATCH'
            )
            baseline_assessment['file_mismatch_count'] = sum(
                1 for result in integrity_results.values()
                if result.get('status') in {'BASELINE_MISMATCH', 'MISSING'}
            )
            baseline_assessment['untracked_count'] = sum(
                1 for result in integrity_results.values() if result.get('status') == 'BASELINE_MISSING_ENTRY'
            )
            if integrity_checker.baseline_error:
                baseline_assessment['status'] = 'ERROR'
            elif integrity_checker.baseline:
                expected_fp = integrity_checker.baseline.get('resolved_chain', {}).get('fingerprint')
                current_fp = boot_graph.get('fingerprint')
                baseline_assessment['resolved_chain_match'] = (
                    None if not expected_fp else expected_fp == current_fp
                )
                if baseline_assessment['file_mismatch_count'] or baseline_assessment['resolved_chain_match'] is False:
                    baseline_assessment['status'] = 'DRIFT'
                elif integrity_checker.baseline_legacy or baseline_assessment['untracked_count']:
                    baseline_assessment['status'] = 'MATCH_WITH_COVERAGE_GAP'
                else:
                    baseline_assessment['status'] = 'MATCH'
            else:
                baseline_assessment['status'] = 'ERROR'

        if args.create_baseline:
            baseline_payload = integrity_checker.write_baseline(args.create_baseline, integrity_results)
            report.raw_artifacts['baseline_assessment'] = {
                'requested': False,
                'path': str(Path(args.create_baseline).expanduser().resolve()),
                'status': 'CREATED',
                'file_match_count': 0,
                'file_mismatch_count': 0,
                'resolved_chain_match': None,
            }
            report.raw_artifacts['baseline_created'] = {
                'path': str(Path(args.create_baseline).expanduser().resolve()),
                'schema': baseline_payload['schema'],
                'files': len(baseline_payload['files']),
                'resolved_chain_fingerprint': boot_graph.get('fingerprint'),
                'missing_at_creation': baseline_payload['missing_at_creation'],
            }
            print(
                f"[+] Baseline saved: {Path(args.create_baseline).expanduser().resolve()} "
                f"({len(baseline_payload['files'])} files)"
            )
    else:
        report.raw_artifacts['boot_integrity'] = {'attempted': False, 'reason': 'Disabled with --skip-integrity'}

    print('[*] Interrogating hardware...')
    hw_interrogator = HardwareInterrogator()
    report.raw_artifacts['tool_metadata'] = hw_interrogator.get_tool_metadata()
    flash_metadata = report.raw_artifacts['tool_metadata'].get('flashrom', {})
    if flash_metadata.get('path') and not flash_metadata.get('wp_cli_expected', True):
        report.add_finding(Finding(
            rule_id='RPI-TOOL-001', severity='INFO', category='TOOLING',
            description='Installed flashrom version predates expected write-protection CLI support.',
            evidence=json.dumps(flash_metadata, ensure_ascii=False),
            remediation='Use flashrom 1.3 or newer for --wp-status assessment.',
            finding_class='TOOLING_LIMITATION', coverage_gap=True,
        ))

    otp_data: Dict[str, str] = {}
    eeprom_conf = 'ERROR_MISSING: hardware interrogation unavailable'
    hw_interrogator.cache.clear()

    if hw_interrogator.vcgencmd_path:
        print(f'[*] Using vcgencmd at: {hw_interrogator.vcgencmd_path}')
        otp_data = hw_interrogator.get_otp_dump()
        report.raw_artifacts['otp_raw'] = otp_data
        report.raw_artifacts['bootloader_version'] = hw_interrogator.get_bootloader_version()
    else:
        print('[-] vcgencmd not found. OTP and bootloader-version checks skipped.')
        report.add_finding(Finding(
            rule_id='HW-OTP-000', severity='INFO', category='HARDWARE',
            description='vcgencmd not found; OTP interrogation was skipped.',
            evidence='vcgencmd binary missing',
            remediation='Install a compatible vcgencmd build if OTP checks are required.',
            coverage_gap=True, finding_class='TOOLING_LIMITATION',
        ))

    if hw_interrogator.rpi_eeprom_config_path:
        print(f'[*] Using rpi-eeprom-config at: {hw_interrogator.rpi_eeprom_config_path}')
        eeprom_conf = hw_interrogator.get_eeprom_config()
    else:
        print('[-] rpi-eeprom-config not found. EEPROM config parsing may be limited.')

    report.raw_artifacts['eeprom_config'] = eeprom_conf
    otp_metadata_bundle = preflight_otp_metadata or load_rpiboot_metadata(None)
    report.raw_artifacts['otp_metadata'] = otp_metadata_bundle
    if args.otp_metadata:
        if otp_metadata_bundle.get('loaded'):
            print(f"[+] rpiboot OTP metadata loaded: {len(otp_metadata_bundle.get('files', []))} JSON file(s)")
        else:
            print(f"[-] rpiboot OTP metadata could not be loaded: {otp_metadata_bundle.get('error')}")
    hardware_policy_engine = HardwarePolicyEngine(
        platform, otp_data, eeprom_conf, report,
        otp_tool_available=bool(hw_interrogator.vcgencmd_path),
        otp_metadata_bundle=otp_metadata_bundle,
    )
    hardware_policy_engine.run_all_checks(defer_secure_boot=True)

    update_policy_engine = EEPROMUpdatePolicyEngine(
        platform=platform,
        eeprom_conf=eeprom_conf,
        report=report,
        interrogator=hw_interrogator,
    )

    if not args.otp_only:
        update_policy_engine.run_pre_spi()

    spi_result: Optional[SPIReadResult] = None
    if not args.skip_spi and not args.otp_only:
        default_spi_path = evidence_builder.path('evidence/spi/eeprom.bin')
        spi_output = args.spi_output or str(default_spi_path)
        print('[*] Starting read-only SPI EEPROM acquisition...')
        if hw_interrogator.flashrom_path:
            print(f'[*] Using flashrom at: {hw_interrogator.flashrom_path}')

        spi_reader = SPIEEPROMReader(
            platform=platform,
            flashrom_path=hw_interrogator.flashrom_path,
            rpi_eeprom_config_path=hw_interrogator.rpi_eeprom_config_path,
            report=report,
            device_override=args.spi_device,
            spi_speed_khz=args.spi_speed,
        )
        spi_result = spi_reader.acquire(spi_output, eeprom_conf)
        report.raw_artifacts['spi_eeprom'] = asdict(spi_result)
        flash_runtime = report.raw_artifacts.get('tool_metadata', {}).get('flashrom', {})
        flash_runtime['wp_status_runtime_supported'] = spi_result.wp_supported
        flash_runtime['detected_chip'] = spi_result.detected_chip
        flash_runtime['probe_ok'] = spi_result.probe_ok
        if not args.otp_only:
            update_policy_engine.run_post_spi(spi_result)

        if spi_result.read_ok:
            report.add_check(
                'RPI-SPI-READ-PASS', 'BOOT_AND_EEPROM',
                'OS-mediated SPI EEPROM acquisition completed successfully.',
                source_type='OS_MEDIATED_SPI_READ', trust_level='MEDIUM',
                chip=spi_result.detected_chip,
                size=spi_result.size,
                sha256=spi_result.sha256,
            )
            print(f'[+] SPI EEPROM read: {spi_result.output_path}')
            print(f'[+] SPI EEPROM size: {spi_result.size} bytes')
            print(f'[+] SPI EEPROM SHA-256: {spi_result.sha256}')
            if spi_result.detected_chip:
                print(f'[+] SPI flash chip: {spi_result.detected_chip}')
            if spi_result.bootconf_path:
                print(f'[+] EEPROM bootconf: {spi_result.bootconf_path}')
            if spi_result.config_comparison:
                print(f"[*] Raw SPI vs live EEPROM config: {spi_result.config_comparison.get('result')}")
            print(f'[*] SPI EEPROM write protection: {spi_result.wp_assessment}')
            if spi_result.wp_start is not None and spi_result.wp_length is not None:
                print(
                    f'[*] SPI WP range: start=0x{spi_result.wp_start:08x}, '
                    f'length=0x{spi_result.wp_length:08x}'
                )
        else:
            print(f'[-] SPI EEPROM acquisition not completed: {spi_result.error}')
    elif args.otp_only:
        spi_result = SPIReadResult(attempted=False)
        report.raw_artifacts['spi_eeprom'] = {
            'attempted': False, 'reason': 'OTP-only mode', 'wp_assessment': 'NOT_TESTED'
        }
    else:
        spi_result = SPIReadResult(attempted=False)
        report.raw_artifacts['spi_eeprom'] = {
            'attempted': False, 'reason': 'Disabled with --skip-spi', 'wp_assessment': 'NOT_TESTED'
        }
        report.add_finding(Finding(
            rule_id='RPI-SPI-WP-000', severity='INFO', category='HARDWARE',
            description='SPI EEPROM write-protection assessment was not performed.',
            evidence='SPI acquisition disabled with --skip-spi',
            remediation='Run without --skip-spi to query flashrom --wp-status.',
            coverage_gap=True, finding_class='COVERAGE_GAP',
        ))
        update_policy_engine.run_post_spi(spi_result)

    spi_image_for_validation = None
    if spi_result is not None and spi_result.read_ok:
        spi_image_for_validation = spi_result.output_path
    print('[*] Validating the customer Secure Boot chain...')
    secure_boot_validation = validate_secure_boot_chain(
        platform_name=platform,
        boot_root=Path(boot_path),
        spi_image_path=spi_image_for_validation,
        public_key_path=args.secure_boot_public_key,
        decoded=report.raw_artifacts.get('otp_decoded', {}),
        metadata_bundle=otp_metadata_bundle,
        max_signature_age_days=args.max_boot_signature_age_days,
        supplied_key_material=preflight_public_key,
    )
    report.raw_artifacts['secure_boot_validation'] = secure_boot_validation
    hardware_policy_engine.check_secure_boot(chain_validation=secure_boot_validation)
    print(
        f"[*] Secure Boot chain validation: {secure_boot_validation.get('overall')} "
        f"(boot.img={secure_boot_validation.get('boot_image_signature', {}).get('overall')}, "
        f"bootconf={secure_boot_validation.get('bootconf_signature', {}).get('overall')}, "
        f"bootsys={secure_boot_validation.get('bootsys_customer_countersignature', {}).get('overall')})"
    )

    # Determine tool/runtime failures separately from a successfully completed policy gate.
    runtime_issues: List[str] = []
    if args.baseline and report.raw_artifacts.get('baseline_assessment', {}).get('status') == 'ERROR':
        runtime_issues.append('BASELINE_LOAD_OR_VALIDATION_FAILED')
    if not args.skip_spi and not args.otp_only:
        if not deps.get('flashrom', (False, ''))[0]:
            runtime_issues.append('FLASHROM_MISSING')
        elif spi_result is None or not spi_result.read_ok:
            runtime_issues.append('SPI_ACQUISITION_FAILED')

    gate_accounting = build_gate_accounting(
        report, args.fail_on, args.gate_exclude, args.fail_on_coverage
    )
    triggered_rules = list(gate_accounting['matching_rules'])
    excluded_triggered_rules = list(gate_accounting['excluded_rules'])
    match_details = list(gate_accounting['matching_findings'])
    excluded_match_details = list(gate_accounting['excluded_findings'])
    policy_exit_code = 2 if triggered_rules else 0
    if runtime_issues:
        final_exit_code = 1
        execution_classification = 'TOOL_ERROR'
        execution_status = 'FAILED'
    elif policy_exit_code == 2:
        final_exit_code = 2
        execution_classification = 'POLICY_TRIGGERED'
        execution_status = 'COMPLETED'
    else:
        final_exit_code = 0
        execution_classification = 'SUCCESS'
        execution_status = 'COMPLETED'

    report.execution = {
        'status': execution_status,
        'classification': execution_classification,
        'policy_triggered': policy_exit_code == 2,
        'exit_code': final_exit_code,
        'fail_on': args.fail_on,
        'gate_exclusions': list(args.gate_exclude),
        'fail_on_coverage': bool(args.fail_on_coverage),
        'gate_semantics': {
            'leaf_findings_only': True,
            'aggregates_can_trigger': False,
            'coverage_gaps_in_severity_gate': bool(args.fail_on_coverage),
        },
        'matching_rules': triggered_rules,
        'matching_findings': match_details,
        'excluded_matching_rules': excluded_triggered_rules,
        'excluded_matching_findings': excluded_match_details,
        'gate_accounting': gate_accounting,
        'runtime_issues': runtime_issues,
        'secure_boot_public_key': args.secure_boot_public_key,
        'max_boot_signature_age_days': args.max_boot_signature_age_days,
        'secure_boot_validation': secure_boot_validation.get('overall'),
        'secure_boot_policy_note': (
            'Secure-boot-required may produce HIGH coverage gaps, but severity-based gates exclude them by default. '
            'Use --fail-on-coverage or --fail-on COVERAGE_GAP to gate evidence completeness.'
        ),
        'gate_exclusion_note': (
            'Gate exclusions affect process gating only. Excluded findings remain in the report, '
            'summary counts, evidence package, and remediation model.'
        ),
    }

    secure_boot_policy_rollup = build_secure_boot_policy_rollup(
        report, args.policy_profile, report.raw_artifacts.get('secure_boot_evidence', {})
    )
    report.raw_artifacts['secure_boot_policy_rollup'] = secure_boot_policy_rollup

    # Calculate summary before evidence collection so README.txt can include trust context.
    report.calculate_summary()

    # Build and package all collected evidence.
    evidence_builder.collect(
        report=report,
        boot_path=boot_path,
        config_detail=config_detail,
        baseline_path=args.baseline or args.create_baseline,
        spi_result=spi_result,
    )
    package_info = evidence_builder.finalise(report, str(package_path))
    report.raw_artifacts['evidence_package'].update(package_info)

    standalone_json_paths: List[Path] = []
    if legacy_json_output:
        standalone_json_paths.append(legacy_json_output)
    if args.json_output:
        standalone_json_paths.append(Path(args.json_output).expanduser().resolve())
    for json_path in standalone_json_paths:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(report.to_json() + '\n', encoding='utf-8')

    print(f'\n[+] Unified analysis complete. Found {len(report.findings)} findings.')
    print(f"[+] Evidence directory: {package_info['scan_directory']}")
    print(f"[+] GGCap package: {package_info['package_path']}")
    print(f"[+] GGCap SHA-256: {package_info['package_sha256']}")
    for json_path in standalone_json_paths:
        print(f'[+] Standalone JSON: {json_path}')

    baseline_assessment = report.raw_artifacts.get('baseline_assessment', {})
    baseline_status = baseline_assessment.get('status', 'NOT_REQUESTED')
    if baseline_status != 'NOT_REQUESTED':
        print(
            f"[+] Baseline result: {baseline_status} "
            f"(matched={baseline_assessment.get('file_match_count', 0)}, "
            f"drift={baseline_assessment.get('file_mismatch_count', 0)}, "
            f"chain_match={baseline_assessment.get('resolved_chain_match')})"
        )

    policy_rollup = report.raw_artifacts.get('secure_boot_policy_rollup', {})
    print_secure_boot_policy_rollup(policy_rollup, args.policy_profile)

    print_scan_summary(report)

    if not args.summary_only:
        severity_rank = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        minimum = severity_rank[args.min_severity]
        print('\n' + '-' * 68)
        print(f'  DETAILED FINDINGS (minimum severity: {args.min_severity})')
        print('-' * 68)
        for domain in ('BOOT_AND_EEPROM', 'PLATFORM_HARDWARE', 'OS_RUNTIME', 'EVIDENCE_COVERAGE'):
            visible = sort_findings_for_display([
                finding for finding in report.findings
                if finding.domain == domain and severity_rank.get(finding.severity, 0) >= minimum
            ])
            if not visible:
                continue
            print(f'\n  [{domain}]')
            for finding in visible:
                flags = []
                if finding.coverage_gap:
                    flags.append('COVERAGE_GAP')
                if finding.applicability in {'NOT_REQUIRED', 'NOT_APPLICABLE'}:
                    flags.append(finding.applicability)
                flag_text = f" [{'|'.join(flags)}]" if flags else ''
                print(
                    f'  [{finding.severity}] {finding.rule_id}: {finding.description}'
                    f' (status={finding.status}, confidence={finding.confidence}){flag_text}'
                )
                if finding.actionable or finding.coverage_gap:
                    print(f'    Observed: {terminal_excerpt(finding.observed)}')
                if finding.severity in {'CRITICAL', 'HIGH'} and finding.expected:
                    print(f'    Expected: {terminal_excerpt(finding.expected)}')
                if finding.severity in {'CRITICAL', 'HIGH'} and finding.rationale:
                    print(f'    Rationale: {terminal_excerpt(finding.rationale)}')
                if finding.evidence_required:
                    print('    Evidence acquisition required: yes')
                if finding.aggregate:
                    print('    Aggregate finding: yes')
                if finding.blocked_by:
                    print(f"    Blocked by: {', '.join(finding.blocked_by)}")
                if finding.remediation_group:
                    print(f'    Remediation group: {finding.remediation_group}')
                if finding.evidence_items:
                    sources = ', '.join(sorted({
                        f'{item.source_type}/{item.trust_level}' for item in finding.evidence_items
                    }))
                    print(f'    Evidence source: {sources}')

    if args.show_passed:
        print_positive_checks(report)
    if args.show_trust_model:
        print_trust_model(report)
    if args.show_otp or args.otp_only:
        print_otp_summary(report)
    if args.secure_boot_evidence or args.otp_only:
        print_secure_boot_matrix(report)

    print_remediation_summary(report)
    print_gate_accounting(
        args.fail_on, policy_exit_code, gate_accounting, list(args.gate_exclude)
    )
    if runtime_issues:
        print(f"[-] Runtime issues: {', '.join(runtime_issues)}")
    print(f'[*] Process exit classification: {execution_classification}')
    print(f'[*] Process exit code: {final_exit_code}')
    return final_exit_code
