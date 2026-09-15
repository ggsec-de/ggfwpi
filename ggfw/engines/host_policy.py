"""Extracted GGFW component: engines.host_policy."""
from ggfw._compat import (
    Any, CRYPT_AVAILABLE, Dict, LIBCRYPT_AVAILABLE, List, Optional, PASSLIB_AVAILABLE, Path,
    Set, Tuple, glob, grp, logger, os, pwd, re, shlex, shutil, subprocess, urlparse,
)
from ggfw.cache import CacheManager
from ggfw.models.evidence import EvidenceRecord
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport
from ggfw.engines.firewall import inspect_firewalls
from ggfw.system.passwords import BUILTIN_WEAK_PASSWORDS, load_weak_password_dictionary, verify_password_against_hash

def read_os_release() -> Dict[str, str]:
    """Read /etc/os-release without executing shell content."""
    result: Dict[str, str] = {}
    try:
        for line in Path('/etc/os-release').read_text(encoding='utf-8', errors='replace').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            result[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return result

def assess_ssh_password_exposure() -> Dict[str, Any]:
    """Best-effort assessment of wildcard SSH plus effective password authentication."""
    assessment: Dict[str, Any] = {
        'wildcard_listener': False,
        'password_authentication': None,
        'kbd_interactive_authentication': None,
        'effective_config_source': None,
        'confirmed_remote_password_exposure': False,
    }
    try:
        result = subprocess.run(['ss', '-H', '-ltn'], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local_addr = parts[3]
            if local_addr.rsplit(':', 1)[-1] == '22' and (
                local_addr.startswith('0.0.0.0:')
                or local_addr.startswith('[::]:')
                or local_addr.startswith('*:')
            ):
                assessment['wildcard_listener'] = True
                break
    except OSError:
        pass

    sshd = shutil.which('sshd')
    if sshd:
        try:
            result = subprocess.run([sshd, '-T'], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                assessment['effective_config_source'] = 'sshd -T'
                for line in result.stdout.splitlines():
                    key, _, value = line.strip().partition(' ')
                    if key == 'passwordauthentication':
                        assessment['password_authentication'] = value.lower() == 'yes'
                    elif key == 'kbdinteractiveauthentication':
                        assessment['kbd_interactive_authentication'] = value.lower() == 'yes'
        except OSError:
            pass

    assessment['confirmed_remote_password_exposure'] = bool(
        assessment['wildcard_listener']
        and (
            assessment['password_authentication'] is True
            or assessment['kbd_interactive_authentication'] is True
        )
    )
    return assessment

_SHELL_EXECUTABLES = {'sh', 'bash', 'dash', 'zsh', 'ash', 'ksh'}

def _shell_name(command: str) -> Optional[str]:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not parts:
        return None
    name = os.path.basename(parts[0]).lower()
    return name if name in _SHELL_EXECUTABLES else None

def detect_dual_use_shell_exec(executable: str, argv: List[str]) -> Optional[Dict[str, str]]:
    """Recognise explicit shell execution using utility-specific argv semantics."""
    utility = os.path.basename(executable).lower()
    args = list(argv[1:] if argv and os.path.basename(argv[0]).lower() == utility else argv)

    if utility in {'nc', 'netcat', 'ncat'}:
        index = 0
        while index < len(args):
            argument = args[index]
            lowered = argument.lower()
            command: Optional[str] = None
            mechanism: Optional[str] = None
            if lowered in {'-e', '--exec'} and index + 1 < len(args):
                command = args[index + 1]
                mechanism = lowered
                index += 1
            elif lowered.startswith('--exec='):
                command = argument.split('=', 1)[1]
                mechanism = '--exec'
            elif lowered.startswith('-e') and len(argument) > 2:
                command = argument[2:]
                mechanism = '-e'
            elif lowered in {'-c', '--sh-exec'} and index + 1 < len(args):
                if args[index + 1]:
                    return {'utility': utility, 'mechanism': lowered, 'shell': '/bin/sh'}
                index += 1
            elif lowered.startswith('--sh-exec=') and argument.split('=', 1)[1]:
                return {'utility': utility, 'mechanism': '--sh-exec', 'shell': '/bin/sh'}

            if command is not None:
                shell = _shell_name(command)
                if shell:
                    return {'utility': utility, 'mechanism': mechanism or 'exec', 'shell': shell}
            index += 1
        return None

    if utility == 'socat':
        for argument in args:
            prefix, separator, remainder = argument.partition(':')
            if not separator or prefix.lower() not in {'exec', 'system'}:
                continue
            command = remainder.split(',', 1)[0]
            if not command:
                continue
            if prefix.lower() == 'system':
                return {'utility': utility, 'mechanism': 'SYSTEM', 'shell': '/bin/sh'}
            shell = _shell_name(command)
            if shell:
                return {'utility': utility, 'mechanism': 'EXEC', 'shell': shell}
    return None

def _wildcard_listener_pids(inventory: List[Dict[str, Any]]) -> Set[int]:
    pids: Set[int] = set()
    for listener in inventory:
        if not listener.get('wildcard'):
            continue
        match = re.search(r'\bpid=(\d+)\b', str(listener.get('process', '')))
        if match:
            pids.add(int(match.group(1)))
    return pids

class FATPolicyEngine:
    def __init__(
        self,
        config: Dict,
        cmdline: Dict,
        report: GGFWReport,
        boot_dir: str = "",
        weak_passwords: Optional[Tuple[str, ...]] = None,
        weak_password_metadata: Optional[Dict[str, Any]] = None,
    ):
        self.config = config
        self.cmdline = cmdline
        self.report = report
        self.boot_dir = boot_dir
        self.cache = CacheManager()
        self.weak_passwords = (
            tuple(BUILTIN_WEAK_PASSWORDS) if weak_passwords is None else tuple(weak_passwords)
        )
        self.weak_password_metadata = dict(
            weak_password_metadata
            if weak_password_metadata is not None
            else load_weak_password_dictionary(None)[1]
        )

        self.all_config_values = {}
        for section, values in config.items():
            self.all_config_values.update(values)

    def run_all_checks(self):
        self.check_debug_interfaces()
        self.check_usb_boot_gadget()
        self.check_kernel_mitigations()
        self.check_boot_chain_integrity()
        self.check_ssh_authorized_keys()
        self.check_network_services()
        self.check_default_credentials()
        self.check_apt_sources()
        self.check_critical_file_permissions()
        self.check_suspicious_processes()
        self.check_firewall()

    def check_debug_interfaces(self):
        if self.all_config_values.get('enable_jtag_gpio') == '1':
            self.report.add_finding(Finding(
                rule_id="RPI-DEBUG-001", severity="HIGH", category="DEBUG",
                description="JTAG interface is explicitly enabled.",
                evidence="enable_jtag_gpio=1",
                remediation="Remove 'enable_jtag_gpio=1' from config.txt"
            ))

        if self.all_config_values.get('uart_2ndstage') == '1':
             self.report.add_finding(Finding(
                rule_id="RPI-DEBUG-002", severity="MEDIUM", category="DEBUG",
                description="UART debug output enabled.",
                evidence="uart_2ndstage=1",
                remediation="Disable UART debug output for production environments."
            ))

    def check_usb_boot_gadget(self):
        overlays = self.all_config_values.get('dtoverlay', '')
        if 'dwc2' in overlays:
            self.report.add_finding(Finding(
                rule_id="RPI-BOOT-005", severity="CRITICAL", category="BOOT",
                description="USB Gadget mode (dwc2) is enabled.",
                evidence=f"dtoverlay={overlays}",
                remediation="Remove dwc2 overlay unless strictly required.",
                cve_references=["CVE-2014-4699", "CVE-2020-13800"]
            ))

        if self.all_config_values.get('program_usb_boot_mode') == '1':
            timeout = self.all_config_values.get('program_usb_boot_timeout')
            if not timeout:
                self.report.add_finding(Finding(
                    rule_id="RPI-BOOT-006", severity="HIGH", category="BOOT",
                    description="USB Boot mode enabled without timeout.",
                    evidence="program_usb_boot_mode=1",
                    remediation="Set program_usb_boot_timeout"
                ))

    def check_kernel_mitigations(self):
        if 'mitigations' in self.cmdline and self.cmdline['mitigations'] == 'off':
            self.report.add_finding(Finding(
                rule_id="RPI-KERNEL-001", severity="HIGH", category="KERNEL",
                description="CPU mitigations explicitly disabled.",
                evidence="cmdline: mitigations=off",
                remediation="Remove 'mitigations=off' from cmdline.txt.",
                cve_references=["CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754"]
            ))

        if self.cmdline.get('iomem') == 'relaxed':
            self.report.add_finding(Finding(
                rule_id="RPI-KERNEL-002", severity="CRITICAL", category="KERNEL",
                description="Strict /dev/mem is disabled.",
                evidence="cmdline: iomem=relaxed",
                remediation="Remove 'iomem=relaxed' to prevent MMIO exploits.",
                cve_references=["CVE-2019-17666"]
            ))

    def check_boot_chain_integrity(self):
        if 'armstub' in self.all_config_values:
            self.report.add_finding(Finding(
                rule_id="RPI-EL3-001", severity="MEDIUM", category="INTEGRITY",
                description="Custom ARM Trusted Firmware loaded.",
                evidence=f"armstub={self.all_config_values['armstub']}",
                remediation="Verify signature of armstub binary."
            ))

    def check_ssh_authorized_keys(self):
        ssh_dirs = [
            '/root/.ssh/authorized_keys',
            '/home/*/.ssh/authorized_keys'
        ]

        suspicious_keys = []
        weak_keys = []

        for pattern in ssh_dirs:
            for filepath in glob.glob(pattern):
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            keys = f.readlines()
                            for i, key in enumerate(keys):
                                key = key.strip()
                                if key and not key.startswith('#'):
                                    parts = key.split()
                                    if len(parts) >= 3:
                                        key_type = parts[0]
                                        comment = parts[2] if len(parts) > 2 else ""

                                        if key_type in ['ssh-dss', 'ssh-rsa']:
                                            weak_keys.append({
                                                'file': filepath,
                                                'line': i + 1,
                                                'type': key_type
                                            })

                                        suspicious_keywords = ['temp', 'test', 'debug', 'admin', 'root', 'backdoor']
                                        if any(kw in comment.lower() for kw in suspicious_keywords):
                                            suspicious_keys.append({
                                                'file': filepath,
                                                'line': i + 1,
                                                'comment': comment
                                            })
                    except PermissionError:
                        pass

        if suspicious_keys:
            evidence = "; ".join([f"{k['file']}:{k['line']} ({k['comment']})" for k in suspicious_keys])
            self.report.add_finding(Finding(
                rule_id="RPI-SSH-001", severity="HIGH", category="ACCESS",
                description="Suspicious SSH authorized keys detected.",
                evidence=evidence,
                remediation="Review and remove unauthorized SSH keys."
            ))

        if weak_keys:
            evidence = "; ".join([f"{k['file']}:{k['line']} ({k['type']})" for k in weak_keys])
            self.report.add_finding(Finding(
                rule_id="RPI-SSH-004", severity="MEDIUM", category="ACCESS",
                description="Weak SSH key types detected.",
                evidence=evidence,
                remediation="Replace weak keys with ed25519 or strong RSA.",
                cve_references=["CVE-2017-15906"]
            ))

        ssh_service = subprocess.run(
            ['systemctl', 'is-active', 'ssh'],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if ssh_service == 'active':
            sshd_config = '/etc/ssh/sshd_config'
            if os.path.exists(sshd_config):
                try:
                    with open(sshd_config, 'r') as f:
                        content = f.read()
                        if re.search(r'^PermitRootLogin\s+(yes|without-password)', content, re.MULTILINE):
                            self.report.add_finding(Finding(
                                rule_id="RPI-SSH-002", severity="HIGH", category="ACCESS",
                                description="SSH root login is enabled.",
                                evidence="PermitRootLogin yes in sshd_config",
                                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
                            ))
                        if re.search(r'^PasswordAuthentication\s+yes', content, re.MULTILINE):
                            self.report.add_finding(Finding(
                                rule_id="RPI-SSH-003", severity="MEDIUM", category="ACCESS",
                                description="SSH password authentication is enabled.",
                                evidence="PasswordAuthentication yes in sshd_config",
                                remediation="Consider using SSH key-only authentication."
                            ))
                except PermissionError:
                    pass

    def check_network_services(self):
        """Classify listening sockets without treating a port number as proof of malware."""
        try:
            result = subprocess.run(
                ['ss', '-H', '-tlnp'], capture_output=True, text=True, check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return

        high_risk_ports = {'21': 'FTP', '23': 'Telnet'}
        remote_admin_ports = {'3389': 'RDP', '5900': 'VNC'}
        high_risk = []
        remote_admin = []
        all_interfaces = []
        listener_inventory: List[Dict[str, Any]] = []

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue

            local_addr = parts[3]
            port = local_addr.rsplit(':', 1)[-1]
            process_info = ' '.join(parts[5:]) if len(parts) > 5 else 'process unknown'
            wildcard = (
                local_addr.startswith('0.0.0.0:')
                or local_addr.startswith('[::]:')
                or local_addr.startswith('*:')
            )
            listener_inventory.append({
                'raw': line,
                'local_address': local_addr,
                'port': port,
                'process': process_info,
                'wildcard': wildcard,
            })

            if port in high_risk_ports:
                high_risk.append(f"{high_risk_ports[port]} port {port} ({process_info})")
            elif port in remote_admin_ports:
                remote_admin.append(f"{remote_admin_ports[port]} port {port} ({process_info})")

            if wildcard:
                all_interfaces.append(f"{port} ({process_info})")

        self.report.raw_artifacts['network_listeners'] = listener_inventory

        if high_risk:
            self.report.add_finding(Finding(
                rule_id="RPI-NET-001", severity="HIGH", category="NETWORK",
                description="Clear-text legacy network services are listening.",
                evidence="; ".join(sorted(set(high_risk))),
                remediation="Disable the service or replace it with an authenticated encrypted protocol."
            ))

        if remote_admin:
            self.report.add_finding(Finding(
                rule_id="RPI-NET-003", severity="MEDIUM", category="NETWORK",
                description="Remote administration services are listening.",
                evidence="; ".join(sorted(set(remote_admin))),
                remediation="Confirm that exposure is intended and restricted by authentication and firewall policy."
            ))

        if all_interfaces:
            self.report.add_finding(Finding(
                rule_id="RPI-NET-002", severity="INFO", category="NETWORK",
                description="Services are listening on wildcard addresses.",
                evidence="Listeners on all interfaces: " + "; ".join(sorted(set(all_interfaces))),
                remediation="Review whether each service must be reachable through every network interface."
            ))

    def check_default_credentials(self):
        """Audit local interactive accounts, privilege groups and weak passwords."""
        if pwd is None or grp is None:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-000', severity='INFO', category='ACCESS',
                description='Local POSIX account APIs are unavailable.',
                evidence='Python grp/pwd modules are unavailable on this platform.',
                remediation='Run GGFW on the target Linux system to audit local accounts.',
                coverage_gap=True,
            ))
            return
        non_login_shells = {
            '/usr/sbin/nologin', '/sbin/nologin', '/bin/false',
            '/usr/bin/false', '/bin/sync',
        }
        privilege_groups = ('sudo', 'wheel', 'adm', 'gpio', 'spi', 'dialout')

        try:
            passwd_entries = list(pwd.getpwall())
        except OSError as exc:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-000', severity='INFO', category='ACCESS',
                description='Local account database could not be read.',
                evidence=str(exc),
                remediation='Review /etc/passwd and NSS configuration manually.',
            ))
            return

        group_members: Dict[str, Set[str]] = {}
        for group_name in privilege_groups:
            try:
                entry = grp.getgrnam(group_name)
                members = set(entry.gr_mem)
                for account in passwd_entries:
                    if account.pw_gid == entry.gr_gid:
                        members.add(account.pw_name)
                group_members[group_name] = members
            except KeyError:
                group_members[group_name] = set()

        shadow_hashes: Dict[str, str] = {}
        try:
            with open('/etc/shadow', 'r', encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    fields = line.rstrip('\n').split(':')
                    if len(fields) >= 2:
                        shadow_hashes[fields[0]] = fields[1]
        except PermissionError:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-000', severity='INFO', category='ACCESS',
                description='Password-hash audit was skipped because /etc/shadow is unreadable.',
                evidence='Permission denied while reading /etc/shadow',
                remediation='Run GGFW as root to enable local password-hash checks.',
            ))
        except OSError as exc:
            logger.debug('Unable to read /etc/shadow: %s', exc)

        account_inventory: List[Dict[str, Any]] = []
        extra_uid_zero: List[str] = []
        empty_passwords: List[str] = []
        weak_password_matches: Dict[str, str] = {}

        for account in passwd_entries:
            interactive = bool(account.pw_shell) and account.pw_shell not in non_login_shells
            groups = sorted(
                name for name, members in group_members.items()
                if account.pw_name in members
            )
            password_hash = shadow_hashes.get(account.pw_name)
            locked = password_hash is None or password_hash.startswith(('!', '*'))
            algorithm = 'unknown'
            if password_hash:
                if password_hash.startswith('$y$'):
                    algorithm = 'yescrypt'
                elif password_hash.startswith('$6$'):
                    algorithm = 'sha512-crypt'
                elif password_hash.startswith('$5$'):
                    algorithm = 'sha256-crypt'
                elif password_hash.startswith('$1$'):
                    algorithm = 'md5-crypt'
                elif password_hash == '':
                    algorithm = 'empty'

            account_inventory.append({
                'username': account.pw_name,
                'uid': account.pw_uid,
                'gid': account.pw_gid,
                'shell': account.pw_shell,
                'interactive': interactive,
                'privilege_groups': groups,
                'password_locked_or_unavailable': locked,
                'password_hash_algorithm': algorithm,
            })

            if account.pw_uid == 0 and account.pw_name != 'root':
                extra_uid_zero.append(account.pw_name)

            if password_hash == '':
                empty_passwords.append(account.pw_name)
                continue

            should_test = (
                bool(password_hash)
                and not locked
                and interactive
                and (
                    account.pw_uid == 0
                    or account.pw_uid >= 1000
                    or account.pw_name == 'pi'
                    or bool({'sudo', 'wheel'} & set(groups))
                )
            )
            if should_test and (PASSLIB_AVAILABLE or CRYPT_AVAILABLE or LIBCRYPT_AVAILABLE):
                for candidate in self.weak_passwords:
                    if verify_password_against_hash(candidate, password_hash):
                        weak_password_matches[account.pw_name] = candidate
                        break

        os_release = read_os_release()
        ssh_exposure = assess_ssh_password_exposure()
        vendor_default_profiles: Dict[str, str] = {}
        if os_release.get('ID', '').lower() == 'kali' and weak_password_matches.get('kali') == 'kali':
            vendor_default_profiles['kali'] = 'KALI_PRECREATED_IMAGE_DEFAULT'
        if weak_password_matches.get('pi') == 'raspberry':
            vendor_default_profiles['pi'] = 'LEGACY_RASPBERRY_PI_OS_DEFAULT'

        self.report.raw_artifacts['local_accounts'] = {
            'accounts': account_inventory,
            'privileged_groups': {
                name: sorted(members) for name, members in group_members.items()
            },
            'weak_password_dictionary_size': len(self.weak_passwords),
            'weak_password_dictionary': dict(self.weak_password_metadata),
            'password_verification_available': PASSLIB_AVAILABLE or CRYPT_AVAILABLE or LIBCRYPT_AVAILABLE,
            'weak_password_accounts': sorted(weak_password_matches),
            'vendor_default_profiles': vendor_default_profiles,
            'os_release': os_release,
            'ssh_password_exposure': ssh_exposure,
        }

        if extra_uid_zero:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-004', severity='CRITICAL', category='ACCESS',
                description='Additional UID 0 accounts were detected.',
                evidence=', '.join(sorted(extra_uid_zero)),
                remediation='Remove unintended UID 0 accounts and use sudo for delegated administration.',
            ))

        if empty_passwords:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-001', severity='CRITICAL', category='ACCESS',
                description='Interactive or local accounts have empty password hashes.',
                evidence=', '.join(sorted(empty_passwords)),
                remediation='Set strong passwords, lock the accounts, or remove unused accounts.',
            ))

        if weak_password_matches:
            accounts = sorted(weak_password_matches)
            privileged_accounts = sorted(
                account for account in accounts
                if any(
                    item['username'] == account
                    and (item['uid'] == 0 or bool({'sudo', 'wheel'} & set(item['privilege_groups'])))
                    for item in account_inventory
                )
            )
            vendor_accounts = sorted(vendor_default_profiles)
            remote_exposure = bool(ssh_exposure.get('confirmed_remote_password_exposure'))

            severity = 'CRITICAL' if privileged_accounts else 'HIGH'
            status = 'DETECTED'
            finding_class = 'CREDENTIAL_WEAKNESS'
            rationale_parts = []
            if vendor_accounts:
                status = 'VENDOR_DEFAULT_CREDENTIAL'
                finding_class = 'VENDOR_DEFAULT_CREDENTIAL'
                rationale_parts.append(
                    'The matched credential corresponds to a documented pre-created image default.'
                )
                # Keep a confirmed remotely reachable default credential CRITICAL.
                # Otherwise default-profile severity is HIGH so OS image hygiene
                # does not obscure boot-chain findings in the top-line summary.
                if not remote_exposure and self.report.policy_profile == 'default':
                    severity = 'HIGH'
            if remote_exposure:
                rationale_parts.append('Wildcard SSH with effective password authentication is enabled.')

            observed_parts = [f"accounts={','.join(accounts)}"]
            if vendor_accounts:
                observed_parts.append(
                    'vendor_profiles=' + ','.join(
                        f'{account}:{vendor_default_profiles[account]}' for account in vendor_accounts
                    )
                )
            observed_parts.append(f'remote_password_exposure={str(remote_exposure).lower()}')

            self.report.add_finding(Finding(
                rule_id='RPI-CRED-003', severity=severity, category='ACCESS',
                description='Common weak or default passwords were detected.',
                evidence='; '.join(observed_parts),
                remediation='Replace weak credentials and prefer key-based administrative access.',
                status=status,
                finding_class=finding_class,
                expected='No active interactive account matches the configured weak/default credential dictionary',
                observed='; '.join(observed_parts),
                rationale=' '.join(rationale_parts),
                evidence_items=[EvidenceRecord(
                    source_type='OS_OBSERVED',
                    source_path='/etc/shadow,/etc/passwd,/etc/group',
                    acquisition_method='offline hash verification plus account privilege inventory',
                    trust_level='MEDIUM',
                    raw='; '.join(observed_parts),
                    normalized={
                        'accounts': accounts,
                        'privileged_accounts': privileged_accounts,
                        'vendor_default_profiles': vendor_default_profiles,
                        'ssh_password_exposure': ssh_exposure,
                    },
                )],
            ))

        try:
            pi_account = pwd.getpwnam('pi')
        except KeyError:
            pi_account = None
        if pi_account:
            pi_interactive = pi_account.pw_shell not in non_login_shells
            pi_admin = bool({'sudo', 'wheel'} & {
                name for name, members in group_members.items() if 'pi' in members
            })
            if pi_interactive and pi_admin:
                self.report.add_finding(Finding(
                    rule_id='RPI-CRED-005', severity='MEDIUM', category='ACCESS',
                    description="The conventional 'pi' account remains interactive and administrative.",
                    evidence=f"shell={pi_account.pw_shell}; sudo_or_wheel={pi_admin}",
                    remediation="Rename, disable or de-privilege the 'pi' account when it is not operationally required.",
                ))
            else:
                self.report.add_finding(Finding(
                    rule_id='RPI-CRED-006', severity='INFO', category='ACCESS',
                    description="The conventional 'pi' account exists.",
                    evidence=f"shell={pi_account.pw_shell}; sudo_or_wheel={pi_admin}",
                    remediation="Confirm that the account is required and appropriately restricted.",
                ))

    def check_apt_sources(self):
        """Audit one-line and deb822 APT sources with apt-secure-aware severity."""
        source_files = (
            ['/etc/apt/sources.list']
            + glob.glob('/etc/apt/sources.list.d/*.list')
            + glob.glob('/etc/apt/sources.list.d/*.sources')
        )

        http_repos = []
        trusted_repos = []
        insecure_overrides = []
        unsigned_third_party = []
        unstable_repos = []
        suspicious_repos = []
        source_inventory: List[Dict[str, Any]] = []

        official_domain_suffixes = (
            'kali.org', 'debian.org', 'raspberrypi.com', 'raspberrypi.org',
            'raspbian.org', 'ubuntu.com', 'canonical.com'
        )
        suspicious_keywords = ('malware', 'crack', 'warez')

        def host_is_official(uri: str) -> bool:
            host = (urlparse(uri).hostname or '').lower().rstrip('.')
            return any(host == suffix or host.endswith('.' + suffix)
                       for suffix in official_domain_suffixes)

        def inspect_entry(source_file: str, location: str, uri: str,
                          options: str = '', signed_by: bool = False,
                          suite_text: str = ''):
            lowered = f"{uri} {options} {suite_text}".lower()
            label = f"{source_file}:{location} ({uri})"
            source_inventory.append({
                'source_file': source_file,
                'location': location,
                'uri': uri,
                'options': options,
                'signed_by_declared': signed_by,
                'suite_text': suite_text,
                'official_domain': host_is_official(uri),
            })

            if uri.lower().startswith('http://'):
                http_repos.append(label)
            if re.search(r'(^|[\s,])trusted\s*=\s*yes($|[\s,])', options, re.IGNORECASE):
                trusted_repos.append(label)
            if re.search(
                r'(allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*=\s*yes',
                options,
                re.IGNORECASE,
            ):
                insecure_overrides.append(label)
            if ('unstable' in suite_text.lower() or
                    'experimental' in suite_text.lower()):
                unstable_repos.append(label)
            if any(keyword in lowered for keyword in suspicious_keywords):
                suspicious_repos.append(label)
            if uri and not host_is_official(uri) and not signed_by:
                unsigned_third_party.append(label)

        for source_file in sorted(set(source_files)):
            if not os.path.isfile(source_file):
                continue
            try:
                content = Path(source_file).read_text(encoding='utf-8', errors='replace')
            except PermissionError:
                continue

            if source_file.endswith('.sources'):
                for block_index, block in enumerate(re.split(r'\n\s*\n', content), 1):
                    fields: Dict[str, str] = {}
                    current_key: Optional[str] = None
                    for raw_line in block.splitlines():
                        if not raw_line.strip() or raw_line.lstrip().startswith('#'):
                            continue
                        if raw_line[:1].isspace() and current_key:
                            fields[current_key] += ' ' + raw_line.strip()
                            continue
                        if ':' not in raw_line:
                            continue
                        key, value = raw_line.split(':', 1)
                        current_key = key.strip().lower()
                        fields[current_key] = value.strip()

                    if fields.get('enabled', 'yes').lower() == 'no':
                        continue
                    if 'deb' not in fields.get('types', 'deb').lower().split():
                        continue

                    options = ' '.join(
                        f"{key}={fields[key]}" for key in (
                            'trusted', 'allow-insecure', 'allow-weak',
                            'allow-downgrade-to-insecure'
                        ) if key in fields
                    )
                    signed_by = bool(fields.get('signed-by'))
                    suites = fields.get('suites', '')
                    for uri in fields.get('uris', '').split():
                        inspect_entry(
                            source_file, f"block {block_index}", uri,
                            options=options, signed_by=signed_by,
                            suite_text=suites,
                        )
            else:
                for line_num, raw_line in enumerate(content.splitlines(), 1):
                    line = raw_line.strip()
                    if not line or line.startswith('#') or not re.match(r'^deb(?:-src)?\s', line):
                        continue

                    remainder = re.sub(r'^deb(?:-src)?\s+', '', line, count=1)
                    options = ''
                    if remainder.startswith('['):
                        closing = remainder.find(']')
                        if closing != -1:
                            options = remainder[1:closing]
                            remainder = remainder[closing + 1:].strip()
                    tokens = remainder.split()
                    if not tokens:
                        continue
                    uri = tokens[0]
                    suites = ' '.join(tokens[1:])
                    signed_by = bool(re.search(r'(^|\s)signed-by\s*=', options, re.IGNORECASE))
                    inspect_entry(
                        source_file, str(line_num), uri,
                        options=options, signed_by=signed_by,
                        suite_text=suites,
                    )

        self.report.raw_artifacts['apt_sources'] = source_inventory

        if insecure_overrides:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-004", severity="CRITICAL", category="INTEGRITY",
                description="APT signature-security overrides are enabled.",
                evidence="; ".join(sorted(set(insecure_overrides))),
                remediation="Remove allow-insecure, allow-weak and downgrade-to-insecure overrides."
            ))

        if trusted_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-005", severity="HIGH", category="INTEGRITY",
                description="APT repositories bypass normal authentication with trusted=yes.",
                evidence="; ".join(sorted(set(trusted_repos))),
                remediation="Remove trusted=yes and configure a repository-specific signing key."
            ))

        if unsigned_third_party:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-006", severity="MEDIUM", category="INTEGRITY",
                description="Third-party APT repositories do not declare a repository-specific Signed-By key.",
                evidence="; ".join(sorted(set(unsigned_third_party))),
                remediation="Configure Signed-By with a dedicated keyring for each third-party repository."
            ))

        if http_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-001", severity="INFO", category="INTEGRITY",
                description="APT repositories use unencrypted HTTP transport.",
                evidence="; ".join(sorted(set(http_repos))),
                remediation=(
                    "Prefer HTTPS where available. Package authenticity still depends on "
                    "valid apt-secure Release/InRelease signatures."
                )
            ))

        if suspicious_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-003", severity="CRITICAL", category="INTEGRITY",
                description="Repository URI contains a strongly suspicious keyword.",
                evidence="; ".join(sorted(set(suspicious_repos))),
                remediation="Validate repository ownership and remove unauthorized sources."
            ))

        if unstable_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-002", severity="MEDIUM", category="INTEGRITY",
                description="Unstable or experimental APT suites are enabled.",
                evidence="; ".join(sorted(set(unstable_repos))),
                remediation="Confirm that unstable repositories are intentional for this device role."
            ))

    def check_critical_file_permissions(self):
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/boot/firmware/config.txt'
        ]
        world_writable = []
        shadow_groups = {0}
        if grp is not None:
            try:
                shadow_groups.add(grp.getgrnam('shadow').gr_gid)
            except (KeyError, OSError):
                pass

        for filepath in critical_files:
            if os.path.exists(filepath):
                try:
                    stat = os.stat(filepath)
                    mode = stat.st_mode & 0o777

                    if mode & 0o002:
                        world_writable.append((filepath, mode))

                    # 0640 is an upper bound, not a command to add permissions.
                    # Group read is acceptable only for root/the shadow group.
                    if filepath == '/etc/shadow' and (
                        mode & ~0o640 or stat.st_uid != 0
                        or (mode & 0o040 and stat.st_gid not in shadow_groups)
                    ):
                        self.report.add_finding(Finding(
                            rule_id="RPI-PERM-002", severity="CRITICAL", category="ACCESS",
                            description=f"Shadow file has incorrect permissions.",
                            evidence=f"Permissions: {oct(mode)}; uid={stat.st_uid}; gid={stat.st_gid}",
                            remediation=(
                                "Review ownership and ACLs. To remove excess access without adding permissions: "
                                "chown root /etc/shadow && chmod u-x,go-rwx /etc/shadow"
                            )
                        ))

                    if 'sudoers' in filepath and mode != 0o440:
                        self.report.add_finding(Finding(
                            rule_id="RPI-PERM-003", severity="CRITICAL", category="ACCESS",
                            description=f"Sudoers file has incorrect permissions.",
                            evidence=f"Permissions: {oct(mode)} (expected 440)",
                            remediation=f"Run: chmod 440 {filepath}"
                        ))

                except Exception as e:
                    logger.error(f"Error checking permissions for {filepath}: {e}")

        if world_writable:
            # One rule ID per report, even when several files need repair.
            self.report.add_finding(Finding(
                rule_id='RPI-PERM-001', severity='HIGH', category='ACCESS',
                description='Critical files are world-writable.',
                evidence='; '.join(f'{path}: {oct(mode)}' for path, mode in world_writable),
                remediation='Remove world-write access: ' + '; '.join(
                    f'chmod o-w {path}' for path, _ in world_writable),
            ))

    def check_suspicious_processes(self):
        """Inspect /proc using exact executable names and high-confidence argument patterns."""
        malware_names = {
            'meterpreter', 'metsrv', 'xmrig', 'minerd', 'cpuminer',
            'cryptominer', 'kinsing', 'kdevtmpfsi'
        }
        dual_use_names = {'nc', 'netcat', 'ncat', 'socat'}
        strong_argument_patterns = [
            re.compile(r'(?i)(?:^|[\s/])meterpreter(?:[\s/]|$)'),
            re.compile(r'(?i)stratum\+(?:tcp|ssl)://'),
            re.compile(r'(?i)(?:^|[\s_-])cryptonight(?:[\s_-]|$)'),
        ]

        high_confidence = []
        dual_use = []
        shell_exec_indicators: List[Dict[str, Any]] = []
        wildcard_pids = _wildcard_listener_pids(
            self.report.raw_artifacts.get('network_listeners', [])
        )
        own_pids = {os.getpid(), os.getppid()}

        for proc_dir in glob.glob('/proc/[0-9]*'):
            try:
                pid = int(os.path.basename(proc_dir))
            except ValueError:
                continue
            if pid in own_pids:
                continue

            try:
                comm = Path(proc_dir, 'comm').read_text(
                    encoding='utf-8', errors='replace'
                ).strip()
            except (OSError, PermissionError):
                comm = ''

            try:
                exe_path = os.readlink(os.path.join(proc_dir, 'exe'))
            except OSError:
                exe_path = ''

            try:
                raw_cmdline = Path(proc_dir, 'cmdline').read_bytes()
                argv = [
                    part.decode('utf-8', errors='replace')
                    for part in raw_cmdline.split(b'\x00') if part
                ]
                cmdline = ' '.join(argv)
            except (OSError, PermissionError):
                argv = []
                cmdline = ''

            executable = os.path.basename(exe_path) or comm
            executable_lower = executable.lower()
            cmdline_lower = cmdline.lower()
            evidence = f"pid={pid}; exe={exe_path or executable}; cmdline={cmdline[:500]}"

            if executable_lower in malware_names:
                high_confidence.append(evidence)
                continue

            if any(pattern.search(cmdline) for pattern in strong_argument_patterns):
                high_confidence.append(evidence)
                continue

            if executable_lower in dual_use_names:
                indicator = detect_dual_use_shell_exec(executable_lower, argv)
                if indicator:
                    normalized = {
                        'pid': pid,
                        'executable': exe_path or executable,
                        **indicator,
                        'wildcard_listener': pid in wildcard_pids,
                        'cmdline': cmdline[:500],
                    }
                    shell_exec_indicators.append(normalized)
                else:
                    dual_use.append(evidence)

        if high_confidence:
            self.report.add_finding(Finding(
                rule_id="RPI-PROC-001", severity="HIGH", category="PROCESSES",
                description="High-confidence suspicious process indicators were detected.",
                evidence=(
                    f"Found {len(high_confidence)} process(es):\n"
                    + "\n".join(high_confidence[:10])
                ),
                remediation="Validate executable provenance, parent process and network activity before termination."
            ))

        if dual_use:
            self.report.add_finding(Finding(
                rule_id="RPI-PROC-002", severity="INFO", category="PROCESSES",
                description="Dual-use networking utilities are currently running.",
                evidence=(
                    f"Found {len(dual_use)} process(es):\n"
                    + "\n".join(dual_use[:10])
                ),
                remediation="Confirm that each utility and its command line are expected."
            ))

        if shell_exec_indicators:
            correlated = any(item['wildcard_listener'] for item in shell_exec_indicators)
            severity = 'HIGH' if correlated else 'MEDIUM'
            confidence = 'HIGH' if correlated else 'MEDIUM'
            rendered = [
                (
                    f"pid={item['pid']}; exe={item['executable']}; "
                    f"mechanism={item['utility']}:{item['mechanism']}; "
                    f"shell={item['shell']}; "
                    f"wildcard_listener={str(item['wildcard_listener']).lower()}; "
                    f"cmdline={item['cmdline']}"
                )
                for item in shell_exec_indicators[:10]
            ]
            self.report.raw_artifacts['process_shell_exec_indicators'] = [
                dict(item) for item in shell_exec_indicators
            ]
            self.report.add_finding(Finding(
                rule_id='RPI-PROC-003', severity=severity, category='PROCESSES',
                description='A dual-use networking utility is configured to execute a shell and requires review.',
                evidence=(
                    f"Found {len(shell_exec_indicators)} explicit shell-execution indicator(s):\n"
                    + "\n".join(rendered)
                ),
                remediation=(
                    'Validate executable provenance, parent process and network exposure '
                    'before terminating or permitting the process.'
                ),
                status='REVIEW_REQUIRED',
                confidence=confidence,
                finding_class='HEURISTIC_INDICATOR',
                expected='Dual-use networking tools do not expose an unapproved shell execution path',
                rationale=(
                    'Explicit shell execution is security-sensitive. Wildcard listener correlation '
                    'raises severity, but the indicator is not proof of malware.'
                ),
            ))

    def check_firewall(self):
        observations = inspect_firewalls()
        self.report.raw_artifacts['firewall_assessment'] = observations
        if not any(item['state'] == 'CONFIGURED' for item in observations):
            incomplete = any(item['state'] == 'UNKNOWN' for item in observations)
            self.report.add_finding(Finding(
                rule_id='RPI-FW-001', severity='MEDIUM' if incomplete else 'HIGH', category='NETWORK',
                description=('Firewall configuration could not be fully inspected.' if incomplete
                             else 'No supported firewall filtering configuration detected.'),
                evidence='; '.join(f"{item['tool']}: {item['state']} ({item['detail']})" for item in observations),
                remediation='Review the firewall rules with administrative access; preserve remote management access before enabling filtering.',
                coverage_gap=incomplete,
                finding_class='COVERAGE_GAP' if incomplete else 'SECURITY_FINDING',
                status='EVIDENCE_INCOMPLETE' if incomplete else 'DETECTED',
            ))


HostPolicyEngine = FATPolicyEngine
