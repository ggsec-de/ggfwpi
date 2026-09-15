"""Offline regressions for host-policy advice and per-scan evidence isolation."""
import json
import contextlib
import io
import sys
from datetime import datetime, timezone
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ggfw.engines import host_policy
from ggfw import audit
from ggfw.errors import GGFWRuntimeError
from ggfw.models.report import GGFWReport
from ggfw.packaging.ggcap import EvidencePackageBuilder


class PermissionTests(unittest.TestCase):
    def check_files(self, files):
        report = GGFWReport()
        engine = host_policy.FATPolicyEngine({}, {}, report)
        with patch.object(host_policy.os.path, 'exists', side_effect=lambda p: p in files), \
                patch.object(host_policy.os, 'stat', side_effect=lambda p: files[p]), \
                patch.object(host_policy, 'grp', SimpleNamespace(
                    getgrnam=lambda name: SimpleNamespace(gr_gid=42))):
            engine.check_critical_file_permissions()
        report.calculate_summary()
        return report.findings

    def stat(self, mode, uid=0, gid=0):
        return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)

    def test_restrictive_shadow_modes(self):
        for mode, gid in ((0o600, 0), (0o640, 42), (0o640, 0), (0o400, 0), (0, 0)):
            with self.subTest(mode=oct(mode), gid=gid):
                self.assertEqual(self.check_files({'/etc/shadow': self.stat(mode, gid=gid)}), [])

    def test_unsafe_shadow_and_non_widening_advice(self):
        for mode in (0o602, 0o642, 0o666, 0o604, 0o660, 0o700):
            with self.subTest(mode=oct(mode)):
                findings = self.check_files({'/etc/shadow': self.stat(mode)})
                self.assertIn('RPI-PERM-002', [f.rule_id for f in findings])
                advice = ' '.join(f.remediation for f in findings)
                self.assertNotIn('chmod 644', advice)
                self.assertNotIn('chmod 640', advice)

    def test_shadow_owner_and_group(self):
        for mode, uid, gid in ((0o600, 1000, 0), (0o640, 0, 1000)):
            with self.subTest(uid=uid, gid=gid):
                self.assertIn('RPI-PERM-002', [f.rule_id for f in self.check_files(
                    {'/etc/shadow': self.stat(mode, uid, gid)})])

    def test_world_writable_files_have_unique_rule_ids_and_safe_advice(self):
        findings = self.check_files({p: self.stat(0o666) for p in (
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config')})
        self.assertEqual(len({f.rule_id for f in findings}), len(findings))
        general = next(f for f in findings if f.rule_id == 'RPI-PERM-001')
        self.assertIn('chmod o-w /etc/shadow', general.remediation)
        self.assertNotIn('chmod 644', general.remediation)

    def test_sudoers_policy_and_regular_files(self):
        self.assertEqual(self.check_files({'/etc/sudoers': self.stat(0o440),
                                          '/etc/passwd': self.stat(0o644)}), [])
        self.assertIn('RPI-PERM-003', [f.rule_id for f in self.check_files(
            {'/etc/sudoers': self.stat(0o666)})])


class FirewallTests(unittest.TestCase):
    EMPTY_IPTABLES = '-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n'

    def check(self, outputs=None, failures=None):
        outputs = outputs or {}
        failures = failures or {}
        report = GGFWReport()

        def run(cmd, **kwargs):
            if cmd[0] in failures:
                raise failures[cmd[0]]
            defaults = {'ufw': ('Status: inactive\n', 0),
                        'nft': ('{"nftables": []}', 0),
                        'iptables': (self.EMPTY_IPTABLES, 0),
                        'ip6tables': (self.EMPTY_IPTABLES, 0)}
            stdout, returncode = outputs.get(cmd[0], defaults[cmd[0]])
            return SimpleNamespace(stdout=stdout, stderr='', returncode=returncode)

        with patch.object(host_policy.subprocess, 'run', side_effect=run) as command:
            host_policy.FATPolicyEngine({}, {}, report).check_firewall()
        report.calculate_summary()
        return report, command

    def test_inactive_ufw_and_empty_accept_chains(self):
        report, _ = self.check({'ufw': ('Status: inactive\n', 0),
                                'iptables': (self.EMPTY_IPTABLES, 0)})
        self.assertIn('RPI-FW-001', [f.rule_id for f in report.findings])
        self.assertFalse(report.findings[0].coverage_gap)

    def test_active_ufw_requires_exact_successful_status(self):
        report, _ = self.check({'ufw': (' Status: active\r\n', 0)})
        self.assertEqual(report.findings, [])
        for text, rc in (('Status: active', 1), ('Not active', 0), ('Status: inactive', 0)):
            with self.subTest(text=text, rc=rc):
                report, _ = self.check({'ufw': (text, rc)})
                self.assertTrue(report.findings)

    def test_accept_log_comment_and_detached_chain_do_not_count(self):
        for extra in ('-A INPUT -j ACCEPT', '-A INPUT -j LOG',
                      '-A INPUT -m comment --comment "-j DROP" -j ACCEPT',
                      '-N unused\n-A unused -j DROP'):
            with self.subTest(extra=extra):
                report, _ = self.check({'iptables': (self.EMPTY_IPTABLES + extra, 0)})
                self.assertTrue(report.findings)

    def test_drop_policy_and_reachable_reject(self):
        for text in ('-P INPUT DROP\n', self.EMPTY_IPTABLES + '-A INPUT -j REJECT',
                     self.EMPTY_IPTABLES + '-N guard\n-A INPUT -j guard\n-A guard -j DROP'):
            with self.subTest(text=text):
                report, _ = self.check({'iptables': (text, 0)})
                self.assertEqual(report.findings, [])

    def test_ipv6_filtering_is_observed(self):
        report, _ = self.check({'ip6tables': ('-P INPUT DROP\n', 0)})
        self.assertEqual(report.findings, [])

    def test_nft_empty_table_and_nat_do_not_count(self):
        entries = [{'table': {'family': 'ip', 'name': 'nat'}},
                   {'chain': {'family': 'ip', 'table': 'nat', 'name': 'post',
                              'type': 'nat', 'hook': 'postrouting', 'policy': 'accept'}}]
        report, _ = self.check({'nft': (json.dumps({'nftables': entries}), 0)})
        self.assertTrue(report.findings)

    def test_nft_hooked_filter_policy_and_rule(self):
        for policy, expr in (('drop', []), ('accept', [{'reject': None}])):
            entries = [{'chain': {'family': 'inet', 'table': 'filter', 'name': 'in',
                                  'type': 'filter', 'hook': 'input', 'policy': policy}},
                       {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'in', 'expr': expr}}]
            with self.subTest(policy=policy):
                report, _ = self.check({'nft': (json.dumps({'nftables': entries}), 0)})
                self.assertEqual(report.findings, [])

    def test_failures_and_malformed_data_are_coverage_not_absence(self):
        report, command = self.check({'nft': ('{bad json', 0)},
                                     {'ufw': PermissionError('denied')})
        self.assertTrue(report.findings)
        self.assertTrue(all(f.coverage_gap for f in report.findings))
        for call in command.call_args_list:
            self.assertGreater(call.kwargs['timeout'], 0)

    def test_missing_tools_and_timeout(self):
        missing = {name: FileNotFoundError() for name in ('ufw', 'nft', 'iptables', 'ip6tables')}
        report, _ = self.check(failures=missing)
        self.assertFalse(report.findings[0].coverage_gap)
        missing['nft'] = host_policy.subprocess.TimeoutExpired('nft', 10)
        report, _ = self.check(failures=missing)
        self.assertTrue(report.findings[0].coverage_gap)

    def test_nft_chain_references_do_not_cross_tables(self):
        entries = [
            {'chain': {'family': 'inet', 'table': 'filter', 'name': 'in',
                       'type': 'filter', 'hook': 'input', 'policy': 'accept'}},
            {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'in',
                      'expr': [{'jump': {'target': 'guard'}}]}},
            {'rule': {'family': 'inet', 'table': 'other', 'chain': 'guard',
                      'expr': [{'drop': None}]}},
        ]
        report, _ = self.check({'nft': (json.dumps({'nftables': entries}), 0)})
        self.assertTrue(report.findings)
        entries[2]['rule']['table'] = 'filter'
        report, _ = self.check({'nft': (json.dumps({'nftables': entries}), 0)})
        self.assertEqual(report.findings, [])

    def test_nft_nontraditional_filter_hooks(self):
        for family, hook in (('inet', 'prerouting'), ('inet', 'postrouting'), ('netdev', 'egress')):
            for policy, expr in (('drop', []), ('accept', [{'drop': None}])):
                with self.subTest(family=family, hook=hook, policy=policy):
                    entries = [
                        {'chain': {'family': family, 'table': 'filter', 'name': 'guard',
                                   'type': 'filter', 'hook': hook, 'prio': 0,
                                   'dev': 'eth0', 'policy': policy}},
                        {'rule': {'family': family, 'table': 'filter', 'chain': 'guard', 'expr': expr}},
                    ]
                    report, _ = self.check({'nft': (json.dumps({'nftables': entries}), 0)})
                    self.assertEqual(report.findings, [])

    def test_nft_verdict_map_needs_manual_review(self):
        entries = [{'rule': {'family': 'inet', 'table': 'f', 'chain': 'in',
                             'expr': [{'vmap': {'key': {}, 'data': {}}}]}}]
        report, _ = self.check({'nft': (json.dumps({'nftables': entries}), 0)})
        self.assertTrue(report.findings[0].coverage_gap)


class EvidenceIsolationTests(unittest.TestCase):
    def test_audit_same_timestamp_allocates_unique_report_and_directory_ids(self):
        class StopAfterReport(Exception):
            pass

        captured = []
        def capture_report(**kwargs):
            captured.append(kwargs['scan_id'])
            raise StopAfterReport

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'config.txt').write_text('# fixture\n')
            arguments = ['ggfw', '--boot-path', directory, '--evidence-root', directory]
            with patch.object(sys, 'argv', arguments), \
                    patch.object(audit, 'detect_platform', return_value='fixture'), \
                    patch.object(audit, 'get_soc_generation', return_value='BCM2712'), \
                    patch.object(audit, 'datetime') as clock, \
                    patch.object(audit, 'GGFWReport', side_effect=capture_report), \
                    contextlib.redirect_stdout(io.StringIO()):
                clock.now.return_value = datetime(2026, 9, 14, tzinfo=timezone.utc)
                for _ in range(2):
                    with self.assertRaises(StopAfterReport):
                        audit.run_audit()
            self.assertEqual(len(set(captured)), 2)
            for scan_id in captured:
                self.assertTrue((Path(directory) / scan_id).is_dir())
                self.assertTrue(scan_id.startswith('ggfw-20260914T000000Z-bcm2712-'))

    def test_scan_id_cannot_reuse_root_or_traverse(self):
        with tempfile.TemporaryDirectory() as directory:
            for scan_id in ('', '.', '..', '../other', 'a/b', 'a\\b', 'C:other'):
                with self.subTest(scan_id=scan_id), self.assertRaises(GGFWRuntimeError):
                    EvidencePackageBuilder(directory, scan_id)

    def test_duplicate_id_fails_without_modifying_prior_run(self):
        with tempfile.TemporaryDirectory() as directory:
            first = EvidencePackageBuilder(directory, 'same-id')
            first.write_text('evidence/first.txt', 'first')
            with self.assertRaises(GGFWRuntimeError):
                EvidencePackageBuilder(directory, 'same-id')
            self.assertEqual(first.path('evidence/first.txt').read_text(), 'first')

    def test_concurrent_allocations_have_one_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            def allocate(_):
                try:
                    EvidencePackageBuilder(directory, 'same-id')
                    return True
                except GGFWRuntimeError:
                    return False
            with ThreadPoolExecutor(max_workers=4) as pool:
                self.assertEqual(sum(pool.map(allocate, range(4))), 1)

    def test_new_packages_do_not_share_files(self):
        with tempfile.TemporaryDirectory() as directory:
            for scan_id in ('first', 'second'):
                builder = EvidencePackageBuilder(directory, scan_id)
                builder.write_text(f'evidence/{scan_id}.txt', scan_id)
                target = Path(directory) / (scan_id + '.ggcap')
                builder.finalise(GGFWReport(scan_id=scan_id), str(target))
                with zipfile.ZipFile(target) as archive:
                    evidence = [p for p in archive.namelist() if p.startswith('evidence/')]
                    self.assertEqual(evidence, [f'evidence/{scan_id}.txt'])
                    self.assertEqual(json.loads(archive.read('manifest.json'))['scan_id'], scan_id)
                    self.assertEqual(json.loads(archive.read('report.json'))['scan_id'], scan_id)


if __name__ == '__main__':
    unittest.main(verbosity=2)
