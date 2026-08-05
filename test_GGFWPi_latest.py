#!/usr/bin/env python3
# Copyright 2026 GG Advanced IT Security UG
# Developed by Maciej Gojny for GGSEC
# SPDX-License-Identifier: Apache-2.0
import hashlib
import contextlib
import io
import importlib.util
import json
import os
import shutil
import re
import sys
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

VERSIONED_MODULE_RE = re.compile(
    r"^GGFWPi_v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)-beta\.py$"
)
MINIMUM_TESTED_VERSION = (0, 6, 6)


def discover_module_path() -> tuple[Path, tuple[int, int, int]]:
    """Select the newest versioned GGFW module from the test directory.

    GGFW_MODULE_PATH may explicitly select a module. Otherwise filenames are
    parsed semantically, so v0.10.0 sorts after v0.9.9.
    """
    explicit = os.environ.get("GGFW_MODULE_PATH")
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not candidate.is_file():
            raise RuntimeError(f"GGFW_MODULE_PATH is not a readable file: {candidate}")
        match = VERSIONED_MODULE_RE.match(candidate.name)
        if not match:
            raise RuntimeError(
                "GGFW_MODULE_PATH must use the versioned name "
                "GGFWPi_vMAJOR.MINOR.PATCH-beta.py"
            )
        version = tuple(int(match.group(name)) for name in ("major", "minor", "patch"))
        return candidate, version

    directory = Path(__file__).resolve().parent
    candidates = []
    for candidate in directory.glob("GGFWPi_v*-beta.py"):
        match = VERSIONED_MODULE_RE.match(candidate.name)
        if not match:
            continue
        version = tuple(int(match.group(name)) for name in ("major", "minor", "patch"))
        candidates.append((version, candidate.resolve()))
    if not candidates:
        raise RuntimeError(
            f"No versioned GGFW module found next to {Path(__file__).name}"
        )
    return max(candidates, key=lambda item: item[0])[1], max(candidates, key=lambda item: item[0])[0]


MODULE_PATH, MODULE_VERSION = discover_module_path()
if MODULE_VERSION < MINIMUM_TESTED_VERSION:
    raise RuntimeError(
        f"This regression suite requires GGFW >= {'.'.join(map(str, MINIMUM_TESTED_VERSION))}; "
        f"selected {MODULE_PATH.name}"
    )

MODULE_NAME = "ggfw_" + "_".join(map(str, MODULE_VERSION))
spec = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not create import spec for {MODULE_PATH}")
ggfw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ggfw)
print(f"[*] GGFW regression target: {MODULE_PATH.name}", file=sys.stderr)


class TestSuiteTargetSelection(unittest.TestCase):
    def test_current_module_is_selected_by_semantic_version(self):
        self.assertGreaterEqual(MODULE_VERSION, MINIMUM_TESTED_VERSION)
        self.assertEqual(ggfw.TOOL_VERSION, f"{MODULE_VERSION[0]}.{MODULE_VERSION[1]}.{MODULE_VERSION[2]}-beta")
        self.assertEqual(MODULE_PATH.name, f"GGFWPi_v{MODULE_VERSION[0]}.{MODULE_VERSION[1]}.{MODULE_VERSION[2]}-beta.py")
        self.assertNotEqual(MODULE_PATH.name, "GGFWPi_v0.5.6-beta.py")



def run_checked(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def sign_bytes(private_key: Path, payload: bytes, directory: Path, stem: str) -> bytes:
    input_path = directory / f'{stem}.input'
    output_path = directory / f'{stem}.signature'
    input_path.write_bytes(payload)
    run_checked(['openssl', 'dgst', '-sha256', '-sign', str(private_key), '-out', str(output_path), str(input_path)])
    return output_path.read_bytes()


def write_sig_file(private_key: Path, image_path: Path, sig_path: Path, target_soc='2712', timestamp=None):
    payload = image_path.read_bytes()
    with tempfile.TemporaryDirectory(prefix='ggfw-sign-') as tmp:
        signature = sign_bytes(private_key, payload, Path(tmp), 'payload')
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    lines = [hashlib.sha256(payload).hexdigest(), f'ts: {timestamp}']
    if target_soc is not None:
        lines.append(f'target-soc: {target_soc}')
    lines.append(f'rsa2048: {signature.hex()}')
    sig_path.write_text('\n'.join(lines) + '\n', encoding='ascii')


def file_section(filename: str, content: bytes) -> bytes:
    name = filename.encode('ascii')
    if len(name) > ggfw.RPI_EEPROM_FILENAME_LEN:
        raise ValueError(filename)
    name = name.ljust(ggfw.RPI_EEPROM_FILENAME_LEN, b'\x00')
    reserved = b'\x00' * 4
    length = 16 + len(content)
    section = struct.pack('>II', ggfw.RPI_EEPROM_FILE_MAGIC, length) + name + reserved + content
    return section + (b'\xff' * ((-len(section)) % 8))


def bootcode_section(content=b'RPI-BOOTCODE-FIXTURE') -> bytes:
    section = struct.pack('>II', ggfw.RPI_EEPROM_MAGIC, len(content)) + content
    return section + (b'\xff' * ((-len(section)) % 8))


def build_eeprom(path: Path, files, size=512 * 1024):
    blob = bytearray(bootcode_section())
    for filename, content in files:
        blob.extend(file_section(filename, content))
    if len(blob) > size:
        raise ValueError('fixture too large')
    blob.extend(b'\xff' * (size - len(blob)))
    path.write_bytes(blob)


def build_bcm2712_signed_bootsys(private_key: Path, key, directory: Path, version=3) -> bytes:
    base = (b'RPI-VENDOR-SIGNED-BOOTSYS-FIXTURE-' * 20) + os.urandom(37)
    metadata = struct.pack('<III', len(base), 16, version)
    signed_prefix = base + metadata
    signature = sign_bytes(private_key, signed_prefix, directory, 'bootsys')
    return signed_prefix + signature + key.to_pubkey_bin()


class SecureBootFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('openssl') is None:
            raise unittest.SkipTest('openssl unavailable')
        cls.root = Path(tempfile.mkdtemp(prefix='ggfw060-tests-'))
        cls.private_key = cls.root / 'customer-private.pem'
        cls.public_key = cls.root / 'customer-public.pem'
        run_checked([
            'openssl', 'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(cls.private_key),
        ])
        run_checked([
            'openssl', 'pkey', '-in', str(cls.private_key), '-pubout', '-out', str(cls.public_key),
        ])
        cls.key = ggfw.parse_pem_rsa_public_key(str(cls.public_key))

        cls.other_private = cls.root / 'other-private.pem'
        cls.other_public = cls.root / 'other-public.pem'
        run_checked([
            'openssl', 'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(cls.other_private),
        ])
        run_checked([
            'openssl', 'pkey', '-in', str(cls.other_private), '-pubout', '-out', str(cls.other_public),
        ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def make_complete_fixture(self, *, timestamp=None, metadata=True, enable_status='PROVISIONED'):
        directory = Path(tempfile.mkdtemp(prefix='chain-', dir=self.root))
        boot = directory / 'boot'
        boot.mkdir()
        (boot / 'config.txt').write_text('[all]\n', encoding='ascii')
        (boot / 'cmdline.txt').write_text('console=serial0,115200\n', encoding='ascii')
        boot_img = boot / 'boot.img'
        boot_img.write_bytes((b'BOOT-IMAGE-FIXTURE-' * 300) + os.urandom(53))
        write_sig_file(self.private_key, boot_img, boot / 'boot.sig', '2712', timestamp)

        bootconf = b'[all]\nBOOT_ORDER=0xf461\nSIGNED_BOOT=1\n'
        bootconf_path = directory / 'bootconf.txt'
        bootconf_path.write_bytes(bootconf)
        write_sig_file(self.private_key, bootconf_path, directory / 'bootconf.sig', None, timestamp)
        bootsys = build_bcm2712_signed_bootsys(self.private_key, self.key, directory)
        eeprom = directory / 'eeprom.bin'
        build_eeprom(eeprom, [
            ('pubkey.bin', self.key.to_pubkey_bin()),
            ('bootsys', bootsys),
            ('bootconf.sig', (directory / 'bootconf.sig').read_bytes()),
            ('bootconf.txt', bootconf),
        ])
        decoded = {
            'soc': 'BCM2712',
            'decoder_profile': 'BCM2712-v1',
            'decoder_status': 'SUPPORTED',
            'raw_word_count': 83,
            'security': {
                'customer_key_hash': {'status': 'PROGRAMMED', 'value': self.key.fingerprint()},
                'secure_boot_enablement': {'status': enable_status},
                'vc_jtag_lock': {'status': 'LOCKED'},
            },
        }
        metadata_bundle = {
            'loaded': bool(metadata),
            'files': ['fixture.json'] if metadata else [],
            'metadata': {
                'CUSTOMER_KEY_HASH': self.key.fingerprint(),
                'SECURE_BOOT_PROVISION': 'success',
                'JTAG_LOCKED': '1',
            } if metadata else {},
        }
        return directory, boot, eeprom, decoded, metadata_bundle

    def test_public_key_roundtrip(self):
        raw = self.key.to_pubkey_bin()
        parsed = ggfw.parse_rpi_pubkey_bin(raw, 'fixture')
        self.assertEqual(parsed.modulus, self.key.modulus)
        self.assertEqual(parsed.exponent, self.key.exponent)
        self.assertEqual(parsed.fingerprint(), self.key.fingerprint())

    def test_boot_sig_valid(self):
        directory = Path(tempfile.mkdtemp(prefix='sig-', dir=self.root))
        image = directory / 'boot.img'
        sig = directory / 'boot.sig'
        image.write_bytes(b'valid signed image')
        write_sig_file(self.private_key, image, sig, '2712')
        result = ggfw.validate_rpi_signed_file(image, sig, self.key, '2712')
        self.assertEqual(result['overall'], 'VALID', result)
        self.assertEqual(result['digest_status'], 'MATCH')
        self.assertEqual(result['rsa_signature_status'], 'VERIFIED')
        self.assertEqual(result['target_soc_status'], 'MATCH')

    def test_boot_sig_tamper_fails(self):
        directory = Path(tempfile.mkdtemp(prefix='tamper-', dir=self.root))
        image = directory / 'boot.img'
        sig = directory / 'boot.sig'
        image.write_bytes(b'original')
        write_sig_file(self.private_key, image, sig, '2712')
        image.write_bytes(b'tampered')
        result = ggfw.validate_rpi_signed_file(image, sig, self.key, '2712')
        self.assertEqual(result['overall'], 'INVALID')
        self.assertEqual(result['digest_status'], 'MISMATCH')
        self.assertEqual(result['rsa_signature_status'], 'INVALID')

    def test_future_timestamp_fails(self):
        directory = Path(tempfile.mkdtemp(prefix='future-', dir=self.root))
        image = directory / 'boot.img'
        sig = directory / 'boot.sig'
        image.write_bytes(b'future timestamp')
        write_sig_file(self.private_key, image, sig, '2712', int(time.time()) + 3600)
        result = ggfw.validate_rpi_signed_file(image, sig, self.key, '2712')
        self.assertEqual(result['overall'], 'INVALID')
        self.assertEqual(result['freshness_status'], 'FUTURE_TIMESTAMP')

    def _validate_signature_bytes(self, signature_bytes, key_marker='default'):
        directory = Path(tempfile.mkdtemp(prefix='sig-class-', dir=self.root))
        image = directory / 'bootconf.txt'
        sig = directory / 'bootconf.sig'
        image.write_bytes(b'[all]\nBOOT_ORDER=0xf461\n')
        sig.write_bytes(signature_bytes)
        key = self.key if key_marker == 'default' else key_marker
        return ggfw.validate_rpi_signed_file(image, sig, key, None)

    def test_erased_ff_signature_placeholder_is_unverified(self):
        result = self._validate_signature_bytes(b'\xff' * 4096)
        self.assertEqual(result['overall'], 'UNVERIFIED', result)
        self.assertEqual(result['reason_code'], 'SIGNATURE_NOT_PRESENT')
        self.assertEqual(result['signature_content']['content_class'], 'ERASED_PLACEHOLDER')
        self.assertFalse(result['effective_signature_present'])

    def test_zero_filled_signature_placeholder_is_unverified(self):
        result = self._validate_signature_bytes(b'\x00' * 4096)
        self.assertEqual(result['overall'], 'UNVERIFIED', result)
        self.assertEqual(result['reason_code'], 'SIGNATURE_NOT_PRESENT')
        self.assertEqual(result['signature_content']['content_class'], 'ZERO_FILLED_PLACEHOLDER')

    def test_whitespace_nul_ff_signature_placeholder_is_unverified(self):
        result = self._validate_signature_bytes(b' \t\r\n\x00\xff' * 32)
        self.assertEqual(result['overall'], 'UNVERIFIED', result)
        self.assertEqual(result['reason_code'], 'SIGNATURE_NOT_PRESENT')
        self.assertIn(result['signature_content']['content_class'], {
            'ERASED_OR_ZERO_PLACEHOLDER', 'WHITESPACE_PLACEHOLDER',
        })

    def test_digest_only_signature_is_unverified_not_invalid(self):
        payload = b'[all]\nBOOT_ORDER=0xf461\n'
        content = (hashlib.sha256(payload).hexdigest() + f'\nts: {int(time.time())}\n').encode('ascii')
        result = self._validate_signature_bytes(content)
        self.assertEqual(result['overall'], 'UNVERIFIED', result)
        self.assertEqual(result['reason_code'], 'SIGNATURE_NOT_PRESENT')
        self.assertEqual(result['signature_content']['content_class'], 'DIGEST_ONLY')
        self.assertEqual(result['digest_status'], 'MATCH')
        self.assertFalse(result['effective_signature_present'])

    def test_malformed_rsa_signature_text_is_invalid(self):
        payload = b'[all]\nBOOT_ORDER=0xf461\n'
        content = (
            hashlib.sha256(payload).hexdigest() +
            f'\nts: {int(time.time())}\nrsa2048: 1234\n'
        ).encode('ascii')
        result = self._validate_signature_bytes(content)
        self.assertEqual(result['overall'], 'INVALID', result)
        self.assertEqual(result['reason_code'], 'FORMAT_INVALID')
        self.assertEqual(result['signature_content']['content_class'], 'MALFORMED_SIGNATURE_TEXT')

    def test_valid_signature_without_key_is_unverified(self):
        directory = Path(tempfile.mkdtemp(prefix='sig-nokey-', dir=self.root))
        image = directory / 'bootconf.txt'
        sig = directory / 'bootconf.sig'
        image.write_bytes(b'[all]\nSIGNED_BOOT=1\n')
        write_sig_file(self.private_key, image, sig, None)
        result = ggfw.validate_rpi_signed_file(image, sig, None, None)
        self.assertEqual(result['overall'], 'UNVERIFIED', result)
        self.assertEqual(result['reason_code'], 'KEY_UNAVAILABLE')
        self.assertEqual(result['signature_content']['content_class'], 'SIGNED_TEXT')
        self.assertTrue(result['effective_signature_present'])

    def test_valid_format_wrong_rsa_is_invalid(self):
        directory = Path(tempfile.mkdtemp(prefix='sig-wrongrsa-', dir=self.root))
        image = directory / 'bootconf.txt'
        sig = directory / 'bootconf.sig'
        image.write_bytes(b'[all]\nSIGNED_BOOT=1\n')
        write_sig_file(self.other_private, image, sig, None)
        result = ggfw.validate_rpi_signed_file(image, sig, self.key, None)
        self.assertEqual(result['overall'], 'INVALID', result)
        self.assertEqual(result['reason_code'], 'CRYPTOGRAPHIC_MISMATCH')
        self.assertTrue(result['cryptographic_verification_performed'])

    def test_eeprom_placeholder_bootconf_does_not_create_sb005(self):
        directory, boot, eeprom, decoded, metadata = self.make_complete_fixture(metadata=False)
        original = ggfw.RaspberryPiEEPROMImage(str(eeprom))
        placeholder_eeprom = directory / 'eeprom-placeholder-bootconf.bin'
        build_eeprom(placeholder_eeprom, [
            ('pubkey.bin', self.key.to_pubkey_bin()),
            ('bootsys', original.get_first('bootsys')),
            ('bootconf.sig', b'\xff' * 4096),
            ('bootconf.txt', original.get_first('bootconf.txt')),
        ])
        decoded['security']['customer_key_hash'] = {'status': 'UNKNOWN', 'value': None}
        decoded['security']['secure_boot_enablement'] = {'status': 'UNKNOWN'}
        validation = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(placeholder_eeprom), None,
            decoded, {'loaded': False, 'metadata': {}},
        )
        self.assertEqual(validation['overall'], 'UNVERIFIED', json.dumps(validation, indent=2))
        self.assertEqual(validation['authenticity'], 'PARTIALLY_VERIFIED')
        bootconf = validation['bootconf_signature']
        self.assertEqual(bootconf['overall'], 'UNVERIFIED')
        self.assertEqual(bootconf['reason_code'], 'SIGNATURE_NOT_PRESENT')
        self.assertEqual(bootconf['content_classes'], ['ERASED_PLACEHOLDER'])
        self.assertEqual(bootconf['section_present_count'], 1)
        self.assertEqual(bootconf['effective_signature_present_count'], 0)

        report = ggfw.GGFWReport(
            target_path=str(boot), platform_guess='Raspberry Pi 5 (BCM2712)',
            policy_profile='secure-boot-required',
        )
        engine = ggfw.HardwarePolicyEngine(
            platform='Raspberry Pi 5 (BCM2712)', otp={}, eeprom_conf='[all]\n',
            report=report, otp_tool_available=True,
            otp_metadata_bundle={'loaded': False, 'metadata': {}},
        )
        engine.decoded = decoded
        engine.check_secure_boot(chain_validation=validation)
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn('RPI-SB-005', rule_ids)

    def test_eeprom_parser_extracts_exact_content(self):
        directory = Path(tempfile.mkdtemp(prefix='eeprom-', dir=self.root))
        image_path = directory / 'eeprom.bin'
        expected = b'key\x00binary\xffcontents'
        build_eeprom(image_path, [('pubkey.bin', expected)])
        parsed = ggfw.RaspberryPiEEPROMImage(str(image_path))
        self.assertEqual(parsed.errors, [])
        self.assertEqual(parsed.get_first('pubkey.bin'), expected)

    def test_bcm2712_bootsys_signature(self):
        directory = Path(tempfile.mkdtemp(prefix='bootsys-', dir=self.root))
        blob = build_bcm2712_signed_bootsys(self.private_key, self.key, directory)
        result = ggfw.verify_bcm2712_customer_signed_blob(blob, self.key, 'fixture')
        self.assertEqual(result['overall'], 'VALID', result)
        self.assertEqual(result['signature_status'], 'VERIFIED')
        self.assertEqual(result['public_key_status'], 'MATCH')
        self.assertEqual(result['key_number'], 16)
        self.assertEqual(result['length_status'], 'MATCH')

    def test_complete_bcm2712_chain_passes(self):
        _, boot, eeprom, decoded, metadata = self.make_complete_fixture()
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(eeprom), str(self.public_key),
            decoded, metadata,
        )
        self.assertEqual(result['overall'], 'PASS', json.dumps(result, indent=2))
        self.assertEqual(result['authenticity'], 'VERIFIED_CUSTOMER_CHAIN')
        self.assertEqual(result['public_key']['otp_binding'], 'MATCH')
        self.assertEqual(result['bootconf_signature']['overall'], 'VALID')
        self.assertEqual(result['boot_image_signature']['overall'], 'VALID')
        self.assertEqual(result['bootsys_customer_countersignature']['overall'], 'VALID')
        matrix = ggfw.build_secure_boot_evidence(
            'Raspberry Pi 5 (BCM2712)', boot, decoded, metadata,
            'secure-boot-required', result,
        )
        self.assertEqual(matrix['overall'], 'PASS')
        self.assertEqual(matrix['policy'], 'PASS')

    def test_unknown_enablement_prevents_pass(self):
        _, boot, eeprom, decoded, metadata = self.make_complete_fixture(enable_status='UNKNOWN')
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(eeprom), str(self.public_key), decoded, metadata,
        )
        self.assertEqual(result['overall'], 'UNVERIFIED', json.dumps(result, indent=2))
        self.assertTrue(result['coverage_gap'])

    def test_missing_otp_binding_prevents_pass(self):
        _, boot, eeprom, decoded, metadata = self.make_complete_fixture(metadata=False)
        decoded['security']['customer_key_hash'] = {'status': 'UNKNOWN', 'value': None}
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(eeprom), str(self.public_key), decoded, metadata,
        )
        self.assertEqual(result['overall'], 'UNVERIFIED')
        self.assertEqual(result['public_key']['otp_binding'], 'HASH_UNAVAILABLE')

    def test_supplied_key_mismatch_fails(self):
        _, boot, eeprom, decoded, metadata = self.make_complete_fixture()
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(eeprom), str(self.other_public), decoded, metadata,
        )
        self.assertEqual(result['overall'], 'FAIL')
        self.assertEqual(result['public_key']['source_relationship'], 'SUPPLIED_MISMATCHES_EEPROM')

    def test_missing_timestamp_cannot_reach_full_pass(self):
        directory, boot, eeprom, decoded, metadata = self.make_complete_fixture()
        sig_path = boot / 'boot.sig'
        lines = [line for line in sig_path.read_text().splitlines() if not line.startswith('ts:')]
        sig_path.write_text('\n'.join(lines) + '\n')
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(eeprom), str(self.public_key), decoded, metadata,
        )
        self.assertEqual(result['boot_image_signature']['overall'], 'VALID')
        self.assertEqual(result['boot_image_signature']['freshness_status'], 'TIMESTAMP_MISSING')
        self.assertEqual(result['overall'], 'UNVERIFIED')

    def test_duplicate_eeprom_public_keys_must_be_consistent(self):
        directory, boot, eeprom, decoded, metadata = self.make_complete_fixture()
        original = ggfw.RaspberryPiEEPROMImage(str(eeprom))
        other_key = ggfw.parse_pem_rsa_public_key(str(self.other_public))
        replacement = directory / 'eeprom-inconsistent-keys.bin'
        build_eeprom(replacement, [
            ('pubkey.bin', self.key.to_pubkey_bin()),
            ('pubkey.bin', other_key.to_pubkey_bin()),
            ('bootsys', original.get_first('bootsys')),
            ('bootconf.sig', original.get_first('bootconf.sig')),
            ('bootconf.txt', original.get_first('bootconf.txt')),
        ])
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(replacement), str(self.public_key), decoded, metadata,
        )
        self.assertEqual(result['overall'], 'FAIL')
        self.assertEqual(result['public_key']['eeprom_status'], 'INCONSISTENT')
        self.assertEqual(result['public_key']['source_relationship'], 'EEPROM_KEYS_INCONSISTENT')

    def test_all_bootconf_partitions_must_verify(self):
        directory, boot, eeprom, decoded, metadata = self.make_complete_fixture()
        original = ggfw.RaspberryPiEEPROMImage(str(eeprom))
        valid_sig = original.get_first('bootconf.sig')
        text = valid_sig.decode('ascii')
        signature_line = next(line for line in text.splitlines() if line.startswith('rsa2048:'))
        hex_value = signature_line.split(':', 1)[1].strip()
        tampered = ('0' if hex_value[0] != '0' else '1') + hex_value[1:]
        invalid_sig = text.replace(hex_value, tampered).encode('ascii')
        replacement = directory / 'eeprom-inconsistent-bootconf.bin'
        build_eeprom(replacement, [
            ('pubkey.bin', self.key.to_pubkey_bin()),
            ('bootsys', original.get_first('bootsys')),
            ('bootconf.sig', valid_sig),
            ('bootconf.txt', original.get_first('bootconf.txt')),
            ('bootconf.sig', invalid_sig),
            ('bootconf.txt', original.get_first('bootconf.txt')),
        ])
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(replacement), str(self.public_key), decoded, metadata,
        )
        self.assertEqual(result['overall'], 'FAIL', json.dumps(result, indent=2))
        self.assertEqual(result['bootconf_signature']['overall'], 'INVALID')
        self.assertEqual(result['bootconf_signature']['entry_count'], 2)

    def test_bcm2711_complete_customer_chain_passes_without_bootsys_countersignature(self):
        directory = Path(tempfile.mkdtemp(prefix='chain2711-', dir=self.root))
        boot = directory / 'boot'
        boot.mkdir()
        (boot / 'boot.img').write_bytes(b'BCM2711 signed image fixture')
        write_sig_file(self.private_key, boot / 'boot.img', boot / 'boot.sig', '2711')
        bootconf = b'[all]\nSIGNED_BOOT=1\n'
        conf_path = directory / 'bootconf.txt'
        conf_path.write_bytes(bootconf)
        write_sig_file(self.private_key, conf_path, directory / 'bootconf.sig', None)
        eeprom = directory / 'eeprom.bin'
        build_eeprom(eeprom, [
            ('pubkey.bin', self.key.to_pubkey_bin()),
            ('bootconf.sig', (directory / 'bootconf.sig').read_bytes()),
            ('bootconf.txt', bootconf),
        ])
        decoded = {
            'soc': 'BCM2711', 'decoder_profile': 'BCM2711-v1', 'decoder_status': 'SUPPORTED',
            'raw_word_count': 67,
            'security': {
                'customer_key_hash': {'status': 'PROGRAMMED', 'value': self.key.fingerprint()},
                'secure_boot_enablement': {'status': 'ENABLED'},
                'vc_jtag_lock': {'status': 'LOCKED'},
            },
        }
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 4 (BCM2711)', boot, str(eeprom), str(self.public_key), decoded, {'loaded': False, 'metadata': {}},
        )
        self.assertEqual(result['overall'], 'PASS', json.dumps(result, indent=2))
        self.assertEqual(result['bootsys_customer_countersignature']['overall'], 'NOT_APPLICABLE')

    def test_target_soc_mismatch_fails(self):
        directory = Path(tempfile.mkdtemp(prefix='soc-mismatch-', dir=self.root))
        image = directory / 'boot.img'
        sig = directory / 'boot.sig'
        image.write_bytes(b'target mismatch')
        write_sig_file(self.private_key, image, sig, '2711')
        result = ggfw.validate_rpi_signed_file(image, sig, self.key, '2712')
        self.assertEqual(result['overall'], 'INVALID')
        self.assertEqual(result['target_soc_status'], 'MISMATCH')

    def test_blocker_rules_include_crypto_failures(self):
        source = MODULE_PATH.read_text(encoding='utf-8')
        for rule in ('RPI-SB-003', 'RPI-SB-004', 'RPI-SB-005', 'RPI-SB-006'):
            self.assertIn(f'"{rule}"', source)

    def test_help_exposes_secure_boot_options(self):
        completed = subprocess.run(
            ['python3', str(MODULE_PATH), '--help'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True,
        )
        self.assertIn('--secure-boot-public-key', completed.stdout)
        self.assertIn('--max-boot-signature-age-days', completed.stdout)


    def test_missing_key_keeps_bootconf_and_bootsys_unverified(self):
        directory, boot, eeprom, decoded, metadata = self.make_complete_fixture(metadata=False)
        original = ggfw.RaspberryPiEEPROMImage(str(eeprom))
        no_key_eeprom = directory / 'eeprom-no-pubkey.bin'
        build_eeprom(no_key_eeprom, [
            ('bootsys', original.get_first('bootsys')),
            ('bootconf.sig', original.get_first('bootconf.sig')),
            ('bootconf.txt', original.get_first('bootconf.txt')),
        ])
        decoded['security']['customer_key_hash'] = {'status': 'UNKNOWN', 'value': None}
        decoded['security']['secure_boot_enablement'] = {'status': 'UNKNOWN'}
        result = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(no_key_eeprom), None,
            decoded, {'loaded': False, 'metadata': {}},
        )
        self.assertEqual(result['overall'], 'UNVERIFIED', json.dumps(result, indent=2))
        self.assertEqual(result['authenticity'], 'UNVERIFIED')
        self.assertEqual(result['bootconf_signature']['overall'], 'UNVERIFIED')
        self.assertEqual(result['bootconf_signature']['reason_code'], 'KEY_UNAVAILABLE')
        self.assertEqual(result['bootsys_customer_countersignature']['overall'], 'UNVERIFIED')
        self.assertEqual(result['bootsys_customer_countersignature']['reason_code'], 'KEY_UNAVAILABLE')
        self.assertEqual(result['boot_image_signature']['overall'], 'UNVERIFIED')
        self.assertEqual(result['boot_image_signature']['reason_code'], 'KEY_UNAVAILABLE')

    def test_missing_key_does_not_create_sb005_or_sb006(self):
        directory, boot, eeprom, decoded, metadata = self.make_complete_fixture(metadata=False)
        original = ggfw.RaspberryPiEEPROMImage(str(eeprom))
        no_key_eeprom = directory / 'eeprom-no-pubkey-findings.bin'
        build_eeprom(no_key_eeprom, [
            ('bootsys', original.get_first('bootsys')),
            ('bootconf.sig', original.get_first('bootconf.sig')),
            ('bootconf.txt', original.get_first('bootconf.txt')),
        ])
        decoded['security']['customer_key_hash'] = {'status': 'UNKNOWN', 'value': None}
        decoded['security']['secure_boot_enablement'] = {'status': 'UNKNOWN'}
        validation = ggfw.validate_secure_boot_chain(
            'Raspberry Pi 5 (BCM2712)', boot, str(no_key_eeprom), None,
            decoded, {'loaded': False, 'metadata': {}},
        )
        report = ggfw.GGFWReport(
            target_path=str(boot), platform_guess='Raspberry Pi 5 (BCM2712)',
            policy_profile='secure-boot-required',
        )
        engine = ggfw.HardwarePolicyEngine(
            platform='Raspberry Pi 5 (BCM2712)', otp={}, eeprom_conf='[all]\n',
            report=report, otp_tool_available=True,
            otp_metadata_bundle={'loaded': False, 'metadata': {}},
        )
        engine.decoded = decoded
        engine.check_secure_boot(chain_validation=validation)
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn('RPI-SB-005', rule_ids)
        self.assertNotIn('RPI-SB-006', rule_ids)
        self.assertIn('HW-SEC-001', rule_ids)

    def test_unsigned_bootsys_is_unverified_not_invalid(self):
        blob = (b'RPI-VENDOR-BOOTSYS-WITHOUT-CUSTOMER-TRAILER' * 20)
        result = ggfw.verify_bcm2712_customer_signed_blob(blob, None, 'fixture')
        self.assertEqual(result['overall'], 'UNVERIFIED')
        self.assertEqual(result['reason_code'], 'SIGNATURE_NOT_PRESENT')

    def test_invalid_explicit_metadata_path_fails_before_scan(self):
        missing = self.root / 'does-not-exist.json'
        completed = subprocess.run(
            ['python3', str(MODULE_PATH), '--otp-metadata', str(missing), '--otp-only'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn('--otp-metadata path does not exist', completed.stdout)
        self.assertNotIn('Auditor starting', completed.stdout)
        self.assertNotIn('Starting read-only SPI EEPROM acquisition', completed.stdout)

    def test_invalid_explicit_public_key_fails_before_scan(self):
        invalid_key = self.root / 'invalid-public.pem'
        invalid_key.write_text('not a PEM key', encoding='ascii')
        completed = subprocess.run(
            ['python3', str(MODULE_PATH), '--secure-boot-public-key', str(invalid_key), '--otp-only'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn('--secure-boot-public-key is invalid', completed.stdout)
        self.assertNotIn('Auditor starting', completed.stdout)
        self.assertNotIn('Starting read-only SPI EEPROM acquisition', completed.stdout)


class OTPDecoderTests(unittest.TestCase):
    def test_bcm2711_programmed_secure_boot_and_jtag_lock(self):
        words = {f"{row:02d}": "00000000" for row in range(67)}
        words["16"] = "0c000000"
        words["17"] = "00008000"
        for index, row in enumerate(range(47, 55), 1):
            words[str(row)] = f"{index:08x}"
        decoded = ggfw.decode_otp_state(
            "Raspberry Pi 4 (BCM2711)", words, ggfw.load_rpiboot_metadata(None)
        )
        self.assertEqual(decoded["security"]["customer_key_hash"]["status"], "PROGRAMMED")
        self.assertEqual(decoded["security"]["secure_boot_enablement"]["status"], "ENABLED")
        self.assertEqual(decoded["security"]["vc_jtag_lock"]["status"], "LOCKED")

    def test_bcm2711_unprogrammed_and_unlocked(self):
        words = {f"{row:02d}": "00000000" for row in range(67)}
        decoded = ggfw.decode_otp_state(
            "Raspberry Pi 4 (BCM2711)", words, ggfw.load_rpiboot_metadata(None)
        )
        self.assertEqual(decoded["security"]["customer_key_hash"]["status"], "UNPROGRAMMED")
        self.assertEqual(decoded["security"]["secure_boot_enablement"]["status"], "DISABLED")
        self.assertEqual(decoded["security"]["vc_jtag_lock"]["status"], "UNLOCKED")

    def test_bcm2712_runtime_security_fields_fail_closed_and_structured(self):
        words = {
            "22": "0000000a", "23": "0000000a", "29": "00009400",
            "31": "cd2af639", "32": "00d04171", "33": "00000000",
            "35": "6ba4ff4e",
        }
        decoded = ggfw.decode_otp_state(
            "Raspberry Pi 5 (BCM2712)", words, ggfw.load_rpiboot_metadata(None)
        )
        self.assertEqual(decoded["decoder_status"], "PARTIAL")
        self.assertEqual(decoded["security"]["customer_key_hash"]["status"], "UNKNOWN")
        self.assertEqual(decoded["security"]["vc_jtag_lock"]["status"], "UNKNOWN")
        unresolved = decoded["unresolved_security_fields"]
        self.assertEqual(len(unresolved), 3)
        by_field = {item["field"]: item for item in unresolved}
        self.assertEqual(by_field["customer_key_hash"]["source_rows"], "UNPUBLISHED")
        self.assertEqual(by_field["vc_jtag_lock"]["source_rows"], "UNPUBLISHED")
        self.assertEqual(
            by_field["device_private_key"]["source_rows"],
            "DEDICATED_MAILBOX_NOT_QUERIED",
        )

    def test_bcm2712_rpiboot_metadata_removes_resolved_unknowns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_path = Path(temp_dir) / "SERIAL_NUMBER.json"
            metadata_path.write_text(json.dumps({
                "SECURE_BOOT_PROVISION": "success",
                "CUSTOMER_KEY_HASH": "8251a63a2edee9d8f710d63e9da5d639064929ce15a2238986a189ac6fcd3cee",
                "JTAG_LOCKED": "1",
                "SIGNATURE_MODE": "0",
            }))
            metadata = ggfw.load_rpiboot_metadata(str(metadata_path))
            decoded = ggfw.decode_otp_state("Raspberry Pi 5 (BCM2712)", {}, metadata)
            self.assertEqual(decoded["security"]["customer_key_hash"]["status"], "PROGRAMMED")
            self.assertEqual(decoded["security"]["secure_boot_enablement"]["status"], "PROVISIONED")
            self.assertEqual(decoded["security"]["vc_jtag_lock"]["status"], "LOCKED")
            self.assertEqual(
                [item["field"] for item in decoded["unresolved_security_fields"]],
                ["device_private_key"],
            )

    def test_secure_boot_matrix_never_claims_signature_pass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            boot_root = Path(temp_dir)
            (boot_root / "boot.img").write_bytes(b"image")
            (boot_root / "boot.sig").write_text("signature")
            metadata_path = boot_root / "metadata.json"
            metadata_path.write_text(json.dumps({
                "SECURE_BOOT_PROVISION": "success",
                "CUSTOMER_KEY_HASH": "11" * 32,
                "JTAG_LOCKED": "1",
            }))
            metadata = ggfw.load_rpiboot_metadata(str(metadata_path))
            decoded = ggfw.decode_otp_state("Raspberry Pi 5 (BCM2712)", {}, metadata)
            matrix = ggfw.build_secure_boot_evidence(
                "Raspberry Pi 5 (BCM2712)", boot_root, decoded, metadata, "default"
            )
            self.assertEqual(matrix["overall"], "EVIDENCE_INCOMPLETE")
            self.assertEqual(matrix["evidence"]["bootsys_customer_countersignature"]["overall"], "NOT_VERIFIED")
            self.assertEqual(matrix["evidence"]["boot_img_signature"]["overall"], "NOT_VERIFIED")

    def test_multiple_metadata_devices_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in (1, 2):
                (root / f"device-{index}.json").write_text(json.dumps({
                    "CUSTOMER_KEY_HASH": f"{index:02x}" * 32,
                    "JTAG_LOCKED": "0",
                }))
            metadata = ggfw.load_rpiboot_metadata(str(root))
            self.assertFalse(metadata["loaded"])
            self.assertIn("Multiple device metadata", metadata["error"])

    def test_secure_boot_matrix_freshness_is_not_assessed_without_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            boot_root = Path(temp_dir)
            decoded = ggfw.decode_otp_state(
                "Raspberry Pi 5 (BCM2712)", {}, ggfw.load_rpiboot_metadata(None)
            )
            matrix = ggfw.build_secure_boot_evidence(
                "Raspberry Pi 5 (BCM2712)", boot_root, decoded,
                ggfw.load_rpiboot_metadata(None), "default"
            )
            self.assertEqual(matrix["freshness"], "NOT_ASSESSED")

    def test_secure_boot_aggregate_relations_and_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report = ggfw.GGFWReport(
                target_path=temp_dir,
                platform_guess="Raspberry Pi 5 (BCM2712)",
                policy_profile="secure-boot-required",
            )
            engine = ggfw.HardwarePolicyEngine(
                platform="Raspberry Pi 5 (BCM2712)",
                otp={"22": "00000000"},
                eeprom_conf="[all]\n",
                report=report,
                otp_tool_available=True,
                otp_metadata_bundle=ggfw.load_rpiboot_metadata(None),
            )
            engine.run_all_checks()
            report.add_finding(ggfw.Finding(
                rule_id="RPI-CRED-003", severity="CRITICAL", category="ACCESS",
                description="credential", evidence="credential", remediation="fix credential",
                actionable=True,
            ))
            report.add_finding(ggfw.Finding(
                rule_id="RPI-SPI-WP-001", severity="HIGH", category="HARDWARE",
                description="wp", evidence="wp", remediation="fix wp", actionable=True,
            ))
            aggregate = next(f for f in report.findings if f.rule_id == "HW-SEC-001")
            self.assertTrue(aggregate.aggregate)
            self.assertFalse(aggregate.actionable)
            self.assertFalse(aggregate.evidence_required)
            self.assertEqual(
                aggregate.blocked_by,
                ["RPI-OTP-002", "RPI-SB-001"],
            )
            report.calculate_summary()
            self.assertEqual(report.summary["actionable"], 3)
            self.assertEqual(report.summary["remediation_tasks"], 3)
            self.assertEqual(report.summary["aggregate_findings"], 1)
            self.assertEqual(report.summary["coverage_gaps"], 2)
            self.assertEqual(report.summary["coverage_gaps_total"], 2)
            self.assertEqual(report.summary["actionable_security_policy"], 3)
            self.assertEqual(report.summary["non_actionable_coverage_gaps"], 0)
            self.assertEqual(report.summary["evidence_required"], 1)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                ggfw.print_scan_summary(report)
            rendered = output.getvalue()
            self.assertIn("FINDING COUNTS", rendered)
            self.assertIn("Actionable security/policy findings:  3", rendered)
            self.assertIn("Evidence acquisition required:        1", rendered)
            self.assertIn("CROSS-CUTTING ATTRIBUTES", rendered)
            self.assertIn("Coverage gaps overall:        2", rendered)
            self.assertIn("Aggregate findings overall:   1", rendered)
            self.assertIn("REMEDIATION VIEW", rendered)
            self.assertIn("Independent remediation tasks:  3", rendered)
            self.assertNotIn("    Remediation tasks:", rendered)

    def test_show_otp_prints_structured_unresolved_fields(self):
        decoded = ggfw.decode_otp_state(
            "Raspberry Pi 5 (BCM2712)", {"22": "00000000"},
            ggfw.load_rpiboot_metadata(None),
        )
        report = ggfw.GGFWReport()
        report.raw_artifacts["otp_decoded"] = decoded
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ggfw.print_otp_summary(report)
        rendered = output.getvalue()
        self.assertIn("Undecoded security data: 3 item(s)", rendered)
        self.assertIn("- customer_key_hash", rendered)
        self.assertIn("source rows: UNPUBLISHED", rendered)
        self.assertIn("- device_private_key", rendered)
        self.assertIn("source rows: DEDICATED_MAILBOX_NOT_QUERIED", rendered)

    def _gate_report(self):
        report = ggfw.GGFWReport(policy_profile="secure-boot-required")
        report.add_finding(ggfw.Finding(
            rule_id="RPI-OTP-002", severity="HIGH", category="HARDWARE",
            description="otp gap", evidence="otp", remediation="collect metadata",
            coverage_gap=True, actionable=True, finding_class="COVERAGE_GAP",
            remediation_group="SECURE_BOOT_ENABLEMENT",
        ))
        report.add_finding(ggfw.Finding(
            rule_id="HW-SEC-001", severity="HIGH", category="HARDWARE",
            description="aggregate gap", evidence="chain", remediation="verify chain",
            coverage_gap=True, actionable=True, aggregate=True,
            blocked_by=["RPI-OTP-002"], finding_class="COVERAGE_GAP",
            remediation_group="SECURE_BOOT_ENABLEMENT",
        ))
        report.add_finding(ggfw.Finding(
            rule_id="RPI-SPI-WP-001", severity="HIGH", category="HARDWARE",
            description="wp disabled", evidence="wp", remediation="protect",
            actionable=True, finding_class="SECURITY_FINDING",
        ))
        return report

    def test_high_gate_uses_leaf_security_policy_findings_by_default(self):
        report = self._gate_report()
        code, matches, excluded = ggfw.evaluate_fail_policy(report, "HIGH")
        self.assertEqual(code, 2)
        self.assertEqual(matches, ["RPI-SPI-WP-001"])
        self.assertEqual(excluded, ["HW-SEC-001", "RPI-OTP-002"])

    def test_fail_on_coverage_opts_leaf_coverage_into_high_gate(self):
        report = self._gate_report()
        code, matches, excluded = ggfw.evaluate_fail_policy(
            report, "HIGH", fail_on_coverage=True
        )
        self.assertEqual(code, 2)
        self.assertEqual(matches, ["RPI-OTP-002", "RPI-SPI-WP-001"])
        self.assertNotIn("HW-SEC-001", matches)
        self.assertEqual(excluded, ["HW-SEC-001"])

    def test_explicit_coverage_gate_uses_leaf_findings_only(self):
        report = self._gate_report()
        code, matches, excluded = ggfw.evaluate_fail_policy(report, "COVERAGE_GAP")
        self.assertEqual(code, 2)
        self.assertEqual(matches, ["RPI-OTP-002"])
        self.assertEqual(excluded, ["HW-SEC-001"])

    def test_gate_exclude_still_filters_opted_in_coverage(self):
        report = self._gate_report()
        code, matches, excluded = ggfw.evaluate_fail_policy(
            report, "HIGH", ["COVERAGE_GAP"], fail_on_coverage=True
        )
        self.assertEqual(code, 2)
        self.assertEqual(matches, ["RPI-SPI-WP-001"])
        self.assertEqual(excluded, ["HW-SEC-001", "RPI-OTP-002"])

    def test_gate_accounting_reports_every_high_candidate_and_reason(self):
        report = self._gate_report()
        accounting = ggfw.build_gate_accounting(report, "HIGH")
        self.assertEqual(accounting["threshold_candidate_count"], 3)
        self.assertEqual(accounting["matching_rules"], ["RPI-SPI-WP-001"])
        self.assertEqual(accounting["excluded_rules"], ["HW-SEC-001", "RPI-OTP-002"])
        excluded = {item["rule_id"]: item for item in accounting["excluded_findings"]}
        self.assertEqual(
            excluded["HW-SEC-001"]["exclusion_reasons"],
            ["AGGREGATE", "COVERAGE_GAP"],
        )
        self.assertEqual(
            excluded["RPI-OTP-002"]["exclusion_reasons"],
            ["COVERAGE_GAP"],
        )
        self.assertTrue(accounting["accounting_invariant"]["satisfied"])

    def test_gate_accounting_terminal_lists_aggregate_and_coverage_reasons(self):
        report = self._gate_report()
        accounting = ggfw.build_gate_accounting(report, "HIGH")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ggfw.print_gate_accounting("HIGH", 2, accounting, [])
        rendered = output.getvalue()
        self.assertIn("Gate accounting: candidates=3, matched=1, excluded=2", rendered)
        self.assertIn("HW-SEC-001 HIGH", rendered)
        self.assertIn("reasons=AGGREGATE,COVERAGE_GAP", rendered)
        self.assertIn("RPI-OTP-002 HIGH", rendered)
        self.assertIn("reasons=COVERAGE_GAP", rendered)
        self.assertIn("Gate accounting invariant: PASS", rendered)

    def test_required_secure_boot_rollup_cannot_be_not_required(self):
        report = ggfw.GGFWReport(policy_profile="secure-boot-required")
        report.add_finding(ggfw.Finding(
            rule_id="RPI-SB-001", severity="HIGH", category="BOOT",
            description="policy failed", evidence="missing controls", remediation="fix",
            finding_class="POLICY_FAILURE", actionable=True,
        ))
        report.add_finding(ggfw.Finding(
            rule_id="RPI-OTP-002", severity="HIGH", category="HARDWARE",
            description="evidence gap", evidence="unknown", remediation="collect",
            coverage_gap=True, finding_class="COVERAGE_GAP",
            remediation_group="SECURE_BOOT_ENABLEMENT",
        ))
        rollup = ggfw.build_secure_boot_policy_rollup(
            report, "secure-boot-required", {"policy": "NOT_REQUIRED"}
        )
        self.assertEqual(rollup["result"], "FAIL")
        self.assertEqual(rollup["primary_finding"], "RPI-SB-001")
        self.assertEqual(rollup["evidence_limitations"], ["RPI-OTP-002"])
        self.assertTrue(
            rollup["invariants"]["required_profile_with_policy_finding_is_fail"]
        )

    def test_required_policy_rollup_prints_fail(self):
        rollup = {
            "result": "FAIL",
            "primary_finding": "RPI-SB-001",
            "evidence_limitations": ["RPI-OTP-002"],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ggfw.print_secure_boot_policy_rollup(rollup, "secure-boot-required")
        rendered = output.getvalue()
        self.assertIn("Secure Boot policy: FAIL", rendered)
        self.assertNotIn("NOT_REQUIRED", rendered)
        self.assertIn("Primary policy finding: RPI-SB-001", rendered)

    def test_finding_count_values_share_one_column(self):
        report = self._gate_report()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ggfw.print_scan_summary(report)
        lines = output.getvalue().splitlines()
        labels = [
            "Total findings:",
            "Actionable security/policy findings:",
            "Evidence acquisition required:",
            "Aggregate rollups:",
            "Other non-actionable findings:",
        ]
        # Compare the index of the final numeric token in every top-level row.
        numeric_columns = [
            next(i for i, ch in enumerate(line) if i > line.index(':') and ch.isdigit())
            for line in [next(item for item in lines if label in item) for label in labels]
        ]
        self.assertEqual(len(set(numeric_columns)), 1)

    def test_evidence_summary_uses_singular_finding(self):
        report = ggfw.GGFWReport(policy_profile="secure-boot-required")
        report.add_finding(ggfw.Finding(
            rule_id="RPI-OTP-002", severity="HIGH", category="HARDWARE",
            description="evidence gap", evidence="unknown", remediation="collect",
            coverage_gap=True, finding_class="COVERAGE_GAP",
            remediation_group="SECURE_BOOT_ENABLEMENT",
        ))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ggfw.print_remediation_summary(report)
        self.assertIn("EVIDENCE: 1 finding / 1 acquisition task", output.getvalue())

    def test_policy_not_required_is_counted_cross_cutting(self):
        report = ggfw.GGFWReport(policy_profile="default")
        report.add_finding(ggfw.Finding(
            rule_id="RPI-EEPROM-AB-000", severity="INFO", category="HARDWARE",
            description="ab unknown", evidence="unknown", remediation="none",
            coverage_gap=True, finding_class="CAPABILITY_GAP",
        ))
        report.calculate_summary()
        self.assertEqual(report.summary["policy_not_required_only"], 0)
        self.assertEqual(report.summary["policy_not_required_total"], 1)
        self.assertEqual(report.summary["multi_attribute_passive"], 1)


    def test_summary_accounting_invariants_pass_for_normal_report(self):
        report = self._gate_report()
        report.calculate_summary()
        accounting = report.summary["summary_accounting"]
        self.assertTrue(accounting["all_invariants_satisfied"])
        self.assertEqual(accounting["failures"], [])
        self.assertEqual(
            accounting["top_level_partition"]["actual"],
            accounting["top_level_partition"]["expected"],
        )
        self.assertEqual(
            accounting["severity_partition"]["actual"],
            accounting["severity_partition"]["expected"],
        )

    def test_accounting_invariant_with_coverage_not_required_and_aggregate(self):
        report = ggfw.GGFWReport(policy_profile="default")
        report.add_finding(ggfw.Finding(
            rule_id="TEST-MULTI-001", severity="HIGH", category="HARDWARE",
            description="synthetic multi-attribute finding", evidence="fixture",
            remediation="none", coverage_gap=True, aggregate=True,
            applicability="NOT_REQUIRED", finding_class="COVERAGE_GAP",
        ))
        report.calculate_summary()
        summary = report.summary
        accounting = summary["summary_accounting"]
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["aggregate_rollups"], 1)
        self.assertEqual(summary["other_non_actionable"], 0)
        self.assertEqual(summary["coverage_gaps_total"], 1)
        self.assertEqual(summary["policy_not_required_total"], 1)
        self.assertEqual(summary["aggregate_findings_total"], 1)
        self.assertEqual(
            accounting["top_level_partition"]["bucket_rule_ids"]["aggregate_rollups"],
            ["TEST-MULTI-001"],
        )
        self.assertEqual(accounting["passive_partition"]["expected"], 0)
        self.assertTrue(accounting["all_invariants_satisfied"])

    def test_summary_validator_recomputes_and_rejects_corrupted_partition(self):
        report = self._gate_report()
        report.calculate_summary()
        accounting = json.loads(json.dumps(report.summary["summary_accounting"]))
        accounting["top_level_partition"]["actual"] -= 1
        accounting["top_level_partition"]["satisfied"] = True
        accounting["failures"] = []
        accounting["all_invariants_satisfied"] = True
        with self.assertRaises(ggfw.SummaryInvariantError):
            ggfw.validate_summary_invariants(accounting)
        self.assertFalse(accounting["all_invariants_satisfied"])
        self.assertIn("top_level_partition", accounting["failures"])

    def test_summary_accounting_is_serialized_and_printed(self):
        report = self._gate_report()
        payload = report.to_dict()
        self.assertIn("summary_accounting", payload["summary"])
        self.assertTrue(payload["summary"]["summary_accounting"]["all_invariants_satisfied"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ggfw.print_scan_summary(report)
        self.assertIn("Summary accounting invariant: PASS", output.getvalue())

    def test_missing_cross_cutting_overall_counter_is_rejected(self):
        report = self._gate_report()
        report.calculate_summary()
        accounting = json.loads(json.dumps(report.summary["summary_accounting"]))
        del accounting["cross_cutting_overall"]["policy_not_required_overall"]
        with self.assertRaises(ggfw.SummaryInvariantError):
            ggfw.validate_summary_invariants(accounting)
        self.assertIn(
            "cross_cutting_overall.policy_not_required_overall",
            accounting["failures"],
        )

    def test_domain_severity_subpartition_is_enforced(self):
        report = self._gate_report()
        report.calculate_summary()
        accounting = json.loads(json.dumps(report.summary["summary_accounting"]))
        domain = next(iter(accounting["domain_severity_partitions"]))
        accounting["domain_severity_partitions"][domain]["actual"] -= 1
        with self.assertRaises(ggfw.SummaryInvariantError):
            ggfw.validate_summary_invariants(accounting)
        self.assertIn(
            f"domain_severity_partitions.{domain}", accounting["failures"]
        )

    def test_summary_invariant_failure_maps_to_tool_error_exit_one(self):
        original = ggfw.run_audit
        ggfw.run_audit = lambda: (_ for _ in ()).throw(
            ggfw.SummaryInvariantError("top_level_partition(expected=2, actual=1)")
        )
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                code = ggfw.main()
        finally:
            ggfw.run_audit = original
        self.assertEqual(code, 1)
        rendered = stderr.getvalue()
        self.assertIn("Summary accounting invariant failed", rendered)
        self.assertIn("Process exit classification: TOOL_ERROR", rendered)
        self.assertIn("Process exit code: 1", rendered)

    def test_duplicate_rule_ids_fail_summary_accounting(self):
        report = ggfw.GGFWReport()
        for _ in range(2):
            report.add_finding(ggfw.Finding(
                rule_id="TEST-DUP-001", severity="INFO", category="TOOLING",
                description="duplicate", evidence="fixture", remediation="none",
            ))
        with self.assertRaises(ggfw.SummaryInvariantError):
            report.calculate_summary()

    def test_findings_are_sorted_by_severity_then_rule_id(self):
        findings = [
            ggfw.Finding("Z-INFO", "INFO", "BOOT", "i", "i", "i"),
            ggfw.Finding("B-HIGH", "HIGH", "BOOT", "h", "h", "h"),
            ggfw.Finding("A-HIGH", "HIGH", "BOOT", "h", "h", "h"),
            ggfw.Finding("C-CRIT", "CRITICAL", "BOOT", "c", "c", "c"),
        ]
        ordered = ggfw.sort_findings_for_display(findings)
        self.assertEqual([item.rule_id for item in ordered], [
            "C-CRIT", "A-HIGH", "B-HIGH", "Z-INFO",
        ])

    def test_crypto_self_test_known_answers_pass(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = ggfw.run_crypto_self_test()
        self.assertEqual(code, 0)
        rendered = output.getvalue()
        self.assertIn("valid boot.img signature: VALID", rendered)
        self.assertIn("tampered boot.img: INVALID", rendered)
        self.assertIn("valid BCM2712 bootsys trailer: VALID", rendered)

    def test_dynamic_tool_version_in_secure_boot_rationale(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report = ggfw.GGFWReport(
                target_path=temp_dir,
                platform_guess="Raspberry Pi 5 (BCM2712)",
                policy_profile="secure-boot-required",
            )
            engine = ggfw.HardwarePolicyEngine(
                platform="Raspberry Pi 5 (BCM2712)",
                otp={"22": "00000000"},
                eeprom_conf="[all]\n",
                report=report,
                otp_tool_available=True,
                otp_metadata_bundle=ggfw.load_rpiboot_metadata(None),
            )
            engine.run_all_checks()
            aggregate = next(f for f in report.findings if f.rule_id == "HW-SEC-001")
            self.assertIn(ggfw.TOOL_VERSION_DISPLAY, aggregate.rationale)
            self.assertNotIn("0.5.7", aggregate.rationale)


class EvidencePackageTests(unittest.TestCase):
    def test_ggcap_contains_secure_boot_validation_and_key(self):
        with tempfile.TemporaryDirectory(prefix='ggcap060-') as temp_dir:
            root = Path(temp_dir)
            boot = root / 'boot'
            boot.mkdir()
            (boot / 'config.txt').write_text('[all]\n', encoding='ascii')
            (boot / 'cmdline.txt').write_text('console=serial0,115200\n', encoding='ascii')
            report = ggfw.GGFWReport(
                target_path=str(boot),
                platform_guess='Raspberry Pi 5 (BCM2712)',
                scan_id='fixture-060',
                policy_profile='secure-boot-required',
            )
            private_key = root / 'package-private.pem'
            public_key = root / 'package-public.pem'
            run_checked(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(private_key)])
            run_checked(['openssl', 'pkey', '-in', str(private_key), '-pubout', '-out', str(public_key)])
            key = ggfw.parse_pem_rsa_public_key(str(public_key))
            report.raw_artifacts.update({
                'secure_boot_validation': {
                    'schema': ggfw.SECURE_BOOT_VALIDATION_SCHEMA,
                    'overall': 'PASS',
                    'eeprom': {'pubkey_bin_hex': key.to_pubkey_bin().hex()},
                },
                'secure_boot_evidence': {'overall': 'PASS'},
                'otp_raw': {},
                'otp_decoded': {},
                'otp_decoder_metadata': {},
                'otp_metadata': {},
                'tool_metadata': {},
                'eeprom_config': '',
                'evidence_model': {},
            })
            report.execution = {
                'status': 'COMPLETED',
                'classification': 'SUCCESS',
                'exit_code': 0,
                'secure_boot_public_key': str(public_key),
            }
            report.calculate_summary()
            builder = ggfw.EvidencePackageBuilder(str(root / 'evidence'), 'fixture-060')
            builder.collect(report, str(boot), {'parsed_files': [str(boot / 'config.txt')]}, None, None)
            package = root / 'fixture.ggcap'
            result = builder.finalise(report, str(package))
            self.assertTrue(package.is_file())
            self.assertEqual(result['package_sha256'], ggfw.sha256_file(str(package)))
            import zipfile
            with zipfile.ZipFile(package) as archive:
                names = set(archive.namelist())
                self.assertIn('evidence/boot/secure-boot-validation.json', names)
                self.assertIn('evidence/boot/secure-boot-evidence.json', names)
                self.assertIn('evidence/boot/customer-public-key.pem', names)
                self.assertIn('evidence/spi/pubkey.bin', names)
                self.assertIn('README.txt', names)
                payload = json.loads(archive.read('evidence/boot/secure-boot-validation.json'))
                self.assertEqual(payload['overall'], 'PASS')


if __name__ == '__main__':
    unittest.main(verbosity=2)
