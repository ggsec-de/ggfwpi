"""GGFW Raspberry Pi security auditor public API."""
from .constants import (
    EVIDENCE_SCHEMA,
    OTP_DECODER_SCHEMA,
    REASON_ARTIFACT_NOT_FOUND,
    REASON_CRYPTOGRAPHIC_MISMATCH,
    REASON_FORMAT_INVALID,
    REASON_FRESHNESS_POLICY_FAILURE,
    REASON_IO_ERROR,
    REASON_KEY_MISMATCH,
    REASON_KEY_UNAVAILABLE,
    REASON_NONE,
    REASON_OTP_BINDING_UNAVAILABLE,
    REASON_SIGNATURE_NOT_PRESENT,
    REASON_TARGET_SOC_MISMATCH,
    REPORT_SCHEMA,
    SECURE_BOOT_EVIDENCE_SCHEMA,
    SECURE_BOOT_VALIDATION_SCHEMA,
    TOOL_VERSION,
    TOOL_VERSION_DISPLAY,
    VALIDATION_INVALID,
    VALIDATION_UNVERIFIED,
    VALIDATION_VALID,
)
from .errors import GGFWRuntimeError, SummaryInvariantError
from .files import sha256_file
from .system.passwords import (
    BUILTIN_WEAK_PASSWORDS, MAX_WEAK_PASSWORD_BYTES, MAX_WEAK_PASSWORD_FILE_BYTES,
    load_weak_password_dictionary,
)
from .models.findings import Finding
from .models.report import GGFWReport, validate_summary_invariants
from .parsers.eeprom_image import (
    RaspberryPiEEPROMImage, RPI_EEPROM_FILENAME_LEN, RPI_EEPROM_FILE_MAGIC, RPI_EEPROM_MAGIC,
)
from .hardware.otp import decode_otp_state, load_rpiboot_metadata
from .crypto.rsa import (
    CRYPTOGRAPHY_AVAILABLE, RSAPublicKeyMaterial, RSAVerificationResult, SecureBootFormatError,
    _der_read_length, _parse_rsa_public_key_der,
    _rsa_pkcs1_v15_sha256_verify_digest_builtin,
    _rsa_pkcs1_v15_sha256_verify_digest_cryptography,
    parse_pem_rsa_public_key, parse_rpi_pubkey_bin,
    rsa_pkcs1_v15_sha256_verify_digest_result,
)
from .crypto.signatures import validate_rpi_signed_file
from .crypto.validation import (
    build_secure_boot_evidence, validate_secure_boot_chain, verify_bcm2712_customer_signed_blob,
)
from .crypto.kat import (
    CRYPTO_KAT_BOOT_IMAGE, CRYPTO_KAT_BOOT_SIGNATURE, CRYPTO_KAT_RSA_EXPONENT,
    CRYPTO_KAT_RSA_MODULUS, _crypto_kat_signature_text, run_crypto_self_test,
)
from .engines.host_policy import (
    FATPolicyEngine, HostPolicyEngine, _wildcard_listener_pids, detect_dual_use_shell_exec,
)
from .engines.hardware_policy import HardwarePolicyEngine
from .packaging.ggcap import EvidencePackageBuilder
from .reporting.console import (
    print_otp_summary, print_remediation_summary, print_scan_summary, sort_findings_for_display,
)
from .reporting.gates import (
    build_gate_accounting, build_secure_boot_policy_rollup, evaluate_fail_policy,
    print_gate_accounting, print_secure_boot_policy_rollup,
)
from .audit import run_audit
from .cli import execute_main as _execute_main

def main() -> int:
    return _execute_main(run_audit)

__all__ = [name for name in globals() if not name.startswith('_')]
