"""Extracted GGFW component: crypto.validation."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, hashlib, re, struct, tempfile,
)
from ggfw.constants import REASON_ARTIFACT_NOT_FOUND, REASON_CRYPTOGRAPHIC_MISMATCH, REASON_FORMAT_INVALID, REASON_KEY_MISMATCH, REASON_KEY_UNAVAILABLE, REASON_NONE, REASON_OTP_BINDING_UNAVAILABLE, REASON_SIGNATURE_NOT_PRESENT, SECURE_BOOT_EVIDENCE_SCHEMA, SECURE_BOOT_VALIDATION_SCHEMA, TOOL_VERSION, VALIDATION_INVALID, VALIDATION_UNVERIFIED, VALIDATION_VALID
from ggfw.crypto.rsa import RPI_PUBLIC_KEY_BIN_SIZE, RSA2048_SIGNATURE_SIZE, RSAPublicKeyMaterial, SecureBootFormatError, parse_pem_rsa_public_key, parse_rpi_pubkey_bin, rsa_pkcs1_v15_sha256_verify_result
from ggfw.crypto.signatures import validate_rpi_signed_file
from ggfw.hardware.otp import OFFICIAL_OTP_REFERENCES
from ggfw.hardware.platform import get_soc_generation
from ggfw.parsers.eeprom_image import RaspberryPiEEPROMImage

def _normalise_sha256(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', value).lower()
    return cleaned if len(cleaned) == 64 else None

def _otp_hash_candidates(decoded: Dict[str, Any], metadata_bundle: Dict[str, Any]) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []
    metadata_hash = _normalise_sha256(metadata_bundle.get('metadata', {}).get('CUSTOMER_KEY_HASH'))
    if metadata_hash:
        candidates.append({'value': metadata_hash, 'encoding': 'RPIBOOT_METADATA', 'source': 'rpiboot -j'})
    decoded_hash = _normalise_sha256(
        decoded.get('security', {}).get('customer_key_hash', {}).get('value')
    )
    if decoded_hash:
        raw = bytes.fromhex(decoded_hash)
        variants = {
            'OTP_DECODED_DIRECT': raw.hex(),
            'OTP_DECODED_REVERSE_ALL': raw[::-1].hex(),
            'OTP_DECODED_REVERSE_BYTES_PER_WORD': b''.join(
                raw[index:index + 4][::-1] for index in range(0, 32, 4)
            ).hex(),
            'OTP_DECODED_REVERSE_WORD_ORDER': b''.join(
                raw[index:index + 4] for index in range(28, -1, -4)
            ).hex(),
        }
        for encoding, value in variants.items():
            if not any(item['value'] == value for item in candidates):
                candidates.append({'value': value, 'encoding': encoding, 'source': 'decoded OTP'})
    return candidates

def verify_bcm2712_customer_signed_blob(
    blob: bytes,
    expected_key: Optional[RSAPublicKeyMaterial],
    source: str,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'source': source,
        'format': 'RPI_SIGN_BOOTCODE_2712_CUSTOMER_TRAILER_V1',
        'overall': VALIDATION_UNVERIFIED,
        'reason_code': REASON_SIGNATURE_NOT_PRESENT,
        'reason_codes': [REASON_SIGNATURE_NOT_PRESENT],
        'signature_status': 'NOT_VERIFIED',
        'public_key_status': 'NOT_VERIFIED',
        'key_number': None,
        'private_version': None,
        'declared_input_length': None,
        'actual_input_length': None,
        'length_status': 'NOT_VERIFIED',
        'cryptographic_verification_performed': False,
        'errors': [],
    }
    trailer_size = 12 + RSA2048_SIGNATURE_SIZE + RPI_PUBLIC_KEY_BIN_SIZE
    if len(blob) < trailer_size:
        result['errors'].append('bootsys does not contain a complete BCM2712 customer-signing trailer')
        return result

    signature_start = len(blob) - (RSA2048_SIGNATURE_SIZE + RPI_PUBLIC_KEY_BIN_SIZE)
    metadata_start = signature_start - 12
    signed_prefix = blob[:signature_start]
    input_blob = blob[:metadata_start]
    declared_length, key_number, private_version = struct.unpack_from('<III', blob, metadata_start)
    signature = blob[signature_start:signature_start + RSA2048_SIGNATURE_SIZE]
    pubkey_bytes = blob[-RPI_PUBLIC_KEY_BIN_SIZE:]
    result.update({
        'declared_input_length': declared_length,
        'actual_input_length': len(input_blob),
        'key_number': key_number,
        'private_version': private_version,
        'signed_prefix_sha256': hashlib.sha256(signed_prefix).hexdigest(),
        'input_sha256': hashlib.sha256(input_blob).hexdigest(),
        'signature_sha256': hashlib.sha256(signature).hexdigest(),
        'embedded_pubkey_sha256': hashlib.sha256(pubkey_bytes).hexdigest(),
    })

    # The trailer has no magic. A key number other than 16 is treated conservatively
    # as absence of a customer trailer rather than proof of an invalid signature.
    if key_number != 16:
        result['errors'].append(f'No recognised customer trailer: key number is {key_number}, expected 16')
        return result

    result['length_status'] = 'MATCH' if declared_length == len(input_blob) else 'MISMATCH'
    if result['length_status'] == 'MISMATCH' or private_version > 32:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        if result['length_status'] == 'MISMATCH':
            result['errors'].append('Embedded input-length field does not match parsed input length')
        if private_version > 32:
            result['errors'].append(f'Private version outside documented range: {private_version}')
        return result

    try:
        trailer_key = parse_rpi_pubkey_bin(pubkey_bytes, f'{source}:customer-trailer')
        result['trailer_key'] = trailer_key.summary()
    except SecureBootFormatError as exc:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        result['errors'].append(str(exc))
        return result

    if expected_key is None:
        result['public_key_status'] = 'KEY_UNAVAILABLE'
        verification_key = trailer_key
    elif trailer_key.to_pubkey_bin() == expected_key.to_pubkey_bin():
        result['public_key_status'] = 'MATCH'
        verification_key = expected_key
    else:
        result['public_key_status'] = 'MISMATCH'
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_KEY_MISMATCH
        result['reason_codes'] = [REASON_KEY_MISMATCH]
        return result

    result['cryptographic_verification_performed'] = True
    verification = rsa_pkcs1_v15_sha256_verify_result(
        signed_prefix, signature, verification_key
    )
    result['verification_backend'] = verification.backend
    result['signature_status'] = 'VERIFIED' if verification.valid else 'INVALID'
    if verification.error:
        result['verification_backend_error'] = verification.error
        result['errors'].append(f'RSA verification backend failure: {verification.error}')
    if not verification.valid:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_CRYPTOGRAPHIC_MISMATCH
        result['reason_codes'] = [REASON_CRYPTOGRAPHIC_MISMATCH]
    elif expected_key is None:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_KEY_UNAVAILABLE
        result['reason_codes'] = [REASON_KEY_UNAVAILABLE]
        result['signature_status'] = 'VERIFIED_EMBEDDED_KEY_UNBOUND'
    else:
        result['overall'] = VALIDATION_VALID
        result['reason_code'] = REASON_NONE
        result['reason_codes'] = []
    return result

def validate_secure_boot_chain(
    platform_name: str,
    boot_root: Path,
    spi_image_path: Optional[str],
    public_key_path: Optional[str],
    decoded: Dict[str, Any],
    metadata_bundle: Dict[str, Any],
    max_signature_age_days: Optional[int] = None,
    supplied_key_material: Optional[RSAPublicKeyMaterial] = None,
) -> Dict[str, Any]:
    soc = get_soc_generation(platform_name)
    result: Dict[str, Any] = {
        'schema': SECURE_BOOT_VALIDATION_SCHEMA,
        'tool_version': TOOL_VERSION,
        'platform': platform_name,
        'soc': soc,
        'public_key': {
            'supplied_path': str(Path(public_key_path).expanduser().resolve()) if public_key_path else None,
            'supplied_status': 'NOT_SUPPLIED',
            'eeprom_status': 'NOT_AVAILABLE',
            'source_relationship': 'UNAVAILABLE',
            'otp_binding': 'UNVERIFIED',
            'otp_binding_reason_code': REASON_OTP_BINDING_UNAVAILABLE,
            'otp_hash_candidates': [],
        },
        'eeprom': {'status': 'NOT_AVAILABLE'},
        'bootconf_signature': {
            'overall': VALIDATION_UNVERIFIED, 'reason_code': REASON_ARTIFACT_NOT_FOUND,
            'reason_codes': [REASON_ARTIFACT_NOT_FOUND],
        },
        'boot_image_signature': {
            'overall': VALIDATION_UNVERIFIED, 'reason_code': REASON_ARTIFACT_NOT_FOUND,
            'reason_codes': [REASON_ARTIFACT_NOT_FOUND],
        },
        'bootsys_customer_countersignature': (
            {'overall': 'NOT_APPLICABLE', 'reason_code': REASON_NONE, 'reason_codes': []}
            if soc != 'BCM2712' else
            {'overall': VALIDATION_UNVERIFIED, 'reason_code': REASON_ARTIFACT_NOT_FOUND,
             'reason_codes': [REASON_ARTIFACT_NOT_FOUND]}
        ),
        'vendor_bootrom_signature': {
            'status': 'BOOTROM_ENFORCED_NOT_INDEPENDENTLY_REPLAYED',
            'note': 'GGFW validates the customer chain; Raspberry Pi vendor-root signatures are enforced by BootROM but vendor public keys are not replay-verified here.',
        },
        'authenticity': 'UNVERIFIED',
        'completeness': 'INCOMPLETE',
        'freshness': 'NOT_ASSESSED',
        'overall': 'UNVERIFIED',
        'coverage_gap': True,
        'errors': [],
        'references': OFFICIAL_OTP_REFERENCES,
    }

    supplied_key: Optional[RSAPublicKeyMaterial] = supplied_key_material
    if supplied_key is not None:
        result['public_key']['supplied_status'] = 'PARSED'
        result['public_key']['supplied'] = supplied_key.summary()
    elif public_key_path:
        try:
            supplied_key = parse_pem_rsa_public_key(public_key_path)
            result['public_key']['supplied_status'] = 'PARSED'
            result['public_key']['supplied'] = supplied_key.summary()
        except (OSError, SecureBootFormatError) as exc:
            # CLI preflight prevents this path for explicit inputs. Direct callers receive
            # an UNVERIFIED result rather than a false signature failure.
            result['public_key']['supplied_status'] = 'INVALID_INPUT'
            result['public_key']['error'] = str(exc)
            result['errors'].append(f'Public key input: {exc}')

    eeprom_key: Optional[RSAPublicKeyMaterial] = None
    image: Optional[RaspberryPiEEPROMImage] = None
    if spi_image_path and Path(spi_image_path).is_file():
        try:
            image = RaspberryPiEEPROMImage(spi_image_path)
            result['eeprom'] = image.summary()
            result['eeprom']['status'] = 'PARSED' if not image.errors else 'PARTIAL'
            pubkey_blobs = image.get_all('pubkey.bin')
            result['eeprom']['pubkey_count'] = len(pubkey_blobs)
            if pubkey_blobs:
                parsed_keys: List[RSAPublicKeyMaterial] = []
                key_entries: List[Dict[str, Any]] = []
                for index, pubkey_bytes in enumerate(pubkey_blobs):
                    parsed_key = parse_rpi_pubkey_bin(pubkey_bytes, f'{spi_image_path}:pubkey.bin[{index}]')
                    parsed_keys.append(parsed_key)
                    key_entries.append({
                        'index': index,
                        'sha256': hashlib.sha256(pubkey_bytes).hexdigest(),
                        'key': parsed_key.summary(),
                    })
                result['eeprom']['pubkey_entries'] = key_entries
                canonical = parsed_keys[0].to_pubkey_bin()
                if all(key.to_pubkey_bin() == canonical for key in parsed_keys[1:]):
                    eeprom_key = parsed_keys[0]
                    result['eeprom']['pubkey_bin_hex'] = canonical.hex()
                    result['public_key']['eeprom_status'] = 'PARSED'
                    result['public_key']['eeprom_consistency'] = 'CONSISTENT'
                    result['public_key']['eeprom'] = eeprom_key.summary()
                else:
                    result['public_key']['eeprom_status'] = 'INCONSISTENT'
                    result['public_key']['eeprom_consistency'] = 'MISMATCH'
                    result['errors'].append('Multiple EEPROM pubkey.bin entries are not identical')
            else:
                result['public_key']['eeprom_status'] = 'ABSENT'
                result['public_key']['eeprom_consistency'] = 'NOT_AVAILABLE'
        except (OSError, SecureBootFormatError, struct.error) as exc:
            result['eeprom'] = {'status': 'FAILED', 'path': spi_image_path, 'error': str(exc)}
            result['errors'].append(f'EEPROM parse: {exc}')

    selected_key: Optional[RSAPublicKeyMaterial] = None
    if result['public_key'].get('eeprom_status') == 'INCONSISTENT':
        result['public_key']['source_relationship'] = 'EEPROM_KEYS_INCONSISTENT'
        selected_key = supplied_key
    elif supplied_key and eeprom_key:
        if supplied_key.to_pubkey_bin() == eeprom_key.to_pubkey_bin():
            result['public_key']['source_relationship'] = 'SUPPLIED_MATCHES_EEPROM'
            selected_key = supplied_key
        else:
            result['public_key']['source_relationship'] = 'SUPPLIED_MISMATCHES_EEPROM'
            selected_key = supplied_key
    elif supplied_key:
        result['public_key']['source_relationship'] = 'SUPPLIED_ONLY'
        selected_key = supplied_key
    elif eeprom_key:
        result['public_key']['source_relationship'] = 'EEPROM_ONLY'
        selected_key = eeprom_key

    candidates = _otp_hash_candidates(decoded, metadata_bundle)
    result['public_key']['otp_hash_candidates'] = candidates
    if selected_key and candidates:
        fingerprint = selected_key.fingerprint()
        result['public_key']['computed_pubkey_bin_sha256'] = fingerprint
        matches = [candidate for candidate in candidates if candidate['value'] == fingerprint]
        if matches:
            result['public_key']['otp_binding'] = 'MATCH'
            result['public_key']['otp_binding_reason_code'] = REASON_NONE
            result['public_key']['otp_binding_matches'] = matches
        else:
            result['public_key']['otp_binding'] = 'MISMATCH'
            result['public_key']['otp_binding_reason_code'] = REASON_KEY_MISMATCH
    elif selected_key:
        result['public_key']['otp_binding'] = 'HASH_UNAVAILABLE'
        result['public_key']['otp_binding_reason_code'] = REASON_OTP_BINDING_UNAVAILABLE
    elif candidates:
        result['public_key']['otp_binding'] = 'PUBLIC_KEY_UNAVAILABLE'
        result['public_key']['otp_binding_reason_code'] = REASON_KEY_UNAVAILABLE
    else:
        result['public_key']['otp_binding'] = 'UNVERIFIED'
        result['public_key']['otp_binding_reason_code'] = REASON_OTP_BINDING_UNAVAILABLE

    expected_soc = '2712' if soc == 'BCM2712' else ('2711' if soc == 'BCM2711' else None)
    result['boot_image_signature'] = validate_rpi_signed_file(
        boot_root / 'boot.img', boot_root / 'boot.sig', selected_key,
        expected_soc=expected_soc, max_age_days=max_signature_age_days,
    )

    if image is not None:
        bootconfs = image.get_all('bootconf.txt')
        bootconf_sigs = image.get_all('bootconf.sig')
        if bootconfs and len(bootconfs) == len(bootconf_sigs):
            entries: List[Dict[str, Any]] = []
            with tempfile.TemporaryDirectory(prefix='ggfw-sb-') as tmp:
                tmp_path = Path(tmp)
                for index, (bootconf, bootconf_sig) in enumerate(zip(bootconfs, bootconf_sigs)):
                    conf_path = tmp_path / f'bootconf-{index}.txt'
                    sig_path = tmp_path / f'bootconf-{index}.sig'
                    conf_path.write_bytes(bootconf)
                    sig_path.write_bytes(bootconf_sig)
                    entry = validate_rpi_signed_file(
                        conf_path, sig_path, selected_key, expected_soc=None, max_age_days=None,
                    )
                    entry['index'] = index
                    entry['source'] = f'{spi_image_path}:bootconf[{index}]'
                    entry['bootconf_sha256'] = hashlib.sha256(bootconf).hexdigest()
                    entry['signature_file_sha256'] = hashlib.sha256(bootconf_sig).hexdigest()
                    entries.append(entry)
            statuses = {entry.get('overall') for entry in entries}
            if statuses == {VALIDATION_VALID}:
                overall = VALIDATION_VALID
                reason_code = REASON_NONE
            elif VALIDATION_INVALID in statuses:
                overall = VALIDATION_INVALID
                invalid_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_INVALID)
                reason_code = invalid_entry.get('reason_code', REASON_CRYPTOGRAPHIC_MISMATCH)
            else:
                overall = VALIDATION_UNVERIFIED
                unverified_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_UNVERIFIED)
                reason_code = unverified_entry.get('reason_code', REASON_KEY_UNAVAILABLE)
            result['bootconf_signature'] = {
                'overall': overall,
                'reason_code': reason_code,
                'reason_codes': list(dict.fromkeys(
                    code for entry in entries for code in entry.get('reason_codes', [])
                )),
                'entry_count': len(entries),
                'section_present_count': len(entries),
                'effective_signature_present_count': sum(
                    bool(entry.get('effective_signature_present')) for entry in entries
                ),
                'content_classes': [
                    entry.get('signature_content', {}).get('content_class', 'UNKNOWN')
                    for entry in entries
                ],
                'entries': entries,
            }
        elif bootconfs or bootconf_sigs:
            reason = REASON_SIGNATURE_NOT_PRESENT if len(bootconfs) > len(bootconf_sigs) else REASON_ARTIFACT_NOT_FOUND
            result['bootconf_signature'] = {
                'overall': VALIDATION_UNVERIFIED,
                'reason_code': reason,
                'reason_codes': [reason],
                'bootconf_count': len(bootconfs),
                'bootconf_sig_count': len(bootconf_sigs),
                'section_present_count': len(bootconf_sigs),
                'effective_signature_present_count': 0,
                'content_classes': [],
                'error': 'The number of bootconf.txt and bootconf.sig entries differs',
            }

        if soc == 'BCM2712':
            bootsys_blobs = image.get_all('bootsys')
            if bootsys_blobs:
                entries = [
                    verify_bcm2712_customer_signed_blob(blob, selected_key, f'{spi_image_path}:bootsys[{index}]')
                    for index, blob in enumerate(bootsys_blobs)
                ]
                statuses = {entry.get('overall') for entry in entries}
                if statuses == {VALIDATION_VALID}:
                    overall = VALIDATION_VALID
                    reason_code = REASON_NONE
                elif VALIDATION_INVALID in statuses:
                    overall = VALIDATION_INVALID
                    invalid_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_INVALID)
                    reason_code = invalid_entry.get('reason_code', REASON_CRYPTOGRAPHIC_MISMATCH)
                else:
                    overall = VALIDATION_UNVERIFIED
                    unverified_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_UNVERIFIED)
                    reason_code = unverified_entry.get('reason_code', REASON_KEY_UNAVAILABLE)
                result['bootsys_customer_countersignature'] = {
                    'overall': overall,
                    'reason_code': reason_code,
                    'reason_codes': list(dict.fromkeys(
                        code for entry in entries for code in entry.get('reason_codes', [])
                    )),
                    'entries': entries,
                }

    enable_status = decoded.get('security', {}).get('secure_boot_enablement', {}).get('status', 'UNKNOWN')
    components = {
        'secure_boot_enablement': enable_status,
        'key_relationship': result['public_key']['source_relationship'],
        'otp_binding': result['public_key']['otp_binding'],
        'bootconf': result['bootconf_signature'].get('overall'),
        'boot_image': result['boot_image_signature'].get('overall'),
        'bootsys': result['bootsys_customer_countersignature'].get('overall'),
    }
    result['components'] = components
    failure_values = {
        'SUPPLIED_MISMATCHES_EEPROM', 'EEPROM_KEYS_INCONSISTENT', 'MISMATCH', VALIDATION_INVALID,
        'DISABLED', 'UNPROGRAMMED',
    }
    confirmed_failure = any(value in failure_values for value in components.values())
    bootsys_ok = (
        components['bootsys'] == VALIDATION_VALID if soc == 'BCM2712'
        else components['bootsys'] == 'NOT_APPLICABLE'
    )
    freshness = result['boot_image_signature'].get('freshness_status', 'NOT_ASSESSED')
    freshness_conclusive = freshness in {'WITHIN_POLICY', 'TIMESTAMP_VALID_NO_MAX_AGE_POLICY'}
    full_customer_chain = (
        components['secure_boot_enablement'] in {'ENABLED', 'PROVISIONED'}
        and components['otp_binding'] == 'MATCH'
        and components['bootconf'] == VALIDATION_VALID
        and components['boot_image'] == VALIDATION_VALID
        and bootsys_ok
        and components['key_relationship'] != 'SUPPLIED_MISMATCHES_EEPROM'
        and freshness_conclusive
    )

    result['freshness'] = freshness
    if confirmed_failure:
        result['authenticity'] = 'FAILED'
        result['overall'] = 'FAIL'
        result['coverage_gap'] = False
    elif full_customer_chain:
        result['authenticity'] = 'VERIFIED_CUSTOMER_CHAIN'
        result['completeness'] = 'SIGNED_CHAIN_COMPLETE'
        result['overall'] = 'PASS'
        result['coverage_gap'] = False
    else:
        verified = sum(value == VALIDATION_VALID for value in components.values())
        result['authenticity'] = 'PARTIALLY_VERIFIED' if verified else 'UNVERIFIED'
        result['completeness'] = 'PARTIAL' if verified else 'INCOMPLETE'
        result['overall'] = 'UNVERIFIED'
        result['coverage_gap'] = True
    result['component_reason_codes'] = {
        'public_key': result['public_key'].get('otp_binding_reason_code'),
        'bootconf': result['bootconf_signature'].get('reason_code'),
        'boot_image': result['boot_image_signature'].get('reason_code'),
        'bootsys': result['bootsys_customer_countersignature'].get('reason_code'),
    }
    return result

def build_secure_boot_evidence(
    platform_name: str, boot_root: Path, decoded: Dict[str, Any], metadata_bundle: Dict[str, Any],
    policy_profile: str, chain_validation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    security = decoded.get("security", {})
    key = security.get("customer_key_hash", {})
    enable = security.get("secure_boot_enablement", {})
    jtag = security.get("vc_jtag_lock", {})
    boot_img_present = (boot_root / "boot.img").is_file()
    boot_sig_present = (boot_root / "boot.sig").is_file()
    key_status = key.get("status", "UNKNOWN")
    enable_status = enable.get("status", "UNKNOWN")
    validation = chain_validation or {
        'schema': SECURE_BOOT_VALIDATION_SCHEMA,
        'overall': 'UNVERIFIED',
        'authenticity': 'UNVERIFIED',
        'completeness': 'INCOMPLETE',
        'freshness': 'NOT_ASSESSED',
        'coverage_gap': True,
        'boot_image_signature': {'overall': 'NOT_VERIFIED'},
        'bootconf_signature': {'overall': 'NOT_VERIFIED'},
        'bootsys_customer_countersignature': {'overall': 'NOT_VERIFIED'},
        'public_key': {'otp_binding': 'UNVERIFIED', 'source_relationship': 'UNAVAILABLE'},
    }

    if boot_img_present and boot_sig_present:
        pair_status = "PRESENT"
    elif boot_img_present or boot_sig_present:
        pair_status = "INCONSISTENT"
    else:
        pair_status = "ABSENT"

    explicitly_not_enforced = enable_status in {"DISABLED", "UNPROGRAMMED"} or key_status == "UNPROGRAMMED"
    validation_overall = validation.get('overall', 'UNVERIFIED')
    if explicitly_not_enforced:
        overall = "DISABLED"
        authenticity = "NOT_ENFORCED"
        coverage_gap = False
    elif pair_status == "INCONSISTENT":
        overall = "INCONSISTENT"
        authenticity = "FAILED"
        coverage_gap = False
    elif validation_overall == 'PASS':
        overall = 'PASS'
        authenticity = validation.get('authenticity', 'VERIFIED_CUSTOMER_CHAIN')
        coverage_gap = False
    elif validation_overall == 'FAIL':
        overall = 'FAIL'
        authenticity = 'FAILED'
        coverage_gap = False
    else:
        overall = "EVIDENCE_INCOMPLETE"
        authenticity = validation.get('authenticity', 'UNVERIFIED')
        coverage_gap = True

    completeness = validation.get('completeness')
    if not completeness or completeness == 'INCOMPLETE':
        completeness = "SIGNED_BUNDLE_PRESENT" if pair_status == "PRESENT" else (
            'SIGNED_BUNDLE_INCONSISTENT' if pair_status == 'INCONSISTENT' else 'SIGNED_BUNDLE_ABSENT'
        )
    freshness = validation.get('freshness', 'NOT_ASSESSED')

    if policy_profile == "secure-boot-required":
        if overall == 'PASS':
            policy = 'PASS'
        elif overall in {'DISABLED', 'INCONSISTENT', 'FAIL'} or pair_status == 'ABSENT':
            policy = 'FAIL'
        else:
            policy = 'UNVERIFIED'
    elif policy_profile == "hardened":
        policy = "PASS" if overall == 'PASS' else "REVIEW"
    else:
        policy = "NOT_REQUIRED"

    return {
        "schema": SECURE_BOOT_EVIDENCE_SCHEMA,
        "platform": platform_name,
        "soc": decoded.get("soc"),
        "decoder_profile": decoded.get("decoder_profile"),
        "decoder_status": decoded.get("decoder_status"),
        "policy_profile": policy_profile,
        "overall": overall,
        "coverage_gap": coverage_gap,
        "authenticity": authenticity,
        "completeness": completeness,
        "freshness": freshness,
        "policy": policy,
        "evidence": {
            "otp_acquisition": "SUCCESS" if decoded.get("raw_word_count", 0) else "FAILED",
            "otp_words_collected": decoded.get("raw_word_count", 0),
            "customer_key_hash": key,
            "secure_boot_enablement": enable,
            "vc_jtag_lock": jtag,
            "boot_img": {"status": "PRESENT" if boot_img_present else "ABSENT", "path": str(boot_root / "boot.img")},
            "boot_sig": {"status": "PRESENT" if boot_sig_present else "ABSENT", "path": str(boot_root / "boot.sig")},
            "eeprom_customer_public_key": validation.get('public_key', {}),
            "bootconf_signature": validation.get('bootconf_signature', {}),
            "bootsys_customer_countersignature": validation.get('bootsys_customer_countersignature', {}),
            "boot_img_signature": validation.get('boot_image_signature', {}),
            "vendor_bootrom_signature": validation.get('vendor_bootrom_signature', {}),
            "rpiboot_metadata": {
                "loaded": bool(metadata_bundle.get("loaded")),
                "files": metadata_bundle.get("files", []),
                "error": metadata_bundle.get("error"),
            },
        },
        "chain_validation": validation,
        "limitations": [
            "Raspberry Pi vendor-root signatures are enforced by BootROM but are not independently replay-verified by GGFW.",
            "BCM2712 customer-key state requires rpiboot metadata because public runtime OTP rows are not documented.",
        ],
        "references": OFFICIAL_OTP_REFERENCES,
    }
