"""Extracted GGFW component: crypto.signatures."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, Tuple, datetime, hashlib, re, timezone,
)
from ggfw.constants import REASON_ARTIFACT_NOT_FOUND, REASON_CRYPTOGRAPHIC_MISMATCH, REASON_FORMAT_INVALID, REASON_FRESHNESS_POLICY_FAILURE, REASON_IO_ERROR, REASON_KEY_UNAVAILABLE, REASON_NONE, REASON_SIGNATURE_NOT_PRESENT, REASON_TARGET_SOC_MISMATCH, VALIDATION_INVALID, VALIDATION_UNVERIFIED, VALIDATION_VALID
from ggfw.crypto.rsa import RSAPublicKeyMaterial, rsa_pkcs1_v15_sha256_verify_digest_result

def parse_rpi_signature_text(content: str, source: str = '') -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'source': source,
        'format': 'RPI_EEPROM_DIGEST_TEXT_V1',
        'digest': None,
        'timestamp': None,
        'target_soc': None,
        'rsa2048_hex': None,
        'unknown_lines': [],
        'errors': [],
    }
    digest_seen = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(r'[0-9a-fA-F]{64}', line):
            if digest_seen:
                result['errors'].append('Duplicate SHA-256 digest line')
            else:
                result['digest'] = line.lower()
                digest_seen = True
            continue
        if line.startswith('ts:'):
            if result['timestamp'] is not None:
                result['errors'].append('Duplicate timestamp line')
            else:
                try:
                    result['timestamp'] = int(line.split(':', 1)[1].strip(), 10)
                except ValueError:
                    result['errors'].append('Invalid timestamp value')
            continue
        if line.startswith('target-soc:'):
            if result['target_soc'] is not None:
                result['errors'].append('Duplicate target-soc line')
            else:
                result['target_soc'] = line.split(':', 1)[1].strip()
            continue
        if line.startswith('rsa2048:'):
            if result['rsa2048_hex'] is not None:
                result['errors'].append('Duplicate rsa2048 line')
            else:
                value = re.sub(r'\s+', '', line.split(':', 1)[1])
                if not re.fullmatch(r'[0-9a-fA-F]{512}', value):
                    result['errors'].append('rsa2048 must contain exactly 256 bytes in hexadecimal')
                else:
                    result['rsa2048_hex'] = value.lower()
            continue
        result['unknown_lines'].append(line)
    if result['digest'] is None:
        result['errors'].append('Missing SHA-256 digest line')
    result['status'] = 'PARSED' if not result['errors'] else 'MALFORMED'
    return result

SIGNATURE_PADDING_BYTES = b'\x00\xff \t\r\n'

def classify_rpi_signature_blob(data: bytes, source: str = '') -> Tuple[Dict[str, Any], Optional[str]]:
    """Classify a Raspberry Pi digest/signature blob before parsing it.

    EEPROM file sections may exist even when their content is erased, zero-filled,
    padded, or contains only an unsigned digest. Those states are evidence gaps,
    not malformed-signature failures.
    """
    raw_size = len(data)
    effective = data.strip(SIGNATURE_PADDING_BYTES)
    trimmed_size = len(effective)
    non_whitespace = bytes(byte for byte in data if byte not in b' \t\r\n')
    byte_values = set(non_whitespace)

    summary: Dict[str, Any] = {
        'source': source,
        'section_present': True,
        'raw_size': raw_size,
        'trimmed_size': trimmed_size,
        'raw_sha256': hashlib.sha256(data).hexdigest(),
        'effective_sha256': hashlib.sha256(effective).hexdigest() if effective else None,
        'content_class': 'UNKNOWN',
        'effective_signature_present': False,
        'signature_intent_present': False,
        'ascii_decodable': None,
    }

    if raw_size == 0:
        summary['content_class'] = 'EMPTY_SECTION'
        summary['ascii_decodable'] = True
        return summary, ''
    if not effective:
        summary['ascii_decodable'] = True
        if byte_values and byte_values <= {0xFF}:
            summary['content_class'] = 'ERASED_PLACEHOLDER'
        elif byte_values and byte_values <= {0x00}:
            summary['content_class'] = 'ZERO_FILLED_PLACEHOLDER'
        elif byte_values and byte_values <= {0x00, 0xFF}:
            summary['content_class'] = 'ERASED_OR_ZERO_PLACEHOLDER'
        else:
            summary['content_class'] = 'WHITESPACE_PLACEHOLDER'
        return summary, ''

    try:
        text = effective.decode('ascii', errors='strict')
        summary['ascii_decodable'] = True
    except UnicodeDecodeError as exc:
        summary['ascii_decodable'] = False
        summary['content_class'] = 'NON_TEXT_BINARY'
        summary['signature_intent_present'] = True
        summary['decode_error'] = str(exc)
        return summary, None

    parsed = parse_rpi_signature_text(text, source)
    has_digest = parsed.get('digest') is not None
    has_rsa_label = bool(re.search(r'(?mi)^\s*rsa2048\s*:', text))
    has_valid_rsa = parsed.get('rsa2048_hex') is not None
    has_metadata_label = bool(re.search(r'(?mi)^\s*(?:ts|target-soc)\s*:', text))
    summary.update({
        'digest_present': has_digest,
        'rsa_label_present': has_rsa_label,
        'valid_rsa_payload_present': has_valid_rsa,
        'signature_intent_present': bool(has_digest or has_rsa_label or has_metadata_label),
        'parse_errors': list(parsed.get('errors', [])),
        'unknown_line_count': len(parsed.get('unknown_lines', [])),
    })

    if has_digest and not has_rsa_label:
        summary['content_class'] = 'DIGEST_ONLY'
        return summary, text
    if has_valid_rsa and not parsed.get('errors'):
        summary['content_class'] = 'SIGNED_TEXT'
        summary['effective_signature_present'] = True
        return summary, text
    if has_rsa_label or has_digest or has_metadata_label:
        summary['content_class'] = 'MALFORMED_SIGNATURE_TEXT'
        summary['effective_signature_present'] = has_rsa_label
        return summary, text

    summary['content_class'] = 'UNRECOGNIZED_TEXT'
    summary['signature_intent_present'] = True
    return summary, text

def validate_rpi_signed_file(
    image_path: Path,
    signature_path: Path,
    key: Optional[RSAPublicKeyMaterial],
    expected_soc: Optional[str] = None,
    max_age_days: Optional[int] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'image_path': str(image_path),
        'signature_path': str(signature_path),
        'image_present': image_path.is_file(),
        'signature_present': signature_path.is_file(),
        'effective_signature_present': False,
        'format_status': 'NOT_AVAILABLE',
        'digest_status': 'NOT_VERIFIED',
        'rsa_signature_status': 'NOT_VERIFIED',
        'target_soc_status': 'NOT_ASSESSED',
        'freshness_status': 'NOT_ASSESSED',
        'timestamp': None,
        'age_days': None,
        'max_age_days': max_age_days,
        'overall': VALIDATION_UNVERIFIED,
        'reason_code': REASON_ARTIFACT_NOT_FOUND,
        'reason_codes': [REASON_ARTIFACT_NOT_FOUND],
        'cryptographic_verification_performed': False,
        'errors': [],
    }
    image_present = image_path.is_file()
    signature_present = signature_path.is_file()
    if not image_present or not signature_present:
        if image_present and not signature_present:
            reason = REASON_SIGNATURE_NOT_PRESENT
        else:
            reason = REASON_ARTIFACT_NOT_FOUND
        result['reason_code'] = reason
        result['reason_codes'] = [reason]
        return result

    try:
        signature_bytes = signature_path.read_bytes()
    except OSError as exc:
        result['errors'].append(str(exc))
        result['reason_code'] = REASON_IO_ERROR
        result['reason_codes'] = [REASON_IO_ERROR]
        return result

    signature_content, signature_text = classify_rpi_signature_blob(
        signature_bytes, str(signature_path)
    )
    result['signature_content'] = signature_content
    result['effective_signature_present'] = bool(
        signature_content.get('effective_signature_present')
    )
    content_class = signature_content.get('content_class')

    placeholder_classes = {
        'EMPTY_SECTION', 'ERASED_PLACEHOLDER', 'ZERO_FILLED_PLACEHOLDER',
        'ERASED_OR_ZERO_PLACEHOLDER', 'WHITESPACE_PLACEHOLDER',
    }
    if content_class in placeholder_classes:
        result['format_status'] = 'NOT_PRESENT'
        result['rsa_signature_status'] = 'MISSING'
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_SIGNATURE_NOT_PRESENT
        result['reason_codes'] = [REASON_SIGNATURE_NOT_PRESENT]
        return result

    if content_class in {'NON_TEXT_BINARY', 'MALFORMED_SIGNATURE_TEXT', 'UNRECOGNIZED_TEXT'}:
        result['format_status'] = 'MALFORMED'
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        result['errors'].extend(signature_content.get('parse_errors', []))
        if signature_content.get('decode_error'):
            result['errors'].append(signature_content['decode_error'])
        if not result['errors']:
            result['errors'].append(f'Unrecognised signature content class: {content_class}')
        return result

    try:
        digest = hashlib.sha256()
        image_size = 0
        with image_path.open('rb') as image_handle:
            for block in iter(lambda: image_handle.read(1024 * 1024), b''):
                digest.update(block)
                image_size += len(block)
        actual_digest_bytes = digest.digest()
        result['image_size'] = image_size
    except OSError as exc:
        result['errors'].append(str(exc))
        result['reason_code'] = REASON_IO_ERROR
        result['reason_codes'] = [REASON_IO_ERROR]
        return result

    parsed = parse_rpi_signature_text(signature_text or '', str(signature_path))
    result['parsed'] = parsed
    result['format_status'] = parsed['status']
    if parsed['errors']:
        result['errors'].extend(parsed['errors'])
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        return result

    actual_digest = actual_digest_bytes.hex()
    result['image_sha256'] = actual_digest
    result['declared_sha256'] = parsed['digest']
    result['digest_status'] = 'MATCH' if actual_digest == parsed['digest'] else 'MISMATCH'

    target_soc = parsed.get('target_soc')
    if target_soc is None:
        result['target_soc_status'] = 'UNSPECIFIED'
    elif expected_soc and target_soc == expected_soc:
        result['target_soc_status'] = 'MATCH'
    elif expected_soc:
        result['target_soc_status'] = 'MISMATCH'
    else:
        result['target_soc_status'] = 'PRESENT_NOT_COMPARED'

    timestamp = parsed.get('timestamp')
    result['timestamp'] = timestamp
    freshness_failed = False
    if timestamp is None:
        result['freshness_status'] = 'TIMESTAMP_MISSING'
    else:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        age_seconds = now_ts - timestamp
        result['age_days'] = round(age_seconds / 86400.0, 3)
        if timestamp > now_ts + 300:
            result['freshness_status'] = 'FUTURE_TIMESTAMP'
            freshness_failed = True
        elif max_age_days is not None and age_seconds > max_age_days * 86400:
            result['freshness_status'] = 'STALE'
            freshness_failed = True
        elif max_age_days is not None:
            result['freshness_status'] = 'WITHIN_POLICY'
        else:
            result['freshness_status'] = 'TIMESTAMP_VALID_NO_MAX_AGE_POLICY'

    signature_hex = parsed.get('rsa2048_hex')
    if signature_hex is None:
        result['rsa_signature_status'] = 'MISSING'
    elif key is None:
        result['rsa_signature_status'] = 'KEY_UNAVAILABLE'
    else:
        signature = bytes.fromhex(signature_hex)
        result['cryptographic_verification_performed'] = True
        verification = rsa_pkcs1_v15_sha256_verify_digest_result(
            actual_digest_bytes, signature, key
        )
        result['verification_backend'] = verification.backend
        result['rsa_signature_status'] = 'VERIFIED' if verification.valid else 'INVALID'
        if verification.error:
            result['verification_backend_error'] = verification.error
            result['errors'].append(f'RSA verification backend failure: {verification.error}')
        result['verification_key'] = key.summary()

    invalid_reasons: List[str] = []
    if result['digest_status'] == 'MISMATCH':
        invalid_reasons.append(REASON_CRYPTOGRAPHIC_MISMATCH)
    if result['rsa_signature_status'] == 'INVALID':
        invalid_reasons.append(REASON_CRYPTOGRAPHIC_MISMATCH)
    if result['target_soc_status'] == 'MISMATCH':
        invalid_reasons.append(REASON_TARGET_SOC_MISMATCH)
    if freshness_failed:
        invalid_reasons.append(REASON_FRESHNESS_POLICY_FAILURE)
    invalid_reasons = list(dict.fromkeys(invalid_reasons))

    if invalid_reasons:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = invalid_reasons[0]
        result['reason_codes'] = invalid_reasons
    elif signature_hex is None:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_SIGNATURE_NOT_PRESENT
        result['reason_codes'] = [REASON_SIGNATURE_NOT_PRESENT]
    elif key is None:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_KEY_UNAVAILABLE
        result['reason_codes'] = [REASON_KEY_UNAVAILABLE]
    elif result['digest_status'] == 'MATCH' and result['rsa_signature_status'] == 'VERIFIED':
        result['overall'] = VALIDATION_VALID
        result['reason_code'] = REASON_NONE
        result['reason_codes'] = []
    else:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_CRYPTOGRAPHIC_MISMATCH
        result['reason_codes'] = [REASON_CRYPTOGRAPHIC_MISMATCH]
    return result
