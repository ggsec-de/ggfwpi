"""Extracted GGFW component: crypto.rsa."""
from ggfw._compat import (
    Any, CRYPTOGRAPHY_AVAILABLE, CRYPTOGRAPHY_VERSION, Dict, Optional, Path, Tuple,
    _CryptographyInvalidSignature, _cryptography_hashes, _cryptography_padding,
    _cryptography_rsa, _cryptography_utils, base64, binascii, dataclass, hashlib, hmac, re,
)

RSA2048_SIGNATURE_SIZE = 256

RPI_PUBLIC_KEY_BIN_SIZE = 264

SHA256_DIGEST_INFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

class SecureBootFormatError(ValueError):
    """Malformed signature, public-key, or EEPROM container data."""

@dataclass
class RSAPublicKeyMaterial:
    modulus: int
    exponent: int
    source: str = ''

    @property
    def size_bits(self) -> int:
        return self.modulus.bit_length()

    def to_pubkey_bin(self) -> bytes:
        if self.size_bits != 2048:
            raise SecureBootFormatError(f'RSA key must be 2048 bits, got {self.size_bits}')
        if self.exponent <= 1 or self.exponent % 2 == 0:
            raise SecureBootFormatError('RSA public exponent is invalid')
        return self.modulus.to_bytes(256, 'little') + self.exponent.to_bytes(8, 'little')

    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_pubkey_bin()).hexdigest()

    def summary(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'size_bits': self.size_bits,
            'exponent': self.exponent,
            'pubkey_bin_sha256': self.fingerprint(),
            'modulus_sha256': hashlib.sha256(self.modulus.to_bytes(256, 'big')).hexdigest(),
        }

def _der_read_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Read one canonical DER length.

    DER is the canonical subset of BER and therefore requires definite-length,
    shortest-form encodings. In particular, 0x80 (BER indefinite length) is
    deliberately rejected rather than scanned for an end-of-contents marker.
    """
    if offset >= len(data):
        raise SecureBootFormatError('Truncated DER length')
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise SecureBootFormatError('DER indefinite-length encoding is not permitted')
    if count > 4 or offset + count > len(data):
        raise SecureBootFormatError('Unsupported DER length encoding')
    encoded = data[offset:offset + count]
    if encoded[0] == 0:
        raise SecureBootFormatError('Non-minimal DER length encoding')
    length = int.from_bytes(encoded, 'big')
    if length < 0x80:
        raise SecureBootFormatError('DER long-form length used for a short value')
    return length, offset + count

def _der_read_tlv(data: bytes, offset: int, expected_tag: Optional[int] = None) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise SecureBootFormatError('Truncated DER object')
    tag = data[offset]
    length, value_offset = _der_read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise SecureBootFormatError('DER object exceeds input length')
    if expected_tag is not None and tag != expected_tag:
        raise SecureBootFormatError(f'Unexpected DER tag 0x{tag:02x}, expected 0x{expected_tag:02x}')
    return tag, data[value_offset:end], end

def _der_read_positive_integer(data: bytes, offset: int, field_name: str) -> Tuple[int, int]:
    """Read a canonical, strictly positive DER INTEGER."""
    _, encoded, end = _der_read_tlv(data, offset, 0x02)
    if not encoded:
        raise SecureBootFormatError(f'Empty DER INTEGER for RSA {field_name}')
    if encoded[0] & 0x80:
        raise SecureBootFormatError(f'Negative DER INTEGER for RSA {field_name}')
    if len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
        raise SecureBootFormatError(f'Non-minimal DER INTEGER for RSA {field_name}')
    value = int.from_bytes(encoded, 'big')
    if value <= 0:
        raise SecureBootFormatError(f'RSA {field_name} must be positive')
    return value, end

RSA_ENCRYPTION_ALGORITHM_IDENTIFIER = bytes.fromhex(
    '06092a864886f70d0101010500'  # rsaEncryption OID followed by canonical NULL parameters
)

def _parse_rsa_public_key_der(der: bytes, source: str = '') -> RSAPublicKeyMaterial:
    _, sequence, end = _der_read_tlv(der, 0, 0x30)
    if end != len(der):
        raise SecureBootFormatError('Trailing data after DER public key')

    if not sequence:
        raise SecureBootFormatError('Empty DER public-key sequence')

    if sequence[0] == 0x02:
        # PKCS#1 RSAPublicKey starts directly with INTEGER modulus/exponent.
        modulus, pos = _der_read_positive_integer(sequence, 0, 'modulus')
        exponent, pos = _der_read_positive_integer(sequence, pos, 'public exponent')
        if pos != len(sequence):
            raise SecureBootFormatError('Trailing data after PKCS#1 RSA public key')
        key = RSAPublicKeyMaterial(modulus, exponent, source)
        key.to_pubkey_bin()
        return key

    # SubjectPublicKeyInfo must identify rsaEncryption, not merely contain any
    # AlgorithmIdentifier-shaped sequence before an RSA-looking BIT STRING.
    _, algorithm_identifier, pos = _der_read_tlv(sequence, 0, 0x30)
    if algorithm_identifier != RSA_ENCRYPTION_ALGORITHM_IDENTIFIER:
        raise SecureBootFormatError('SubjectPublicKeyInfo algorithm is not canonical rsaEncryption')
    _, bit_string, pos = _der_read_tlv(sequence, pos, 0x03)
    if pos != len(sequence) or not bit_string or bit_string[0] != 0:
        raise SecureBootFormatError('Invalid SubjectPublicKeyInfo BIT STRING')
    return _parse_rsa_public_key_der(bit_string[1:], source)

def parse_pem_rsa_public_key(path: str) -> RSAPublicKeyMaterial:
    public_path = Path(path).expanduser().resolve()
    if not public_path.is_file():
        raise SecureBootFormatError(f'Public key file not found: {public_path}')
    text = public_path.read_text(encoding='ascii', errors='strict')
    match = re.search(
        r'-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY)-----\s*(.*?)\s*-----END \1-----',
        text, re.DOTALL,
    )
    if not match:
        raise SecureBootFormatError('Expected PEM PUBLIC KEY or RSA PUBLIC KEY')
    try:
        der = base64.b64decode(re.sub(r'\s+', '', match.group(2)), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecureBootFormatError(f'Invalid PEM base64: {exc}') from exc
    return _parse_rsa_public_key_der(der, str(public_path))

def parse_rpi_pubkey_bin(data: bytes, source: str = '') -> RSAPublicKeyMaterial:
    if len(data) != RPI_PUBLIC_KEY_BIN_SIZE:
        raise SecureBootFormatError(
            f'Raspberry Pi pubkey.bin must be {RPI_PUBLIC_KEY_BIN_SIZE} bytes, got {len(data)}'
        )
    modulus = int.from_bytes(data[:256], 'little')
    exponent = int.from_bytes(data[256:264], 'little')
    key = RSAPublicKeyMaterial(modulus, exponent, source)
    key.to_pubkey_bin()
    return key

@dataclass(frozen=True)
class RSAVerificationResult:
    valid: bool
    backend: str
    error: Optional[str] = None

def _rsa_pkcs1_v15_sha256_verify_digest_builtin(
    digest: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> RSAVerificationResult:
    if len(digest) != 32 or len(signature) != RSA2048_SIGNATURE_SIZE or key.size_bits != 2048:
        return RSAVerificationResult(False, 'builtin-python')
    signature_int = int.from_bytes(signature, 'big')
    if signature_int >= key.modulus:
        return RSAVerificationResult(False, 'builtin-python')
    encoded = pow(signature_int, key.exponent, key.modulus).to_bytes(256, 'big')
    digest_info = SHA256_DIGEST_INFO_PREFIX + digest
    padding_len = 256 - len(digest_info) - 3
    if padding_len < 8:
        return RSAVerificationResult(False, 'builtin-python')
    expected = b'\x00\x01' + (b'\xff' * padding_len) + b'\x00' + digest_info
    # Both operands are public during signature verification, but compare_digest
    # avoids introducing an avoidable timing distinction as defence in depth.
    return RSAVerificationResult(hmac.compare_digest(encoded, expected), 'builtin-python')

def _cryptography_verify_rsa_digest(
    digest: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> None:
    """Verify using cryptography; factored out to make error behavior testable."""
    public_key = _cryptography_rsa.RSAPublicNumbers(key.exponent, key.modulus).public_key()
    public_key.verify(
        signature,
        digest,
        _cryptography_padding.PKCS1v15(),
        _cryptography_utils.Prehashed(_cryptography_hashes.SHA256()),
    )

def _rsa_pkcs1_v15_sha256_verify_digest_cryptography(
    digest: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> RSAVerificationResult:
    backend = f'cryptography/{CRYPTOGRAPHY_VERSION or "unknown"}'
    try:
        _cryptography_verify_rsa_digest(digest, signature, key)
        return RSAVerificationResult(True, backend)
    except _CryptographyInvalidSignature:
        return RSAVerificationResult(False, backend)
    except Exception as exc:
        # An installed but malfunctioning backend must fail closed. In
        # particular, do not retry the same input with the built-in verifier.
        return RSAVerificationResult(
            False, backend, f'{type(exc).__name__}: {exc}'
        )

def rsa_pkcs1_v15_sha256_verify_digest_result(
    digest: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> RSAVerificationResult:
    if (
        len(digest) != 32
        or len(signature) != RSA2048_SIGNATURE_SIZE
        or key.size_bits != 2048
        or int.from_bytes(signature, 'big') >= key.modulus
    ):
        backend = (
            f'cryptography/{CRYPTOGRAPHY_VERSION or "unknown"}'
            if CRYPTOGRAPHY_AVAILABLE else 'builtin-python'
        )
        return RSAVerificationResult(False, backend)
    if CRYPTOGRAPHY_AVAILABLE:
        return _rsa_pkcs1_v15_sha256_verify_digest_cryptography(digest, signature, key)
    return _rsa_pkcs1_v15_sha256_verify_digest_builtin(digest, signature, key)

def rsa_pkcs1_v15_sha256_verify_digest(
    digest: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> bool:
    """Compatibility bool API for RSA-2048 PKCS#1 v1.5 SHA-256 verification."""
    return rsa_pkcs1_v15_sha256_verify_digest_result(digest, signature, key).valid

def rsa_pkcs1_v15_sha256_verify_result(
    data: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> RSAVerificationResult:
    return rsa_pkcs1_v15_sha256_verify_digest_result(hashlib.sha256(data).digest(), signature, key)

def rsa_pkcs1_v15_sha256_verify(data: bytes, signature: bytes, key: RSAPublicKeyMaterial) -> bool:
    return rsa_pkcs1_v15_sha256_verify_result(data, signature, key).valid
