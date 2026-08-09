"""Extracted GGFW component: hardware.otp."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, Tuple, json, re,
)
from ggfw.constants import OTP_DECODER_SCHEMA
from ggfw.files import sha256_file
from ggfw.hardware.platform import get_soc_generation

OFFICIAL_OTP_REFERENCES = {
    "otp_registers": "https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#otp-register-and-bit-definitions",
    "secure_boot": "https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md",
    "secure_boot_pi5": "https://github.com/raspberrypi/usbboot/blob/master/secure-boot-recovery5/README.md",
    "rpi_eeprom_digest": "https://github.com/raspberrypi/rpi-eeprom/blob/master/rpi-eeprom-digest",
    "rpi_eeprom_config": "https://github.com/raspberrypi/rpi-eeprom/blob/master/rpi-eeprom-config",
    "rpi_sign_bootcode": "https://github.com/raspberrypi/rpi-eeprom/blob/master/tools/rpi-sign-bootcode",
}

def _otp_int(words: Dict[str, str], row: int) -> Optional[int]:
    raw = words.get(f"{row:02d}")
    if raw is None:
        raw = words.get(str(row))
    if raw is None:
        return None
    try:
        return int(str(raw).strip(), 16)
    except (TypeError, ValueError):
        return None

def _otp_rows(words: Dict[str, str], rows: List[int]) -> Tuple[List[Optional[int]], List[int]]:
    values = [_otp_int(words, row) for row in rows]
    missing = [row for row, value in zip(rows, values) if value is None]
    return values, missing

def _row_hex(value: Optional[int]) -> Optional[str]:
    return None if value is None else f"{value:08x}"

def _programmed_status(values: List[Optional[int]]) -> str:
    if not values or any(value is None for value in values):
        return "UNKNOWN"
    return "PROGRAMMED" if any(value != 0 for value in values) else "UNPROGRAMMED"

def _safe_metadata_hash(value: Any) -> Tuple[str, Optional[str]]:
    text = str(value or "").strip().lower().replace("0x", "")
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        return "UNKNOWN", None
    if set(text) == {"0"}:
        return "UNPROGRAMMED", text
    return "PROGRAMMED", text

def load_rpiboot_metadata(path: Optional[str]) -> Dict[str, Any]:
    """Load metadata emitted by `rpiboot -j`. The file is operator-supplied external evidence."""
    result: Dict[str, Any] = {
        "requested": bool(path), "loaded": False, "path": path or "", "files": [],
        "metadata": {}, "error": None, "source_type": "EXTERNAL_PROVISIONING_METADATA",
        "trust_level": "HIGH", "integrity_note": (
            "Metadata is independently acquired during rpiboot/recovery provisioning, but GGFW does not "
            "cryptographically authenticate the JSON file itself. Provenance is asserted by the operator."
        ),
    }
    if not path:
        return result
    target = Path(path).expanduser().resolve()
    try:
        candidates = [target] if target.is_file() else sorted(target.rglob("*.json")) if target.is_dir() else []
        if not candidates:
            raise ValueError("No JSON metadata file was found")
        parsed: List[Tuple[Path, Dict[str, Any]]] = []
        for candidate in candidates:
            payload = json.loads(candidate.read_text(encoding="utf-8", errors="strict"))
            if isinstance(payload, dict):
                parsed.append((candidate, payload))
        if not parsed:
            raise ValueError("Metadata JSON did not contain an object")
        security_files = [item for item in parsed if any(
            key in item[1] for key in ("CUSTOMER_KEY_HASH", "SECURE_BOOT_PROVISION", "JTAG_LOCKED")
        )]
        selectable = security_files or parsed
        if len(selectable) != 1:
            raise ValueError(
                "Multiple device metadata JSON files were found; specify the exact rpiboot metadata file"
            )
        candidate, payload = selectable[0]
        used = [{"path": str(candidate), "sha256": sha256_file(str(candidate))}]
        result.update({"loaded": True, "files": used, "metadata": payload})
    except Exception as exc:
        result["error"] = str(exc)
    return result

class OTPDecoderBase:
    profile = "GENERIC"
    public_mapping = "UNSUPPORTED"

    def __init__(self, words: Dict[str, str], metadata_bundle: Optional[Dict[str, Any]] = None):
        self.words = words or {}
        self.metadata_bundle = metadata_bundle or {}
        self.metadata = self.metadata_bundle.get("metadata", {}) if self.metadata_bundle.get("loaded") else {}

    def field(
        self, name: str, status: str, source_words: Optional[List[int]] = None,
        value: Any = None, mask: Optional[str] = None, confidence: str = "HIGH",
        note: str = "", source: str = "RUNTIME_OTP_DUMP", sensitive: bool = False,
    ) -> Dict[str, Any]:
        return {
            "field": name, "status": status, "value": None if sensitive else value,
            "value_redacted": bool(sensitive), "source_words": source_words or [],
            "mask": mask, "confidence": confidence, "note": note, "source": source,
        }

    def base_result(self, soc: str) -> Dict[str, Any]:
        return {
            "schema": OTP_DECODER_SCHEMA,
            "decoder_profile": self.profile,
            "decoder_version": "1",
            "soc": soc,
            "decoder_status": "SUPPORTED",
            "public_mapping": self.public_mapping,
            "raw_word_count": len(self.words),
            "metadata_supplied": bool(self.metadata_bundle.get("loaded")),
            "fields": {},
            "security": {},
            "unknown_fields": [],
            "unresolved_security_fields": [],
            "references": OFFICIAL_OTP_REFERENCES,
        }

    def decode(self) -> Dict[str, Any]:
        result = self.base_result("UNKNOWN")
        result["decoder_status"] = "UNSUPPORTED"
        result["unknown_fields"].append("No model-specific OTP mapping is available")
        return result

class OTPDecoderBCM2711(OTPDecoderBase):
    profile = "BCM2711-v1"
    public_mapping = "PUBLIC_RUNTIME_MAPPING"

    def decode(self) -> Dict[str, Any]:
        result = self.base_result("BCM2711")
        fields = result["fields"]
        security = result["security"]

        control = _otp_int(self.words, 16)
        bootmode = _otp_int(self.words, 17)
        serial_low = _otp_int(self.words, 28)
        serial_high = _otp_int(self.words, 35)
        board_revision = _otp_int(self.words, 30)

        fields["serial_number"] = self.field(
            "serial_number", "DECODED" if serial_low is not None else "UNKNOWN", [35, 28],
            value=None if serial_low is None else f"{(serial_high or 0):08x}{serial_low:08x}",
            note="BCM2711/non-BCM2712 public OTP serial mapping.",
        )
        fields["board_revision"] = self.field(
            "board_revision", "DECODED" if board_revision is not None else "UNKNOWN", [30],
            value=_row_hex(board_revision),
        )

        key_rows = list(range(47, 55))
        key_values, key_missing = _otp_rows(self.words, key_rows)
        key_status = _programmed_status(key_values)
        key_hex = None if key_missing else "".join(_row_hex(value) or "" for value in key_values)
        security["customer_key_hash"] = self.field(
            "customer_key_hash", key_status, key_rows, value=key_hex,
            note=("Rows 47-54 are publicly documented as the SHA-256 RSA customer public-key hash. "
                  "The value is represented in otp_dump row order."),
        )

        if bootmode is None:
            sb_status = "UNKNOWN"
        else:
            sb_status = "ENABLED" if (bootmode & (1 << 15)) else "DISABLED"
        security["secure_boot_enablement"] = self.field(
            "secure_boot_enablement", sb_status, [17], value=_row_hex(bootmode), mask="0x00008000",
            note="BCM2711 row 17 bit 15 disables ROM RSA key 0; the official documentation identifies this as Secure Boot enabled.",
        )

        if control is None:
            jtag_status = "UNKNOWN"
        else:
            jtag_bits = (control >> 26) & 0x3
            jtag_status = "LOCKED" if jtag_bits == 0x3 else "UNLOCKED" if jtag_bits == 0 else "PARTIAL"
        security["vc_jtag_lock"] = self.field(
            "vc_jtag_lock", jtag_status, [16], value=_row_hex(control), mask="0x0c000000",
            note="Rows 16 bits 26 and 27 are publicly documented VC JTAG disable controls.",
        )

        private_rows = list(range(56, 64))
        private_values, _ = _otp_rows(self.words, private_rows)
        security["device_private_key"] = self.field(
            "device_private_key", _programmed_status(private_values), private_rows,
            value={"nonzero_word_count": sum(1 for value in private_values if value)}, sensitive=True,
            note="The key value is deliberately redacted from decoded output; raw OTP evidence remains separately controlled.",
        )
        customer_rows = list(range(36, 44))
        customer_values, _ = _otp_rows(self.words, customer_rows)
        fields["customer_otp"] = self.field(
            "customer_otp", _programmed_status(customer_values), customer_rows,
            value={"nonzero_word_count": sum(1 for value in customer_values if value)},
        )
        fields["secure_boot_flags_reserved"] = self.field(
            "secure_boot_flags_reserved", "RAW_ONLY" if _otp_int(self.words, 55) is not None else "UNKNOWN",
            [55], value=_row_hex(_otp_int(self.words, 55)),
            note="The row is reserved for bootloader use; GGFW does not infer undocumented bit meanings.",
        )

        # Optional external rpiboot metadata cross-check.
        if self.metadata:
            meta_status, meta_hash = _safe_metadata_hash(self.metadata.get("CUSTOMER_KEY_HASH"))
            security["customer_key_hash"]["external_metadata_status"] = meta_status
            security["customer_key_hash"]["external_metadata_value"] = meta_hash
            if meta_hash and key_hex:
                security["customer_key_hash"]["cross_check"] = "MATCH" if meta_hash == key_hex else "MISMATCH"
            if "JTAG_LOCKED" in self.metadata:
                meta_jtag = "LOCKED" if str(self.metadata.get("JTAG_LOCKED")).strip() == "1" else "UNLOCKED"
                security["vc_jtag_lock"]["external_metadata_status"] = meta_jtag
        return result

class OTPDecoderBCM2712(OTPDecoderBase):
    profile = "BCM2712-v1"
    public_mapping = "PARTIAL_PUBLIC_RUNTIME_MAPPING"

    def decode(self) -> Dict[str, Any]:
        result = self.base_result("BCM2712")
        result["decoder_status"] = "PARTIAL"
        fields = result["fields"]
        security = result["security"]

        bootmode = _otp_int(self.words, 22)
        boot_copy = _otp_int(self.words, 23)
        advanced = _otp_int(self.words, 29)
        serial_low = _otp_int(self.words, 31)
        serial_high = _otp_int(self.words, 35)
        board_revision = _otp_int(self.words, 32)
        board_attributes = _otp_int(self.words, 33)

        fields["serial_number"] = self.field(
            "serial_number", "DECODED" if serial_low is not None else "UNKNOWN", [35, 31],
            value=None if serial_low is None else f"{(serial_high or 0):08x}{serial_low:08x}",
        )
        fields["board_revision"] = self.field(
            "board_revision", "DECODED" if board_revision is not None else "UNKNOWN", [32],
            value=_row_hex(board_revision),
        )
        fields["board_attributes"] = self.field(
            "board_attributes", "RAW_ONLY" if board_attributes is not None else "UNKNOWN", [33],
            value=_row_hex(board_attributes), note="Meaning depends on the board model; no undocumented bits are inferred.",
        )
        fields["bootmode"] = self.field(
            "bootmode", "DECODED" if bootmode is not None else "UNKNOWN", [22, 23],
            value={
                "raw": _row_hex(bootmode), "copy": _row_hex(boot_copy),
                "boot_sd": None if bootmode is None else bool(bootmode & (1 << 1)),
                "spi_selector": None if bootmode is None else ((bootmode >> 2) & 0x7),
                "disable_sd": None if bootmode is None else bool(bootmode & (1 << 10)),
                "disable_spi": None if bootmode is None else bool(bootmode & (1 << 11)),
                "disable_usb": None if bootmode is None else bool(bootmode & (1 << 12)),
            },
        )
        fields["advanced_boot"] = self.field(
            "advanced_boot", "DECODED" if advanced is not None else "UNKNOWN", [29],
            value={
                "raw": _row_hex(advanced),
                "sd_detect_gpio": None if advanced is None else advanced & 0xff,
                "rpiboot_gpio": None if advanced is None else (advanced >> 8) & 0xff,
            },
        )
        customer_rows = list(range(77, 85))
        customer_values, _ = _otp_rows(self.words, customer_rows)
        fields["customer_otp"] = self.field(
            "customer_otp", _programmed_status(customer_values), customer_rows,
            value={"nonzero_word_count": sum(1 for value in customer_values if value)},
        )
        fields["factory_mac_rows"] = self.field(
            "factory_mac_rows", "RAW_ONLY", list(range(50, 56)),
            value={str(row): _row_hex(_otp_int(self.words, row)) for row in range(50, 56)},
            note="Rows are public, but GGFW preserves raw values instead of guessing byte order from otp_dump.",
        )
        fields["factory_uuid_rows"] = self.field(
            "factory_uuid_rows", "RAW_ONLY", list(range(109, 115)),
            value={str(row): _row_hex(_otp_int(self.words, row)) for row in range(109, 115)},
            note="Factory UUID is C40 encoded; decoding is outside the current security decoder scope.",
        )

        meta_status, meta_hash = _safe_metadata_hash(self.metadata.get("CUSTOMER_KEY_HASH")) if self.metadata else ("UNKNOWN", None)
        if self.metadata:
            key_note = "Decoded from operator-supplied rpiboot -j provisioning metadata; runtime otp_dump row mapping is not public."
            key_source = "RPIBOOT_METADATA"
            key_status = meta_status
        else:
            key_note = (
                "BCM2712 customer Secure Boot key-hash rows are not part of the public runtime otp_dump mapping. "
                "Supply rpiboot -j metadata with --otp-metadata for an authoritative provisioning-state observation."
            )
            key_source = "UNAVAILABLE_IN_PUBLIC_RUNTIME_MAPPING"
            key_status = "UNKNOWN"
        security["customer_key_hash"] = self.field(
            "customer_key_hash", key_status, [], value=meta_hash, confidence="HIGH" if self.metadata else "HIGH",
            note=key_note, source=key_source,
        )

        provision = str(self.metadata.get("SECURE_BOOT_PROVISION", "")).strip().lower() if self.metadata else ""
        if provision == "success" or meta_status == "PROGRAMMED":
            sb_status = "PROVISIONED"
        elif self.metadata and meta_status == "UNPROGRAMMED":
            sb_status = "UNPROGRAMMED"
        else:
            sb_status = "UNKNOWN"
        security["secure_boot_enablement"] = self.field(
            "secure_boot_enablement", sb_status, [],
            value={"SECURE_BOOT_PROVISION": self.metadata.get("SECURE_BOOT_PROVISION"),
                   "SIGNATURE_MODE": self.metadata.get("SIGNATURE_MODE")},
            note=("BCM2712 Secure Boot provisioning is derived only from rpiboot metadata. "
                  "No undocumented runtime OTP row is interpreted."),
            source="RPIBOOT_METADATA" if self.metadata else "UNAVAILABLE_IN_PUBLIC_RUNTIME_MAPPING",
        )

        if "JTAG_LOCKED" in self.metadata:
            jtag_status = "LOCKED" if str(self.metadata.get("JTAG_LOCKED")).strip() == "1" else "UNLOCKED"
        else:
            jtag_status = "UNKNOWN"
        security["vc_jtag_lock"] = self.field(
            "vc_jtag_lock", jtag_status, [], value=self.metadata.get("JTAG_LOCKED"),
            note="BCM2712 JTAG lock is accepted from rpiboot provisioning metadata; runtime row mapping is not public.",
            source="RPIBOOT_METADATA" if self.metadata else "UNAVAILABLE_IN_PUBLIC_RUNTIME_MAPPING",
        )
        security["device_private_key"] = self.field(
            "device_private_key", "NOT_QUERIED", [], value=None, sensitive=True,
            note=("BCM2712 device-private-key storage uses a dedicated mailbox interface and is not decoded from otp_dump. "
                  "The key and its lock state are not read by this GGFW release."),
        )
        unresolved: List[Dict[str, Any]] = []
        if key_status == "UNKNOWN":
            unresolved.append({
                "field": "customer_key_hash",
                "status": "UNKNOWN",
                "source_rows": "UNPUBLISHED",
                "source": "UNAVAILABLE_IN_PUBLIC_RUNTIME_MAPPING",
                "reason": key_note,
            })
        if jtag_status == "UNKNOWN":
            unresolved.append({
                "field": "vc_jtag_lock",
                "status": "UNKNOWN",
                "source_rows": "UNPUBLISHED",
                "source": "UNAVAILABLE_IN_PUBLIC_RUNTIME_MAPPING",
                "reason": "BCM2712 runtime JTAG-lock OTP row mapping is not publicly documented.",
            })
        unresolved.append({
            "field": "device_private_key",
            "status": "NOT_QUERIED",
            "source_rows": "DEDICATED_MAILBOX_NOT_QUERIED",
            "source": "NOT_ACQUIRED",
            "reason": security["device_private_key"].get("note", "Device-private-key lock state was not queried."),
        })
        result["unresolved_security_fields"] = unresolved
        result["unknown_fields"] = [item["reason"] for item in unresolved]
        return result

def decode_otp_state(platform_name: str, words: Dict[str, str], metadata_bundle: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    soc = get_soc_generation(platform_name)
    decoder: OTPDecoderBase
    if soc == "BCM2711":
        decoder = OTPDecoderBCM2711(words, metadata_bundle)
    elif soc == "BCM2712":
        decoder = OTPDecoderBCM2712(words, metadata_bundle)
    else:
        decoder = OTPDecoderBase(words, metadata_bundle)
    return decoder.decode()
