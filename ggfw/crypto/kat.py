"""Extracted GGFW component: crypto.kat."""
from ggfw._compat import (
    List, Optional, Path, Tuple, hashlib, tempfile,
)
from ggfw.constants import REASON_FORMAT_INVALID, TOOL_VERSION_DISPLAY, VALIDATION_INVALID, VALIDATION_VALID
from ggfw.crypto.rsa import RSAPublicKeyMaterial
from ggfw.crypto.signatures import validate_rpi_signed_file
from ggfw.crypto.validation import verify_bcm2712_customer_signed_blob

CRYPTO_KAT_RSA_MODULUS = int(
    "dc8e623b3ed4014d449b3d244f8ab529856aa66e4b0c7a5ca9fb040c88aba812"
    "1ad4c8ddc4e4c5143b0a071b66e419d00c34581337bc4be9d63f7e19bb0e65c4"
    "e1e5ce6ded970e042775743e27516511e38d6341af48072ff309dcce40736ec0"
    "ade4a27e4087595432a3117eda0d8459271b8947f3f92b681d6fffa40d48d3d6"
    "afb121e31110919f5829a671f4ce4fea81371867e7366e78d2aa3970cbf552fef"
    "efc78910e47248f1263ab46f18f6a64f11f05961d08f746156b6161f47a5d740"
    "134659e75a46febb192f40e9c26c288d311b5e256bb1c0b22682c976777a62324"
    "de47c5d3f2f4890db6bfbdbc6065c24c157e003d0aa7cb8df0e7910ec0fe21",
    16,
)

CRYPTO_KAT_RSA_EXPONENT = 65537

CRYPTO_KAT_BOOT_IMAGE = bytes.fromhex(
    "474746572d43525950544f2d4b41542d424f4f542d494d4147452d76310a"
)

CRYPTO_KAT_BOOT_SIGNATURE = bytes.fromhex(
    "cd59d537e058863c73a44a46d41877594e3dfc4362384fe41574bee53d44b4e6"
    "091d1d65a3dcdc0f9f507ce5c5b204aa4bfe2675f27ecef6f6f2e7e1a3423b70"
    "dcec23a424c5b85100ca6ee3fce82f1ecdc3d91e7ccc11b2f958a1f44b56797f"
    "8dc0460d5f628d2aa000d658dac03ce79d041d816ca551334436e478e34b7b248"
    "6cda7fa53ccbeb00a600fcf11803bd5aa0354588af244284a045c978e7e7bf028"
    "a04730daded51ef9c4453c06853948c1467d1480cd93aa349c9f33f12f08ed0d4"
    "c6d74497c3f6a7645c35f814c07a384f29b73086e022d939044c277d7f94c3347"
    "bc9f739c6a75b51f75395bbd91eb81e26a90ba0db6b1774af594d870a2b6"
)

CRYPTO_KAT_BOOTCONF = bytes.fromhex(
    "474746572d43525950544f2d4b41542d424f4f54434f4e462d76310a"
)

CRYPTO_KAT_BOOTCONF_SIGNATURE = bytes.fromhex(
    "dbd37908f52397f1d269149cc6c9c90ac408a89a7aa1958cc15e984b7b85d15d"
    "1a84830e346d17be25cddf753a229650cd54f09ba10d1de8fddc4381a1b8f0b2"
    "d594b9be638ab1e74c70099b0d64d377613abd94ada5ac77d976d5cba38c13e9"
    "382b8a401ebb576910714210ba2744666d43338fa2baaf3654f6160adf814f408"
    "b9cc56c8d19191bf02de8243685e0d1a9dc8e148a0e6de9a56cba3b24da46847"
    "3151735ea55d63e0abbb4944207892558cbd1b413805856645ab63445c1ca09d3"
    "b95aa9cbd0db68814526c0ce8bb9d5dc5bc69548bb72df1bff85b287f0ee2ce7"
    "c59db7c01873c3b9decda44e658da953bd2253e4e9a3877027abc764ea41cf"
)

CRYPTO_KAT_BOOTSYS = bytes.fromhex(
    "474746572d43525950544f2d4b41542d424f4f545359532d76310a000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"
    "3b3c3d3e3f5b0000001000000003000000c938d968327d1b88b5ee9e7333f173e31be2b30cdf663ec5efdf"
    "2b9f4bab3b21fb7de5e51f9185fb6d8d6494b7b66d897ae3573af43741b59fbf12eb54c51233d28aa925b"
    "63683ca56f106ce91ccef9a569c6a7130cc025f43d677966152d6ffb745b05330eb988d433432fa8dd2d3d"
    "4a941b2dea1ab14f3c0b3ae8e273cf1131bcba7f7fcb29af83a52ac4514a941039008e1921a42573a752c2"
    "ab6eeb597068f4b2d745b434b121006e2b0601c83c73dcf2dd103fb85a099896774e76497556d5d5fb35a0"
    "849caac8dfc0547d3cb2d242a9a9698b67d43b925f8c41abc1a399616372eeb7af9832526e6cc0856e5452"
    "dd052f892965238367cb21aece5474021fec00e91e7f08dcba70a3d007e154cc26560bcbdbfb60d89f4f2d"
    "3c547de2423a67767972c68220b1cbb56e2b511d388c2269c0ef492b1eb6fa4759e653401745d7af461616b"
    "1546f7081d96051ff1646a8ff146ab63128f24470e9178fcfefe52f5cb7039aad2786e36e767183781ea4fc"
    "ef471a629589f911011e321b1afd6d3480da4ff6f1d682bf9f347891b2759840dda7e11a332545987407ea2"
    "e4adc06e7340cedc09f32f0748af41638de3116551273e747527040e97ed6dcee5e1c4650ebb197e3fd6e94"
    "bbc371358340cd019e4661b070a3b14c5e4c4ddc8d41a12a8ab880c04fba95c7a0c4b6ea66a8529b58a4f"
    "243d9b444d01d43e3b628edc0100010000000000"
)

def _crypto_kat_signature_text(payload: bytes, signature: bytes, target_soc: Optional[str]) -> str:
    lines = [hashlib.sha256(payload).hexdigest(), 'ts: 1700000000']
    if target_soc:
        lines.append(f'target-soc: {target_soc}')
    lines.append(f'rsa2048: {signature.hex()}')
    return '\n'.join(lines) + '\n'

def run_crypto_self_test() -> int:
    """Run embedded known-answer tests without reading platform state."""
    key = RSAPublicKeyMaterial(CRYPTO_KAT_RSA_MODULUS, CRYPTO_KAT_RSA_EXPONENT, 'embedded-kat')
    wrong_key = RSAPublicKeyMaterial(CRYPTO_KAT_RSA_MODULUS ^ 2, CRYPTO_KAT_RSA_EXPONENT, 'embedded-wrong-key')
    results: List[Tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        results.append((name, bool(ok), detail))

    with tempfile.TemporaryDirectory(prefix='ggfw-crypto-kat-') as tmp:
        root = Path(tmp)
        image = root / 'boot.img'
        signature = root / 'boot.sig'
        image.write_bytes(CRYPTO_KAT_BOOT_IMAGE)
        signature.write_text(
            _crypto_kat_signature_text(CRYPTO_KAT_BOOT_IMAGE, CRYPTO_KAT_BOOT_SIGNATURE, '2712'),
            encoding='ascii',
        )
        valid = validate_rpi_signed_file(image, signature, key, '2712')
        record('valid boot.img signature', valid.get('overall') == VALIDATION_VALID, str(valid.get('overall')))

        image.write_bytes(CRYPTO_KAT_BOOT_IMAGE[:-1] + bytes([CRYPTO_KAT_BOOT_IMAGE[-1] ^ 1]))
        tampered = validate_rpi_signed_file(image, signature, key, '2712')
        record('tampered boot.img', tampered.get('overall') == VALIDATION_INVALID, str(tampered.get('overall')))

        image.write_bytes(CRYPTO_KAT_BOOT_IMAGE)
        wrong = validate_rpi_signed_file(image, signature, wrong_key, '2712')
        record('wrong public key', wrong.get('overall') == VALIDATION_INVALID, str(wrong.get('overall')))

        signature.write_text(
            hashlib.sha256(CRYPTO_KAT_BOOT_IMAGE).hexdigest() + '\nts: 1700000000\nrsa2048: 1234\n',
            encoding='ascii',
        )
        truncated = validate_rpi_signed_file(image, signature, key, '2712')
        record(
            'truncated boot.sig',
            truncated.get('overall') == VALIDATION_INVALID and truncated.get('reason_code') == REASON_FORMAT_INVALID,
            f"{truncated.get('overall')}/{truncated.get('reason_code')}",
        )

        bootconf = root / 'bootconf.txt'
        bootconf_sig = root / 'bootconf.sig'
        bootconf.write_bytes(CRYPTO_KAT_BOOTCONF)
        bootconf_sig.write_text(
            _crypto_kat_signature_text(CRYPTO_KAT_BOOTCONF, CRYPTO_KAT_BOOTCONF_SIGNATURE, None),
            encoding='ascii',
        )
        bootconf_result = validate_rpi_signed_file(bootconf, bootconf_sig, key, None)
        record('valid bootconf signature', bootconf_result.get('overall') == VALIDATION_VALID, str(bootconf_result.get('overall')))

        bootsys_result = verify_bcm2712_customer_signed_blob(CRYPTO_KAT_BOOTSYS, key, 'embedded-kat-bootsys')
        record('valid BCM2712 bootsys trailer', bootsys_result.get('overall') == VALIDATION_VALID, str(bootsys_result.get('overall')))

    print(f'[*] GGFW {TOOL_VERSION_DISPLAY} cryptographic self-test')
    print('-' * 68)
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    passed = all(ok for _, ok, _ in results)
    print('-' * 68)
    print(f"[*] Crypto self-test result: {'PASS' if passed else 'FAIL'}")
    print(f"[*] Process exit code: {0 if passed else 1}")
    return 0 if passed else 1
