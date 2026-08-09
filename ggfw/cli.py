"""Extracted GGFW component: cli."""
from ggfw._compat import (
    Any, Dict, Optional, Path, Tuple, argparse, logger, os, sys,
)
from ggfw.crypto.rsa import RSAPublicKeyMaterial, SecureBootFormatError, parse_pem_rsa_public_key
from ggfw.errors import GGFWRuntimeError
from ggfw.hardware.otp import load_rpiboot_metadata

class GGFWArgumentParser(argparse.ArgumentParser):
    """Use exit code 1 for invalid CLI input; code 2 is reserved for policy gates."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")

def preflight_explicit_external_inputs(args: argparse.Namespace) -> Tuple[Optional[Dict[str, Any]], Optional[RSAPublicKeyMaterial]]:
    """Validate explicitly supplied external evidence before any scan/acquisition begins."""
    metadata_bundle: Optional[Dict[str, Any]] = None
    public_key: Optional[RSAPublicKeyMaterial] = None

    if args.otp_metadata:
        metadata_path = Path(args.otp_metadata).expanduser().resolve()
        if not metadata_path.exists():
            raise GGFWRuntimeError(f'--otp-metadata path does not exist: {metadata_path}')
        if not os.access(metadata_path, os.R_OK):
            raise GGFWRuntimeError(f'--otp-metadata path is not readable: {metadata_path}')
        metadata_bundle = load_rpiboot_metadata(str(metadata_path))
        if not metadata_bundle.get('loaded'):
            raise GGFWRuntimeError(
                f'--otp-metadata could not be loaded: {metadata_bundle.get("error") or "unknown metadata error"}'
            )

    if args.secure_boot_public_key:
        key_path = Path(args.secure_boot_public_key).expanduser().resolve()
        if not key_path.is_file():
            raise GGFWRuntimeError(f'--secure-boot-public-key file does not exist: {key_path}')
        if not os.access(key_path, os.R_OK):
            raise GGFWRuntimeError(f'--secure-boot-public-key file is not readable: {key_path}')
        try:
            public_key = parse_pem_rsa_public_key(str(key_path))
        except (OSError, SecureBootFormatError, UnicodeError) as exc:
            raise GGFWRuntimeError(f'--secure-boot-public-key is invalid: {exc}') from exc

    return metadata_bundle, public_key


from ggfw.errors import GGFWRuntimeError, SummaryInvariantError

def execute_main(run_callable) -> int:
    """Map an audit callable to the stable GGFW process exit contract."""
    try:
        return run_callable()
    except KeyboardInterrupt:
        print('\n[-] GGFW interrupted by operator.', file=sys.stderr)
        print('[*] Process exit classification: TOOL_ERROR', file=sys.stderr)
        print('[*] Process exit code: 1', file=sys.stderr)
        return 1
    except SummaryInvariantError as exc:
        print(f'[-] Summary accounting invariant failed: {exc}', file=sys.stderr)
        print('[*] Process exit classification: TOOL_ERROR', file=sys.stderr)
        print('[*] Process exit code: 1', file=sys.stderr)
        return 1
    except GGFWRuntimeError as exc:
        print(f'[-] GGFW runtime failure: {exc}', file=sys.stderr)
        print('[*] Process exit classification: TOOL_ERROR', file=sys.stderr)
        print('[*] Process exit code: 1', file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception('Unhandled GGFW failure')
        print(f'[-] GGFW unhandled failure: {exc}', file=sys.stderr)
        print('[*] Process exit classification: TOOL_ERROR', file=sys.stderr)
        print('[*] Process exit code: 1', file=sys.stderr)
        return 1
