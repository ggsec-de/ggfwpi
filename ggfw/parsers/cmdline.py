"""Extracted GGFW component: parsers.cmdline."""
from ggfw._compat import Dict, Optional, logger, os

class CmdlineTxtParser:
    @staticmethod
    def parse(filepath: str) -> Dict[str, Optional[str]]:
        params = {}
        if not os.path.exists(filepath):
            return params

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()

            for token in content.split():
                if '=' in token:
                    k, v = token.split('=', 1)
                    params[k.lower()] = v
                else:
                    params[token.lower()] = None
        except Exception as e:
            logger.error(f"Error parsing cmdline.txt: {e}")

        return params
