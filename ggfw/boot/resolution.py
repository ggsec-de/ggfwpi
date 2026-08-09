"""Extracted GGFW component: boot.resolution."""
from ggfw._compat import (
    Any, Dict, List, Optional, Path, Set, Tuple, hashlib, json, os,
)
from ggfw.files import sha256_file
from ggfw.hardware.platform import get_soc_generation

class BootResolutionGraphBuilder:
    """Resolve the effective Pi boot components for the detected board profile."""

    MULTI_KEYS = {'dtoverlay', 'dtparam', 'initramfs'}

    def __init__(self, boot_dir: str, platform: str, config_detail: Dict[str, Any]):
        self.boot_dir = Path(boot_dir).expanduser().resolve()
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.detail = config_detail

    @staticmethod
    def _safe_relative(value: str) -> Optional[str]:
        candidate = value.strip().replace('\\', '/')
        if not candidate or candidate.startswith('/'):
            return None
        normalised = os.path.normpath(candidate)
        if normalised == '..' or normalised.startswith('../'):
            return None
        return normalised

    def _active_values(self) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
        scalar: Dict[str, str] = {}
        multi: Dict[str, List[str]] = {key: [] for key in self.MULTI_KEYS}
        for directive in self.detail.get('active_directives', []):
            key = directive['key']
            value = directive['value']
            if key in self.MULTI_KEYS:
                multi.setdefault(key, []).append(value)
            else:
                scalar[key] = value
        return scalar, multi

    def _node(self, node_id: str, role: str, relative_path: Optional[str], source: str) -> Dict[str, Any]:
        node: Dict[str, Any] = {
            'id': node_id,
            'role': role,
            'path': relative_path,
            'source': source,
            'exists': None,
            'size': None,
            'sha256': None,
        }
        if relative_path:
            safe = self._safe_relative(relative_path)
            if safe:
                path = self.boot_dir / safe
                node['path'] = safe
                node['exists'] = path.is_file()
                if path.is_file():
                    try:
                        node['size'] = path.stat().st_size
                    except OSError:
                        pass
                    node['sha256'] = sha256_file(str(path))
            else:
                node['exists'] = False
                node['error'] = 'unsafe path'
        return node

    def build(self) -> Dict[str, Any]:
        scalar, multi = self._active_values()
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        active_files: Set[str] = {'config.txt'}

        config_node = self._node('config', 'CONFIG', 'config.txt', 'config.txt')
        nodes.append(config_node)
        for parsed in self.detail.get('parsed_files', []):
            try:
                rel = str(Path(parsed).resolve().relative_to(self.boot_dir))
            except (OSError, ValueError):
                continue
            active_files.add(rel)

        if self.soc == 'BCM2712':
            kernel_default = 'kernel_2712.img'
            dtb_default = 'bcm2712-rpi-5-b.dtb'
        elif self.soc == 'BCM2711':
            kernel_default = 'kernel8.img'
            dtb_default = 'bcm2711-rpi-4-b.dtb'
        else:
            kernel_default = 'kernel7.img'
            dtb_default = None

        kernel = scalar.get('kernel', kernel_default)
        dtb = scalar.get('device_tree', dtb_default)
        cmdline = scalar.get('cmdline', 'cmdline.txt')
        armstub = scalar.get('armstub')

        for node_id, role, value, source in (
            ('kernel', 'KERNEL', kernel, 'kernel/default'),
            ('dtb', 'DEVICE_TREE', dtb, 'device_tree/default'),
            ('cmdline', 'KERNEL_CMDLINE', cmdline, 'cmdline/default'),
            ('armstub', 'EL3_STUB', armstub, 'armstub'),
        ):
            if not value or str(value).strip().lower() in {'-', 'none', 'disable'}:
                continue
            node = self._node(node_id, role, value, source)
            nodes.append(node)
            if node.get('path'):
                active_files.add(node['path'])
            edges.append({'from': 'config', 'to': node_id, 'relation': 'SELECTS'})

        explicit_initramfs: List[str] = []
        for value in multi.get('initramfs', []):
            filename = value.split()[0] if value.split() else ''
            if filename:
                explicit_initramfs.append(filename)
        if explicit_initramfs:
            initramfs_files = explicit_initramfs
            initramfs_source = 'initramfs directive'
        elif scalar.get('auto_initramfs') == '1':
            candidates = []
            preferred = ['initramfs_2712', 'initramfs8'] if self.soc == 'BCM2712' else ['initramfs8']
            for name in preferred:
                if (self.boot_dir / name).is_file():
                    candidates.append(name)
            if not candidates:
                candidates = sorted(path.name for path in self.boot_dir.glob('initramfs*') if path.is_file())
            initramfs_files = candidates
            initramfs_source = 'auto_initramfs=1'
        else:
            initramfs_files = []
            initramfs_source = 'not configured'

        for index, filename in enumerate(initramfs_files):
            node_id = f'initramfs-{index}'
            node = self._node(node_id, 'INITRAMFS', filename, initramfs_source)
            nodes.append(node)
            if node.get('path'):
                active_files.add(node['path'])
            edges.append({'from': 'config', 'to': node_id, 'relation': 'SELECTS'})
            if any(n['id'] == 'kernel' for n in nodes):
                edges.append({'from': node_id, 'to': 'kernel', 'relation': 'ACCOMPANIES'})

        overlay_nodes = []
        for index, value in enumerate(multi.get('dtoverlay', [])):
            if not value or value.startswith('-'):
                continue
            overlay_name = value.split(',', 1)[0].strip()
            if not overlay_name:
                continue
            filename = overlay_name if overlay_name.endswith('.dtbo') else f'overlays/{overlay_name}.dtbo'
            node_id = f'overlay-{index}'
            node = self._node(node_id, 'DEVICE_TREE_OVERLAY', filename, f'dtoverlay={value}')
            node['arguments'] = value.split(',')[1:]
            nodes.append(node)
            overlay_nodes.append(node_id)
            if node.get('path'):
                active_files.add(node['path'])
            edges.append({'from': 'dtb', 'to': node_id, 'relation': 'APPLIES_OVERLAY'})

        active_directive_view = [
            {
                'sequence': d['sequence'], 'source': d['source'], 'line': d['line'],
                'section': d['section'], 'key': d['key'], 'value': d['value'],
            }
            for d in self.detail.get('active_directives', [])
        ]
        fingerprint_payload = {
            'soc': self.soc,
            'active_directives': active_directive_view,
            'active_files': sorted(active_files),
            'edges': edges,
        }
        fingerprint = hashlib.sha256(
            json.dumps(fingerprint_payload, sort_keys=True, separators=(',', ':')).encode()
        ).hexdigest()

        text_lines = [f'Platform: {self.platform}', 'config.txt']
        role_order = ['EL3_STUB', 'KERNEL', 'INITRAMFS', 'DEVICE_TREE', 'DEVICE_TREE_OVERLAY', 'KERNEL_CMDLINE']
        for role in role_order:
            for node in nodes:
                if node['role'] == role:
                    state = 'present' if node.get('exists') else 'missing'
                    text_lines.append(f"  -> {role}: {node.get('path')} [{state}]")

        return {
            'schema': 'ggfw-boot-resolution/v1',
            'platform': self.platform,
            'soc': self.soc,
            'nodes': nodes,
            'edges': edges,
            'active_files': sorted(active_files),
            'active_directives': active_directive_view,
            'inactive_or_unknown_directives': [
                d for d in self.detail.get('directives', []) if d.get('applicability') != 'ACTIVE'
            ],
            'fingerprint': fingerprint,
            'text': '\n'.join(text_lines),
        }
