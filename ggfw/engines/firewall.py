"""Best-effort firewall configuration evidence, not a packet-reachability proof."""
import json
import os
import re
import shlex
import subprocess


def _reachable_restriction(roots, edges, restrictive):
    pending, seen = list(roots), set()
    while pending:
        chain = pending.pop()
        if chain in seen:
            continue
        seen.add(chain)
        if chain in restrictive:
            return True
        pending.extend(edges.get(chain, ()))
    return False


def _iptables_configured(text):
    roots, restrictive, edges = set(), set(), {}
    for line in text.splitlines():
        tokens = shlex.split(line)
        if not tokens:
            continue
        if tokens[0] == '-P' and len(tokens) == 3:
            if tokens[1] in {'INPUT', 'FORWARD', 'OUTPUT'}:
                roots.add(tokens[1])
                if tokens[2] == 'DROP':
                    restrictive.add(tokens[1])
        elif tokens[0] == '-A' and len(tokens) >= 4:
            # Quoted comments remain single tokens; never search the raw line.
            targets = [i for i in range(2, len(tokens) - 1) if tokens[i] in ('-j', '-g')]
            if targets:
                target = tokens[targets[-1] + 1]
                if target in {'DROP', 'REJECT'}:
                    restrictive.add(tokens[1])
                else:
                    edges.setdefault(tokens[1], set()).add(target)
        elif tokens[0] != '-N':
            raise ValueError('unrecognized iptables rule format')
    return _reachable_restriction(roots, edges, restrictive)


def _nft_configured(text):
    payload = json.loads(text)
    if not isinstance(payload, dict) or not isinstance(payload.get('nftables'), list):
        raise ValueError('missing nftables list')
    roots, restrictive, edges = set(), set(), {}
    unsupported_verdict = False
    for entry in payload['nftables']:
        if not isinstance(entry, dict):
            raise ValueError('invalid nftables entry')
        chain = entry.get('chain')
        if chain is not None:
            key = (chain['family'], chain['table'], chain['name'])
            if chain.get('type') == 'filter' and chain.get('hook') in {
                'input', 'forward', 'output', 'ingress', 'egress', 'prerouting', 'postrouting',
            }:
                roots.add(key)
                if chain.get('policy') == 'drop':
                    restrictive.add(key)
        rule = entry.get('rule')
        if rule is not None:
            key = (rule['family'], rule['table'], rule['chain'])
            for expr in rule['expr']:
                if not isinstance(expr, dict):
                    raise ValueError('invalid nftables expression')
                if 'drop' in expr or 'reject' in expr:
                    restrictive.add(key)
                for verb in ('jump', 'goto'):
                    if verb in expr:
                        target = (key[0], key[1], expr[verb]['target'])
                        edges.setdefault(key, set()).add(target)
                # Verdict maps require an evaluator; do not report absence.
                if 'vmap' in expr:
                    unsupported_verdict = True
    if _reachable_restriction(roots, edges, restrictive):
        return True
    if unsupported_verdict:
        raise ValueError('nftables verdict maps require manual review')
    return False


def _ufw_configured(text):
    statuses = re.findall(r'^\s*Status:\s*(active|inactive)\s*$', text, re.MULTILINE | re.IGNORECASE)
    if len(statuses) != 1:
        raise ValueError('unrecognized ufw status')
    return statuses[0].lower() == 'active'


def inspect_firewalls():
    """Record configured filtering, absent evidence, and acquisition gaps separately.

    A UFW active status or a reachable DROP/REJECT configuration is evidence of
    configuration only. Rule ordering, packet matches, interfaces and address
    families must still be reviewed to establish actual network protection.
    """
    observations = []
    checks = (
        ('ufw', ['ufw', 'status'], _ufw_configured),
        ('nftables', ['nft', '-j', 'list', 'ruleset'], _nft_configured),
        ('iptables', ['iptables', '-S'], _iptables_configured),
        ('ip6tables', ['ip6tables', '-S'], _iptables_configured),
    )
    for name, command, parse in checks:
        state, detail = 'UNKNOWN', 'inspection failed'
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10,
                                    env={**os.environ, 'LC_ALL': 'C'})
            if result.returncode != 0:
                detail = f'command exit {result.returncode}'
            else:
                configured = parse(result.stdout)
                state = 'CONFIGURED' if configured else 'NOT_CONFIGURED'
                detail = 'supported filtering configuration' if configured else 'no supported filtering configuration'
        except FileNotFoundError:
            state, detail = 'UNAVAILABLE', 'tool not installed'
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
            detail = 'command unavailable, timed out, or output unsupported'
        observations.append({'tool': name, 'state': state, 'detail': detail})
    return observations
