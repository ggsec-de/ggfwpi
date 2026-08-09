"""Extracted GGFW component: reporting.gates."""
from ggfw._compat import (
    Any, Dict, List, Optional, Set, Tuple,
)
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport

def _gate_candidate_findings(report: GGFWReport, fail_on: str) -> List[Finding]:
    """Return every finding considered by the selected policy before exclusions."""
    policy = fail_on.upper()
    if policy == 'NONE':
        return []
    if policy == 'COVERAGE_GAP':
        return [f for f in report.findings if f.coverage_gap]
    if policy == 'ACTIONABLE':
        return [f for f in report.findings if bool(f.actionable)]
    if policy == 'ANY':
        return list(report.findings)

    rank = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    threshold = rank[policy]
    return [f for f in report.findings if rank.get(f.severity, 0) >= threshold]

def _gate_exclusion_reasons(
    finding: Finding,
    fail_on: str,
    explicit_exclusions: Set[str],
    fail_on_coverage: bool,
) -> Tuple[List[str], List[str]]:
    """Return stable exclusion reasons and their policy sources for one candidate."""
    policy = fail_on.upper()
    reasons: List[str] = []
    sources: List[str] = []

    def add(reason: str, source: str) -> None:
        if reason not in reasons:
            reasons.append(reason)
        if source not in sources:
            sources.append(source)

    if finding.applicability == 'NOT_REQUIRED':
        add('NOT_REQUIRED', 'APPLICABILITY')
    elif finding.applicability == 'NOT_APPLICABLE':
        add('NOT_APPLICABLE', 'APPLICABILITY')

    if finding.aggregate:
        add('AGGREGATE', 'LEAF_ONLY_GATE')

    if policy not in {'NONE', 'COVERAGE_GAP'} and finding.coverage_gap and not fail_on_coverage:
        add('COVERAGE_GAP', 'DEFAULT_SEVERITY_GATE')

    if 'COVERAGE_GAP' in explicit_exclusions and finding.coverage_gap:
        add('COVERAGE_GAP', 'EXPLICIT_GATE_EXCLUSION')
    if 'AGGREGATE' in explicit_exclusions and finding.aggregate:
        add('AGGREGATE', 'EXPLICIT_GATE_EXCLUSION')

    gate_classes = {'SECURITY_FINDING', 'POLICY_FAILURE', 'VENDOR_DEFAULT_CREDENTIAL'}
    if policy in {'ANY', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        class_allowed = (
            finding.finding_class in gate_classes
            or (finding.finding_class == 'CAPABILITY_GAP' and finding.applicability == 'REQUIRED')
            or (finding.coverage_gap and fail_on_coverage)
        )
        if not class_allowed and not finding.coverage_gap:
            add('NON_GATING_CLASS', 'FINDING_CLASS_POLICY')

    return reasons, sources

def build_gate_accounting(
    report: GGFWReport,
    fail_on: str,
    gate_exclusions: Optional[List[str]] = None,
    fail_on_coverage: bool = False,
) -> Dict[str, Any]:
    """Partition every policy candidate into MATCHED or EXCLUDED with explicit reasons."""
    exclusions = {str(value).upper() for value in (gate_exclusions or [])}
    candidates = sorted(_gate_candidate_findings(report, fail_on), key=lambda f: f.rule_id)
    matched: List[Finding] = []
    excluded: List[Tuple[Finding, List[str], List[str]]] = []

    for finding in candidates:
        reasons, sources = _gate_exclusion_reasons(
            finding, fail_on, exclusions, fail_on_coverage
        )
        if reasons:
            excluded.append((finding, reasons, sources))
        else:
            matched.append(finding)

    matched_rules = [f.rule_id for f in matched]
    excluded_rules = [f.rule_id for f, _reasons, _sources in excluded]
    candidate_rules = [f.rule_id for f in candidates]
    matched_details = policy_match_details(report, matched_rules)
    excluded_reason_map = {f.rule_id: (reasons, sources) for f, reasons, sources in excluded}
    excluded_details = policy_match_details(report, excluded_rules)
    for item in excluded_details:
        reasons, sources = excluded_reason_map[item['rule_id']]
        item['exclusion_reasons'] = list(reasons)
        item['exclusion_sources'] = list(sources)
        item['disposition'] = 'EXCLUDED'
    for item in matched_details:
        item['exclusion_reasons'] = []
        item['exclusion_sources'] = []
        item['disposition'] = 'MATCHED'

    invariant_ok = len(candidate_rules) == len(matched_rules) + len(excluded_rules)
    return {
        'policy': fail_on.upper(),
        'threshold_candidate_count': len(candidate_rules),
        'threshold_candidates': candidate_rules,
        'matching_count': len(matched_rules),
        'matching_rules': matched_rules,
        'matching_findings': matched_details,
        'excluded_count': len(excluded_rules),
        'excluded_rules': excluded_rules,
        'excluded_findings': excluded_details,
        'accounting_invariant': {
            'expression': 'threshold_candidates == matching_findings + excluded_findings',
            'satisfied': invariant_ok,
        },
    }

def evaluate_fail_policy(
    report: GGFWReport,
    fail_on: str,
    gate_exclusions: Optional[List[str]] = None,
    fail_on_coverage: bool = False,
) -> Tuple[int, List[str], List[str]]:
    """Compatibility wrapper over the auditable gate-accounting model."""
    accounting = build_gate_accounting(
        report, fail_on, gate_exclusions, fail_on_coverage
    )
    matches = list(accounting['matching_rules'])
    excluded = list(accounting['excluded_rules'])
    return (2 if matches else 0, matches, excluded)

def policy_match_details(report: GGFWReport, rule_ids: List[str]) -> List[Dict[str, Any]]:
    """Return structured descriptions of findings that triggered the CI policy."""
    selected = set(rule_ids)
    details: List[Dict[str, Any]] = []
    for finding in report.findings:
        if finding.rule_id not in selected:
            continue
        gate_reason = 'COVERAGE_GAP' if finding.coverage_gap else finding.finding_class
        details.append({
            'rule_id': finding.rule_id,
            'severity': finding.severity,
            'status': finding.status,
            'gate_reason': gate_reason,
            'actionable': bool(finding.actionable),
            'aggregate': bool(finding.aggregate),
            'blocked_by': list(finding.blocked_by),
            'remediation_group': finding.remediation_group,
        })
    return sorted(details, key=lambda item: item['rule_id'])

def build_secure_boot_policy_rollup(
    report: GGFWReport,
    policy_profile: str,
    secure_boot_matrix: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the policy rollup from the policy-aware matrix, never the raw crypto validator."""
    matrix = secure_boot_matrix or report.raw_artifacts.get('secure_boot_evidence', {})
    matrix_policy_result = str(matrix.get('policy', 'UNKNOWN')).upper()
    policy_finding = next((f for f in report.findings if f.rule_id == 'RPI-SB-001'), None)
    evidence_limits = sorted({
        f.rule_id for f in report.findings
        if f.coverage_gap and not f.aggregate and f.remediation_group == 'SECURE_BOOT_ENABLEMENT'
    })

    if policy_profile == 'secure-boot-required':
        if policy_finding is not None:
            result = 'FAIL'
        elif matrix_policy_result in {'PASS', 'FAIL', 'UNVERIFIED'}:
            result = matrix_policy_result
        else:
            result = 'UNVERIFIED'
    elif matrix_policy_result in {'PASS', 'FAIL', 'REVIEW', 'UNVERIFIED', 'NOT_REQUIRED'}:
        result = matrix_policy_result
    else:
        result = 'UNKNOWN'

    invariant_ok = not (
        policy_profile == 'secure-boot-required'
        and policy_finding is not None
        and result != 'FAIL'
    )
    return {
        'profile': policy_profile,
        'result': result,
        'matrix_policy_result': matrix_policy_result,
        'primary_finding': policy_finding.rule_id if policy_finding else None,
        'evidence_limitations': evidence_limits,
        'invariants': {
            'required_profile_with_policy_finding_is_fail': invariant_ok,
        },
    }

def print_secure_boot_policy_rollup(policy_rollup: Dict[str, Any], policy_profile: str) -> None:
    """Print the selected policy result without conflating it with per-finding applicability."""
    if policy_profile != 'secure-boot-required':
        return
    print(f"[!] Secure Boot policy: {policy_rollup.get('result', 'UNKNOWN')}")
    print(f"    Primary policy finding: {policy_rollup.get('primary_finding') or 'none'}")
    limits = policy_rollup.get('evidence_limitations', [])
    print(f"    Evidence limitations: {', '.join(limits) if limits else 'none'}")

def print_gate_accounting(
    fail_on: str,
    policy_exit_code: int,
    accounting: Dict[str, Any],
    explicit_exclusions: Optional[List[str]] = None,
) -> None:
    """Print a complete, auditable partition of all gate candidates."""
    if fail_on == 'NONE':
        return
    state = 'TRIGGERED' if policy_exit_code == 2 else 'NOT_TRIGGERED'
    print(f'[*] Exit policy --fail-on {fail_on}: {state}')
    print(
        f"[*] Gate accounting: candidates={accounting['threshold_candidate_count']}, "
        f"matched={accounting['matching_count']}, "
        f"excluded={accounting['excluded_count']}"
    )
    if explicit_exclusions:
        print(f"[*] Explicit gate exclusions: {', '.join(explicit_exclusions)}")

    print('    Matching findings:')
    matched = accounting.get('matching_findings', [])
    if not matched:
        print('    - none')
    for item in matched:
        relation = ""
        if item.get('blocked_by'):
            relation += f" blocked_by={','.join(item['blocked_by'])}"
        print(
            f"    - {item['rule_id']} {item['severity']} {item['gate_reason']} "
            f"(status={item['status']}){relation}"
        )

    print('    Excluded findings:')
    excluded = accounting.get('excluded_findings', [])
    if not excluded:
        print('    - none')
    for item in excluded:
        relation = ""
        if item.get('blocked_by'):
            relation += f" blocked_by={','.join(item['blocked_by'])}"
        reasons = ','.join(item.get('exclusion_reasons', [])) or 'UNSPECIFIED'
        print(
            f"    - {item['rule_id']} {item['severity']} "
            f"(status={item['status']}) reasons={reasons}{relation}"
        )

    invariant = accounting.get('accounting_invariant', {})
    print(
        "[*] Gate accounting invariant: "
        + ('PASS' if invariant.get('satisfied') else 'FAIL')
    )
