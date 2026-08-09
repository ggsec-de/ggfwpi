"""Extracted GGFW component: reporting.console."""
from ggfw._compat import (
    Any, List, Optional, Tuple, json, re,
)
from ggfw.constants import REASON_NONE
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport

def print_otp_summary(report: GGFWReport) -> None:
    decoded = report.raw_artifacts.get("otp_decoded", {})
    security = decoded.get("security", {})
    print("\n" + "-" * 68)
    print("  OTP DECODER SUMMARY")
    print("-" * 68)
    print(f"  Profile:                 {decoded.get('decoder_profile', 'UNKNOWN')}")
    print(f"  Decoder status:          {decoded.get('decoder_status', 'UNKNOWN')}")
    print(f"  OTP words collected:     {decoded.get('raw_word_count', 0)}")
    key = security.get("customer_key_hash", {})
    key_value = key.get("value")
    key_display = key.get("status", "UNKNOWN")
    if isinstance(key_value, str) and len(key_value) >= 8 and key.get("status") == "PROGRAMMED":
        key_display += f" ({key_value[:8]}...)"
    print(f"  Customer key hash:       {key_display}")
    print(f"  Secure Boot enablement:  {security.get('secure_boot_enablement', {}).get('status', 'UNKNOWN')}")
    print(f"  VC JTAG lock:            {security.get('vc_jtag_lock', {}).get('status', 'UNKNOWN')}")
    print(f"  Device private key:      {security.get('device_private_key', {}).get('status', 'UNKNOWN')}")

    unresolved = decoded.get("unresolved_security_fields", [])
    if not unresolved and decoded.get("unknown_fields"):
        unresolved = [{
            "field": "decoder_limitation",
            "status": "UNKNOWN",
            "source_rows": "NOT_AVAILABLE",
            "source": "DECODER",
            "reason": value,
        } for value in decoded.get("unknown_fields", [])]
    if unresolved:
        print(f"  Undecoded security data: {len(unresolved)} item(s)")
        print()
        print("  Unresolved security fields:")
        for item in unresolved:
            rows = item.get("source_rows", "NOT_AVAILABLE")
            if isinstance(rows, list):
                rows = ", ".join(str(row) for row in rows) if rows else "NOT_AVAILABLE"
            print(f"    - {item.get('field', 'unknown')}")
            print(f"      status: {item.get('status', 'UNKNOWN')}")
            print(f"      source rows: {rows}")
            print(f"      source: {item.get('source', 'UNKNOWN')}")
            if item.get("mask"):
                print(f"      mask: {item.get('mask')}")
            if item.get("reason"):
                print(f"      reason: {terminal_excerpt(item.get('reason'), limit=600)}")

def print_secure_boot_matrix(report: GGFWReport) -> None:
    matrix = report.raw_artifacts.get("secure_boot_evidence", {})
    ev = matrix.get("evidence", {})
    validation = matrix.get('chain_validation', {})
    public_key = validation.get('public_key', {})
    boot_image = validation.get('boot_image_signature', {})
    bootconf = validation.get('bootconf_signature', {})
    bootsys = validation.get('bootsys_customer_countersignature', {})
    print("\n" + "-" * 68)
    print("  SECURE BOOT CHAIN VALIDATION")
    print("-" * 68)
    print(f"  Overall:                     {matrix.get('overall', 'UNKNOWN')}")
    print(f"  Authenticity:                {matrix.get('authenticity', 'UNKNOWN')}")
    print(f"  Completeness:                {matrix.get('completeness', 'UNKNOWN')}")
    print(f"  Freshness:                   {matrix.get('freshness', 'UNKNOWN')}")
    print(f"  Policy:                      {matrix.get('policy', 'UNKNOWN')}")
    print(f"  OTP customer key:            {ev.get('customer_key_hash', {}).get('status', 'UNKNOWN')}")
    print(f"  Secure Boot enablement:      {ev.get('secure_boot_enablement', {}).get('status', 'UNKNOWN')}")
    print(f"  Public key relationship:     {public_key.get('source_relationship', 'UNKNOWN')}")
    print(f"  Public key ↔ OTP binding:    {public_key.get('otp_binding', 'UNKNOWN')}")
    bootconf_reason = bootconf.get('reason_code')
    bootsys_reason = bootsys.get('reason_code')
    boot_image_reason = boot_image.get('reason_code')
    print(
        f"  EEPROM bootconf signature:   {bootconf.get('overall', 'UNKNOWN')}"
        + (f" ({bootconf_reason})" if bootconf_reason and bootconf_reason != REASON_NONE else '')
    )
    bootconf_classes = bootconf.get('content_classes', [])
    if bootconf_classes:
        print(
            f"    content class:            {', '.join(str(item) for item in bootconf_classes)}"
        )
        print(
            f"    signature sections:       {bootconf.get('section_present_count', len(bootconf_classes))}; "
            f"effective signatures: {bootconf.get('effective_signature_present_count', 0)}"
        )
    print(
        f"  BCM2712 bootsys countersig:  {bootsys.get('overall', 'UNKNOWN')}"
        + (f" ({bootsys_reason})" if bootsys_reason and bootsys_reason != REASON_NONE else '')
    )
    print(
        f"  boot.img digest/signature:   {boot_image.get('overall', 'UNKNOWN')}"
        + (f" ({boot_image_reason})" if boot_image_reason and boot_image_reason != REASON_NONE else '')
    )
    print(f"    digest:                    {boot_image.get('digest_status', 'UNKNOWN')}")
    print(f"    RSA PKCS#1 v1.5:           {boot_image.get('rsa_signature_status', 'UNKNOWN')}")
    print(f"    target SoC:                {boot_image.get('target_soc_status', 'UNKNOWN')}")
    print(f"    signature timestamp:       {boot_image.get('freshness_status', 'UNKNOWN')}")

def terminal_excerpt(value: Any, limit: int = 420) -> str:
    """Render evidence safely on one terminal line without flooding the console."""
    text = re.sub(r'\s+', ' ', str(value or '')).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + '...'

def sort_findings_for_display(findings: List[Finding]) -> List[Finding]:
    severity_rank = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    return sorted(findings, key=lambda item: (-severity_rank.get(item.severity, 0), item.rule_id))

def _print_aligned_rows(rows: List[Tuple[int, str, Any]]) -> None:
    """Print label/value rows with one shared value column, including nested rows."""
    if not rows:
        return
    width = max(indent + len(label) for indent, label, _value in rows)
    for indent, label, value in rows:
        prefix = (' ' * indent) + label
        print(prefix + (' ' * (width - len(prefix) + 2)) + str(value))

def _counted_noun(count: int, singular: str, plural: Optional[str] = None) -> str:
    """Return a count with the grammatically correct English noun form."""
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"

def print_scan_summary(report: GGFWReport):
    report.calculate_summary()
    summary = report.summary
    print("\n" + "=" * 68)
    print("  SCAN SUMMARY")
    print("=" * 68)
    print("  FINDING COUNTS")
    _print_aligned_rows([
        (4, "Total findings:", summary['total_findings']),
        (4, "Actionable security/policy findings:", summary['actionable_security_policy']),
        (4, "Evidence acquisition required:", summary['evidence_required']),
        (4, "Aggregate rollups:", summary['aggregate_rollups']),
        (4, "Other non-actionable findings:", summary['other_non_actionable']),
        (6, "Informational only:", summary['informational_only']),
        (6, "Coverage-gap only:", summary['non_actionable_coverage_gaps']),
        (6, "Policy-not-required only:", summary['policy_not_required_only']),
        (6, "Multi-attribute passive:", summary['multi_attribute_passive']),
    ])
    print()
    print("  CROSS-CUTTING ATTRIBUTES")
    _print_aligned_rows([
        (4, "Coverage gaps overall:", summary['coverage_gaps_total']),
        (4, "Policy not required overall:", summary['policy_not_required_total']),
        (4, "Aggregate findings overall:", summary['aggregate_findings_total']),
        (4, "Evidence required overall:", summary['evidence_required_total']),
    ])
    print()
    print("  REMEDIATION VIEW")
    _print_aligned_rows([
        (4, "Independent remediation tasks:", summary['remediation_tasks']),
        (4, "Evidence acquisition tasks:", summary['evidence_acquisition_tasks']),
        (4, "Positive checks:", summary['positive_checks']),
    ])
    print()
    print(
        f"  CRITICAL: {summary['CRITICAL']} | HIGH: {summary['HIGH']} | "
        f"MEDIUM: {summary['MEDIUM']} | LOW: {summary['LOW']} | INFO: {summary['INFO']}"
    )
    evidence_context = summary.get('evidence_context', {})
    print(
        f"  Evidence context: {evidence_context.get('acquisition_context', 'UNKNOWN')} | "
        f"max trust={evidence_context.get('maximum_trust_achieved', 'UNKNOWN')} | "
        f"external={'YES' if evidence_context.get('external_acquisition_supplied') else 'NO'}"
    )
    print("  Domain severity:")
    for domain in ('BOOT_AND_EEPROM', 'PLATFORM_HARDWARE', 'OS_RUNTIME', 'EVIDENCE_COVERAGE'):
        values = summary['domains'].get(domain)
        if not values:
            continue
        print(
            f"    {domain}: total={values['total']}, actions={values['actionable']}, "
            f"evidence={values['evidence_required']}, aggregates={values['aggregates']}, "
            f"C={values['CRITICAL']} H={values['HIGH']} M={values['MEDIUM']} "
            f"L={values['LOW']} I={values['INFO']}"
        )
    invariant_ok = summary.get('summary_accounting', {}).get('all_invariants_satisfied') is True
    print(f"[*] Summary accounting invariant: {'PASS' if invariant_ok else 'FAIL'}")
    print("=" * 68)

def print_positive_checks(report: GGFWReport):
    print("\n" + "-" * 68)
    print("  POSITIVE CHECKS")
    print("-" * 68)
    if not report.positive_checks:
        print("  None recorded.")
        return
    for check in report.positive_checks:
        evidence = terminal_excerpt(json.dumps(check.evidence, ensure_ascii=False))
        print(f"  [PASS] {check.check_id}: {check.description}")
        if evidence and evidence != '{}':
            print(f"    Evidence: {evidence}")

def print_trust_model(report: GGFWReport):
    """Print the evidence trust legend and the trust actually achieved by this scan."""
    report.calculate_summary()
    context = report.summary.get('evidence_context', {})
    print("\n" + "-" * 68)
    print("  EVIDENCE TRUST MODEL")
    print("-" * 68)
    print("  HIGH   Independently acquired offline/external evidence or a verified trusted artifact.")
    print("  MEDIUM Evidence mediated by the examined OS, firmware interface, or local baseline.")
    print("  LOW    Indirect, heuristic, or incomplete evidence.")
    print()
    print(f"  Acquisition context:        {context.get('acquisition_context', 'UNKNOWN')}")
    print(f"  Maximum trust achieved:     {context.get('maximum_trust_achieved', 'UNKNOWN')}")
    print(
        "  External acquisition used: "
        + ("YES" if context.get('external_acquisition_supplied') else "NO")
    )
    if not context.get('external_acquisition_supplied'):
        print("  Note: MEDIUM is the normal maximum for this in-band scan. HIGH requires")
        print("        external/offline acquisition or a separately verified trusted artifact.")

def print_remediation_summary(report: GGFWReport):
    actionable = [
        f for f in report.findings
        if f.actionable and not f.coverage_gap and not f.aggregate
    ]
    evidence_tasks = [
        f for f in report.findings
        if f.evidence_required and not f.aggregate
    ]

    print("\n" + "=" * 68)
    print("  REMEDIATION SUMMARY")
    print("=" * 68)
    if not actionable:
        print("  NO ACTIONABLE SECURITY OR POLICY FINDINGS DETECTED")
    else:
        labels = (
            ('CRITICAL', 'Immediate action required'),
            ('HIGH', 'Action required soon'),
            ('MEDIUM', 'Recommended'),
            ('LOW', 'Best practice / policy dependent'),
        )
        for severity, label in labels:
            findings = sorted(
                [f for f in actionable if f.severity == severity],
                key=lambda item: item.rule_id,
            )
            if not findings:
                continue
            print(f"\n  {severity} ({label}):")
            print("  " + "-" * 58)
            for finding in findings:
                print(f"  - {finding.rule_id}: {finding.description}")
                if finding.observed:
                    print(f"    Observed: {terminal_excerpt(finding.observed)}")
                if finding.severity in {'CRITICAL', 'HIGH'} and finding.expected:
                    print(f"    Expected: {terminal_excerpt(finding.expected)}")
                if finding.rationale:
                    print(f"    Rationale: {terminal_excerpt(finding.rationale)}")
                if finding.remediation_group:
                    print(f"    Remediation group: {finding.remediation_group}")
                print(f"    Fix: {finding.remediation}")
                print()

    if evidence_tasks:
        print("\n  EVIDENCE ACQUISITION REQUIRED:")
        print("  " + "-" * 58)
        for finding in sorted(evidence_tasks, key=lambda item: item.rule_id):
            print(f"  - {finding.rule_id}: {finding.description}")
            if finding.observed:
                print(f"    Observed: {terminal_excerpt(finding.observed)}")
            print(f"    Acquire: {finding.remediation}")
            print()

    task_groups = {(f.remediation_group or f.rule_id) for f in actionable}
    evidence_groups = {(f.remediation_group or f.rule_id) for f in evidence_tasks}
    print("=" * 68)
    print(f"  SECURITY/POLICY FINDINGS: {len(actionable)}")
    print(f"  REMEDIATION: {len(task_groups)} independent {'task' if len(task_groups) == 1 else 'tasks'}")
    print(
        "  EVIDENCE: "
        + _counted_noun(len(evidence_tasks), "finding")
        + " / "
        + _counted_noun(len(evidence_groups), "acquisition task", "acquisition tasks")
    )
    print("=" * 68)
