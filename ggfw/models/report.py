"""Extracted GGFW component: models.report."""
from ggfw._compat import (
    Any, Dict, List, Set, asdict, dataclass, field, json,
)
from ggfw.constants import REPORT_SCHEMA, TOOL_VERSION
from ggfw.errors import SummaryInvariantError
from ggfw.models.findings import Finding, PositiveCheck

SUMMARY_CROSS_CUTTING_COUNTERS = (
    "coverage_gaps_overall",
    "policy_not_required_overall",
    "aggregate_findings_overall",
    "evidence_required_overall",
)

def _rule_ids(findings: List[Finding]) -> List[str]:
    return [finding.rule_id for finding in findings]

def _duplicate_values(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    duplicates: Set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)

def _pairwise_rule_id_overlaps(partitions: Dict[str, List[Finding]]) -> Dict[str, List[str]]:
    names = list(partitions)
    overlaps: Dict[str, List[str]] = {}
    for index, left_name in enumerate(names):
        left = set(_rule_ids(partitions[left_name]))
        for right_name in names[index + 1:]:
            shared = sorted(left & set(_rule_ids(partitions[right_name])))
            if shared:
                overlaps[f"{left_name}__{right_name}"] = shared
    return overlaps

def build_summary_accounting(
    findings: List[Finding],
    summary: Dict[str, Any],
    top_level: Dict[str, List[Finding]],
    passive_subgroups: Dict[str, List[Finding]],
) -> Dict[str, Any]:
    """Build machine-verifiable accounting for every summary partition."""
    all_rule_ids = _rule_ids(findings)
    top_level_rule_ids = {
        name: _rule_ids(items) for name, items in top_level.items()
    }
    passive_rule_ids = {
        name: _rule_ids(items) for name, items in passive_subgroups.items()
    }

    top_level_actual = sum(len(items) for items in top_level.values())
    passive_expected = len(top_level["other_non_actionable"])
    passive_actual = sum(len(items) for items in passive_subgroups.values())
    severity_actual = sum(int(summary.get(severity, 0)) for severity in (
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    ))
    domain_actual = sum(
        int(domain.get("total", 0)) for domain in summary.get("domains", {}).values()
    )
    domain_severity_partitions = {
        domain_name: {
            "expected": int(values.get("total", 0)),
            "actual": sum(int(values.get(severity, 0)) for severity in (
                "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
            )),
        }
        for domain_name, values in summary.get("domains", {}).items()
    }
    for item in domain_severity_partitions.values():
        item["satisfied"] = item["expected"] == item["actual"]

    top_level_overlaps = _pairwise_rule_id_overlaps(top_level)
    passive_overlaps = _pairwise_rule_id_overlaps(passive_subgroups)
    top_level_union = set().union(*(set(ids) for ids in top_level_rule_ids.values())) if top_level_rule_ids else set()
    passive_union = set().union(*(set(ids) for ids in passive_rule_ids.values())) if passive_rule_ids else set()
    expected_all_ids = set(all_rule_ids)
    expected_passive_ids = set(top_level_rule_ids["other_non_actionable"])

    direct_cross_cutting = {
        "coverage_gaps_overall": sum(1 for finding in findings if finding.coverage_gap),
        "policy_not_required_overall": sum(
            1 for finding in findings
            if finding.applicability in {"NOT_APPLICABLE", "NOT_REQUIRED"}
        ),
        "aggregate_findings_overall": sum(1 for finding in findings if finding.aggregate),
        "evidence_required_overall": sum(1 for finding in findings if finding.evidence_required),
    }
    summary_cross_cutting = {
        "coverage_gaps_overall": int(summary.get("coverage_gaps_total", -1)),
        "policy_not_required_overall": int(summary.get("policy_not_required_total", -1)),
        "aggregate_findings_overall": int(summary.get("aggregate_findings_total", -1)),
        "evidence_required_overall": int(summary.get("evidence_required_total", -1)),
    }
    cross_cutting_checks = {
        name: {
            "expected": expected,
            "actual": summary_cross_cutting[name],
            "satisfied": expected == summary_cross_cutting[name],
        }
        for name, expected in direct_cross_cutting.items()
    }

    accounting: Dict[str, Any] = {
        "schema": "ggfw-summary-accounting/v1",
        "top_level_partition": {
            "expected": len(findings),
            "actual": top_level_actual,
            "bucket_counts": {name: len(items) for name, items in top_level.items()},
            "bucket_rule_ids": top_level_rule_ids,
            "satisfied": top_level_actual == len(findings),
        },
        "passive_partition": {
            "expected": passive_expected,
            "actual": passive_actual,
            "bucket_counts": {name: len(items) for name, items in passive_subgroups.items()},
            "bucket_rule_ids": passive_rule_ids,
            "satisfied": passive_actual == passive_expected,
        },
        "severity_partition": {
            "expected": len(findings),
            "actual": severity_actual,
            "satisfied": severity_actual == len(findings),
        },
        "domain_partition": {
            "expected": len(findings),
            "actual": domain_actual,
            "satisfied": domain_actual == len(findings),
        },
        "domain_severity_partitions": domain_severity_partitions,
        "unique_rule_ids": {
            "expected": len(findings),
            "actual": len(expected_all_ids),
            "duplicates": _duplicate_values(all_rule_ids),
            "satisfied": len(expected_all_ids) == len(findings),
        },
        "top_level_rule_id_disjointness": {
            "overlaps": top_level_overlaps,
            "satisfied": not top_level_overlaps,
        },
        "passive_rule_id_disjointness": {
            "overlaps": passive_overlaps,
            "satisfied": not passive_overlaps,
        },
        "top_level_rule_id_coverage": {
            "missing": sorted(expected_all_ids - top_level_union),
            "unexpected": sorted(top_level_union - expected_all_ids),
            "satisfied": top_level_union == expected_all_ids,
        },
        "passive_rule_id_coverage": {
            "missing": sorted(expected_passive_ids - passive_union),
            "unexpected": sorted(passive_union - expected_passive_ids),
            "satisfied": passive_union == expected_passive_ids,
        },
        "cross_cutting_overall": cross_cutting_checks,
    }

    invariant_sections = [
        "top_level_partition", "passive_partition", "severity_partition",
        "domain_partition", "unique_rule_ids", "top_level_rule_id_disjointness",
        "passive_rule_id_disjointness", "top_level_rule_id_coverage",
        "passive_rule_id_coverage",
    ]
    failures = [
        name for name in invariant_sections
        if not accounting[name]["satisfied"]
    ]
    failures.extend(
        f"domain_severity_partitions.{name}"
        for name, result in domain_severity_partitions.items()
        if not result["satisfied"]
    )
    failures.extend(
        f"cross_cutting_overall.{name}"
        for name, result in cross_cutting_checks.items()
        if not result["satisfied"]
    )
    accounting["failures"] = failures
    accounting["all_invariants_satisfied"] = not failures
    return accounting

def validate_summary_invariants(accounting: Dict[str, Any]) -> None:
    """Recompute and enforce every summary accounting invariant."""
    failures: List[str] = []

    for name in (
        "top_level_partition", "passive_partition", "severity_partition",
        "domain_partition", "unique_rule_ids",
    ):
        item = accounting.get(name, {})
        satisfied = item.get("expected") == item.get("actual")
        if name == "unique_rule_ids":
            satisfied = satisfied and not item.get("duplicates", [])
        item["satisfied"] = bool(satisfied)
        if not satisfied:
            failures.append(name)

    for name in ("top_level_rule_id_disjointness", "passive_rule_id_disjointness"):
        item = accounting.get(name, {})
        satisfied = not item.get("overlaps", {})
        item["satisfied"] = bool(satisfied)
        if not satisfied:
            failures.append(name)

    for name in ("top_level_rule_id_coverage", "passive_rule_id_coverage"):
        item = accounting.get(name, {})
        satisfied = not item.get("missing", []) and not item.get("unexpected", [])
        item["satisfied"] = bool(satisfied)
        if not satisfied:
            failures.append(name)

    for domain_name, item in accounting.get("domain_severity_partitions", {}).items():
        satisfied = item.get("expected") == item.get("actual")
        item["satisfied"] = bool(satisfied)
        if not satisfied:
            failures.append(f"domain_severity_partitions.{domain_name}")

    cross_cutting = accounting.setdefault("cross_cutting_overall", {})
    for name in SUMMARY_CROSS_CUTTING_COUNTERS:
        item = cross_cutting.get(name)
        if item is None:
            cross_cutting[name] = {
                "expected": "PRESENT", "actual": "MISSING", "satisfied": False,
            }
            failures.append(f"cross_cutting_overall.{name}")
            continue
        satisfied = item.get("expected") == item.get("actual")
        item["satisfied"] = bool(satisfied)
        if not satisfied:
            failures.append(f"cross_cutting_overall.{name}")

    accounting["failures"] = failures
    accounting["all_invariants_satisfied"] = not failures
    if not failures:
        return

    details: List[str] = []
    for name in failures:
        if name.startswith("cross_cutting_overall."):
            key = name.split(".", 1)[1]
            item = accounting.get("cross_cutting_overall", {}).get(key, {})
        elif name.startswith("domain_severity_partitions."):
            key = name.split(".", 1)[1]
            item = accounting.get("domain_severity_partitions", {}).get(key, {})
        else:
            item = accounting.get(name, {})
        expected = item.get("expected")
        actual = item.get("actual")
        if expected is not None or actual is not None:
            details.append(f"{name}(expected={expected}, actual={actual})")
        elif item.get("overlaps"):
            details.append(f"{name}(overlaps={item.get('overlaps')})")
        elif item.get("missing") or item.get("unexpected"):
            details.append(
                f"{name}(missing={item.get('missing', [])}, unexpected={item.get('unexpected', [])})"
            )
        elif item.get("duplicates"):
            details.append(f"{name}(duplicates={item.get('duplicates')})")
        else:
            details.append(name)
    raise SummaryInvariantError("; ".join(details))

@dataclass
class GGFWReport:
    schema: str = REPORT_SCHEMA
    tool_version: str = TOOL_VERSION
    target_path: str = ""
    platform_guess: str = "Unknown"
    scan_timestamp: str = ""
    scan_id: str = ""
    policy_profile: str = "default"
    findings: List[Finding] = field(default_factory=list)
    positive_checks: List[PositiveCheck] = field(default_factory=list)
    raw_artifacts: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    execution: Dict[str, Any] = field(default_factory=lambda: {
        "status": "PENDING",
        "classification": "PENDING",
        "policy_triggered": False,
        "exit_code": None,
        "fail_on": "NONE",
        "gate_exclusions": [],
        "matching_rules": [],
        "matching_findings": [],
        "excluded_matching_rules": [],
        "excluded_matching_findings": [],
        "runtime_issues": [],
    })

    def add_finding(self, finding: Finding):
        finding.finalise(self.policy_profile)
        self.findings.append(finding)

    def add_check(self, check_id: str, domain: str, description: str, **evidence: Any):
        self.positive_checks.append(PositiveCheck(
            check_id=check_id, domain=domain, description=description, evidence=evidence
        ))

    def calculate_summary(self):
        severity_counts = {
            severity: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }

        # A finding belongs to exactly one top-level reporting partition. The
        # precedence is deliberate: aggregate rollups, then evidence work,
        # then security/policy remediation, then passive/report-only findings.
        top_level: Dict[str, List[Finding]] = {
            "actionable_security_policy": [],
            "evidence_acquisition_required": [],
            "aggregate_rollups": [],
            "other_non_actionable": [],
        }
        for finding in self.findings:
            if finding.aggregate:
                top_level["aggregate_rollups"].append(finding)
            elif finding.evidence_required:
                top_level["evidence_acquisition_required"].append(finding)
            elif bool(finding.actionable) and not finding.coverage_gap:
                top_level["actionable_security_policy"].append(finding)
            else:
                top_level["other_non_actionable"].append(finding)

        security_actions = top_level["actionable_security_policy"]
        evidence_actions = top_level["evidence_acquisition_required"]
        aggregate_rollups = top_level["aggregate_rollups"]
        passive_findings = top_level["other_non_actionable"]

        passive_subgroups: Dict[str, List[Finding]] = {
            "informational_only": [],
            "coverage_gap_only": [],
            "policy_not_required_only": [],
            "multi_attribute_passive": [],
        }
        for finding in passive_findings:
            is_coverage = bool(finding.coverage_gap)
            is_not_required = finding.applicability in {"NOT_APPLICABLE", "NOT_REQUIRED"}
            if is_coverage and is_not_required:
                passive_subgroups["multi_attribute_passive"].append(finding)
            elif is_coverage:
                passive_subgroups["coverage_gap_only"].append(finding)
            elif is_not_required:
                passive_subgroups["policy_not_required_only"].append(finding)
            else:
                passive_subgroups["informational_only"].append(finding)

        security_ids = {id(finding) for finding in security_actions}
        evidence_ids = {id(finding) for finding in evidence_actions}
        aggregate_ids = {id(finding) for finding in aggregate_rollups}
        domain_summary: Dict[str, Dict[str, Any]] = {}
        for finding in self.findings:
            entry = domain_summary.setdefault(finding.domain, {
                "total": 0,
                "actionable": 0,
                "evidence_required": 0,
                "aggregates": 0,
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            })
            entry["total"] += 1
            entry["actionable"] += int(id(finding) in security_ids)
            entry["evidence_required"] += int(id(finding) in evidence_ids)
            entry["aggregates"] += int(id(finding) in aggregate_ids)
            entry[finding.severity] += 1

        source_types: Set[str] = set()
        trust_levels: Set[str] = set()
        for finding in self.findings:
            for item in finding.evidence_items:
                if item.source_type:
                    source_types.add(item.source_type)
                if item.trust_level:
                    trust_levels.add(item.trust_level.upper())
        for check in self.positive_checks:
            source_type = str(check.evidence.get('source_type', '') or '')
            trust_level = str(check.evidence.get('trust_level', '') or '')
            if source_type:
                source_types.add(source_type)
            if trust_level:
                trust_levels.add(trust_level.upper())

        external_types = {
            'EXTERNAL_SPI_DUMP', 'OFFLINE_FILE_MEASURED', 'SIGNED_TRUSTED_ARTIFACT',
            'EXTERNAL_PROVISIONING_METADATA'
        }
        external_supplied = bool(source_types & external_types)
        in_band_supplied = bool(source_types - external_types)
        if external_supplied and in_band_supplied:
            acquisition_context = 'MIXED'
        elif external_supplied:
            acquisition_context = 'EXTERNAL_OR_OFFLINE'
        else:
            acquisition_context = 'IN_BAND'
        trust_rank = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
        maximum_trust = max(trust_levels, key=lambda value: trust_rank.get(value, -1), default='UNKNOWN')

        remediation_groups = {
            (finding.remediation_group or finding.rule_id)
            for finding in security_actions
        }
        evidence_groups = {
            (finding.remediation_group or finding.rule_id)
            for finding in evidence_actions
        }

        coverage_total = sum(1 for finding in self.findings if finding.coverage_gap)
        policy_not_required_total = sum(
            1 for finding in self.findings
            if finding.applicability in {"NOT_APPLICABLE", "NOT_REQUIRED"}
        )
        aggregate_total = sum(1 for finding in self.findings if finding.aggregate)
        evidence_required_total = sum(1 for finding in self.findings if finding.evidence_required)

        summary: Dict[str, Any] = {
            **severity_counts,
            "total_findings": len(self.findings),
            "actionable": len(security_actions),
            "actionable_security_policy": len(security_actions),
            "evidence_required": len(evidence_actions),
            "evidence_required_total": evidence_required_total,
            "aggregate_findings": len(aggregate_rollups),
            "aggregate_findings_total": aggregate_total,
            "aggregate_rollups": len(aggregate_rollups),
            "non_actionable": len(passive_findings),
            "other_non_actionable": len(passive_findings),
            "informational": len(passive_subgroups["informational_only"]),
            "informational_only": len(passive_subgroups["informational_only"]),
            "non_actionable_coverage_gaps": len(passive_subgroups["coverage_gap_only"]),
            "policy_not_required": len(passive_subgroups["policy_not_required_only"]),
            "policy_not_required_only": len(passive_subgroups["policy_not_required_only"]),
            "multi_attribute_passive": len(passive_subgroups["multi_attribute_passive"]),
            "coverage_gaps": coverage_total,
            "coverage_gaps_total": coverage_total,
            "policy_not_required_total": policy_not_required_total,
            "remediation_tasks": len(remediation_groups),
            "evidence_acquisition_tasks": len(evidence_groups),
            "positive_checks": len(self.positive_checks),
            "domains": domain_summary,
            "evidence_context": {
                "acquisition_context": acquisition_context,
                "maximum_trust_achieved": maximum_trust,
                "external_acquisition_supplied": external_supplied,
                "source_types_observed": sorted(source_types),
            },
        }
        accounting = build_summary_accounting(
            self.findings, summary, top_level, passive_subgroups
        )
        validate_summary_invariants(accounting)
        summary["summary_accounting"] = accounting
        self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        self.calculate_summary()
        finding_dicts = [finding.to_dict() for finding in self.findings]
        sections: Dict[str, List[Dict[str, Any]]] = {
            "BOOT_AND_EEPROM": [],
            "PLATFORM_HARDWARE": [],
            "OS_RUNTIME": [],
            "EVIDENCE_COVERAGE": [],
        }
        for item in finding_dicts:
            # Every finding appears in exactly one section. Coverage gaps are
            # indexed below instead of being duplicated into a second section.
            sections.setdefault(item.get('domain', 'OS_RUNTIME'), []).append(item)

        indexes = {
            "actionable_ids": [item["rule_id"] for item in finding_dicts if item.get("actionable")],
            "coverage_gap_ids": [item["rule_id"] for item in finding_dicts if item.get("coverage_gap")],
            "evidence_required_ids": [item["rule_id"] for item in finding_dicts if item.get("evidence_required")],
            "aggregate_ids": [item["rule_id"] for item in finding_dicts if item.get("aggregate")],
            "remediation_groups": {
                group: [item["rule_id"] for item in finding_dicts if item.get("remediation_group") == group]
                for group in sorted({item.get("remediation_group") for item in finding_dicts if item.get("remediation_group")})
            },
            "policy_not_required_ids": [
                item["rule_id"] for item in finding_dicts
                if item.get("applicability") in {"NOT_APPLICABLE", "NOT_REQUIRED"}
            ],
        }
        return {
            "schema": self.schema,
            "tool_version": self.tool_version,
            "target_path": self.target_path,
            "platform_guess": self.platform_guess,
            "scan_timestamp": self.scan_timestamp,
            "scan_id": self.scan_id,
            "policy_profile": self.policy_profile,
            "execution": self.execution,
            "findings": finding_dicts,
            "sections": sections,
            "indexes": indexes,
            "positive_checks": [asdict(check) for check in self.positive_checks],
            "raw_artifacts": self.raw_artifacts,
            "summary": self.summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4, ensure_ascii=False)
