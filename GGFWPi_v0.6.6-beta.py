#!/usr/bin/env python3
# Copyright 2026 GG Advanced IT Security UG
# Developed by Maciej Gojny for GGSEC
# SPDX-License-Identifier: Apache-2.0
"""
GGFW Raspberry Pi Unified Auditor - GGFW 0.6.6 beta (cryptographic Secure Boot chain validator)
Developed for GG ADVANCED IT SECURITY Ug (ggsec.de)
"""

import argparse
import base64
import binascii
import struct
import ctypes
import ctypes.util
import grp
import pwd
import platform as py_platform
import json
import os
import re
import sys
import subprocess
import hashlib
import glob
import shutil
import logging
import time
import zipfile
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from urllib.parse import urlparse

TOOL_VERSION = "0.6.6-beta"
TOOL_VERSION_DISPLAY = "0.6.6 beta"

# ==============================================================================
# 0. Optional dependencies handling (Kali Linux compatible)
# ==============================================================================

# Try passlib first; it supports common shadow password formats.
try:
    from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False

# Fall back to the platform crypt module when available.
try:
    import crypt
    CRYPT_AVAILABLE = True
except ImportError:
    crypt = None
    CRYPT_AVAILABLE = False

# Direct libcrypt fallback for Python builds where the crypt module was removed.
LIBCRYPT_AVAILABLE = False
_LIBCRYPT = None
try:
    libcrypt_name = ctypes.util.find_library("crypt")
    if libcrypt_name:
        _LIBCRYPT = ctypes.CDLL(libcrypt_name)
        _LIBCRYPT.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _LIBCRYPT.crypt.restype = ctypes.c_char_p
        LIBCRYPT_AVAILABLE = True
except (OSError, AttributeError):
    _LIBCRYPT = None
    LIBCRYPT_AVAILABLE = False

if PASSLIB_AVAILABLE:
    print("[*] passlib available - password verification enabled")
elif CRYPT_AVAILABLE:
    print("[*] crypt available - password verification enabled")
elif LIBCRYPT_AVAILABLE:
    print("[*] libcrypt available - password verification enabled")
else:
    print("[*] Warning: no password-hash verification backend is available.")

# ==============================================================================
# 1. Password verification helper
# ==============================================================================

def verify_password_against_hash(password: str, hash_str: str) -> bool:
    """
    Verify a candidate password against a shadow hash (passlib, then crypt).
    """
    if not hash_str or hash_str in ['!', '*', '']:
        return False
    
    # Prefer passlib.
    if PASSLIB_AVAILABLE:
        try:
            # Select the matching hash handler.
            if hash_str.startswith('$6$'):  # SHA512
                return sha512_crypt.verify(password, hash_str)
            elif hash_str.startswith('$5$'):  # SHA256
                return sha256_crypt.verify(password, hash_str)
            elif hash_str.startswith('$1$'):  # MD5
                return md5_crypt.verify(password, hash_str)
        except Exception as e:
            logger.debug(f"passlib verification error: {e}")
    
    # Fall back to the Python crypt module for formats such as yescrypt.
    if CRYPT_AVAILABLE:
        try:
            test_hash = crypt.crypt(password, hash_str)
            return test_hash == hash_str
        except Exception as e:
            logger.debug(f"crypt verification error: {e}")

    # Python 3.13 may omit the crypt module while libxcrypt is still present.
    if LIBCRYPT_AVAILABLE and _LIBCRYPT is not None:
        try:
            encoded = _LIBCRYPT.crypt(password.encode(), hash_str.encode())
            if encoded:
                return encoded.decode(errors='replace') == hash_str
        except Exception as e:
            logger.debug(f"libcrypt verification error: {e}")

    return False

# ==============================================================================
# 2. Logging Configuration
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ==============================================================================
# 3. Evidence & Reporting Model
# ==============================================================================

REPORT_SCHEMA = "ggfw-report/v2.11"
EVIDENCE_SCHEMA = "ggfw-evidence/v1.9"
OTP_DECODER_SCHEMA = "ggfw-otp-decoder/v1"
SECURE_BOOT_EVIDENCE_SCHEMA = "ggfw-secure-boot-evidence/v2"
SECURE_BOOT_VALIDATION_SCHEMA = "ggfw-secure-boot-validation/v2.1"


class GGFWRuntimeError(RuntimeError):
    """A controlled tool/runtime failure that must exit with status 1."""


class SummaryInvariantError(GGFWRuntimeError):
    """Raised when report summary accounting is internally inconsistent."""


DOMAIN_MAP = {
    "HARDWARE": "PLATFORM_HARDWARE",
    "INTEGRITY": "BOOT_AND_EEPROM",
    "BOOT": "BOOT_AND_EEPROM",
    "DEBUG": "BOOT_AND_EEPROM",
    "KERNEL": "OS_RUNTIME",
    "ACCESS": "OS_RUNTIME",
    "NETWORK": "OS_RUNTIME",
    "PROCESSES": "OS_RUNTIME",
    "TOOLING": "EVIDENCE_COVERAGE",
}


def infer_evidence_source(rule_id: str, category: str) -> Tuple[str, str, str]:
    """Return source_type, trust_level and acquisition_method for legacy findings."""
    if rule_id.startswith("RPI-SPI"):
        return ("OS_MEDIATED_SPI_READ", "MEDIUM", "flashrom/linux_spi through the running kernel")
    if rule_id.startswith("RPI-INTEGRITY"):
        return ("OS_MEDIATED_FILE_MEASURED", "MEDIUM", "SHA-256 and size comparison performed by the running operating system")
    if rule_id.startswith("HW-SEC") or rule_id.startswith("HW-OTP"):
        return ("FIRMWARE_REPORTED", "MEDIUM", "vcgencmd and firmware mailbox reporting")
    if "EEPROM" in rule_id or rule_id.startswith("RPI-BOOT"):
        return ("FIRMWARE_REPORTED", "MEDIUM", "rpi-eeprom tools and parsed boot configuration")
    if category in {"ACCESS", "NETWORK", "PROCESSES", "KERNEL", "INTEGRITY"}:
        return ("OS_OBSERVED", "MEDIUM", "running operating-system state")
    return ("OS_OBSERVED", "MEDIUM", "local system observation")


@dataclass
class EvidenceRecord:
    source_type: str
    source_path: str = ""
    acquisition_method: str = ""
    trust_level: str = "MEDIUM"
    raw: str = ""
    normalized: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    # The first seven fields preserve compatibility with legacy callers.
    rule_id: str
    severity: str
    category: str
    description: str
    evidence: str
    remediation: str
    cve_references: List[str] = field(default_factory=list)

    title: str = ""
    domain: str = ""
    status: str = "DETECTED"
    confidence: str = "HIGH"
    applicability: str = "APPLICABLE"
    coverage_gap: bool = False
    actionable: Optional[bool] = None
    expected: str = ""
    observed: str = ""
    rationale: str = ""
    policy_profile: str = "default"
    finding_class: str = "SECURITY_FINDING"
    evidence_required: bool = False
    aggregate: bool = False
    blocked_by: List[str] = field(default_factory=list)
    remediation_group: str = ""
    evidence_items: List[EvidenceRecord] = field(default_factory=list)

    def finalise(self, policy_profile: str = "default"):
        self.policy_profile = policy_profile
        self.title = self.title or self.description
        if not self.domain:
            if self.rule_id.startswith((
                'RPI-CRED', 'RPI-NET', 'RPI-APT', 'RPI-SSH', 'RPI-FW',
                'RPI-PERM', 'RPI-PROC', 'RPI-KERNEL',
            )):
                self.domain = 'OS_RUNTIME'
            elif self.rule_id.startswith(('RPI-SPI', 'RPI-EEPROM', 'RPI-BOOT', 'RPI-INTEGRITY', 'RPI-SB', 'RPI-OTP', 'HW-SEC')):
                self.domain = 'BOOT_AND_EEPROM'
            elif self.rule_id.startswith(('RPI-TOOL', 'HW-OTP')) and self.coverage_gap:
                self.domain = 'EVIDENCE_COVERAGE'
            else:
                self.domain = DOMAIN_MAP.get(self.category, 'OS_RUNTIME')
        self.observed = self.observed or self.evidence

        if self.rule_id == "HW-SEC-001":
            self.coverage_gap = True
            self.status = "EVIDENCE_INCOMPLETE"
            self.finding_class = "COVERAGE_GAP"
            self.aggregate = True
            self.actionable = False
            self.evidence_required = False
            if policy_profile == "secure-boot-required":
                self.severity = "HIGH"
                self.applicability = "REQUIRED"
            elif policy_profile == "hardened":
                self.severity = "MEDIUM"
                self.applicability = "REQUIRED"
            else:
                self.severity = "INFO"
        elif self.rule_id.startswith("RPI-EEPROM-AB"):
            self.finding_class = "CAPABILITY_GAP"
            if policy_profile == "resilient-appliance":
                self.applicability = "REQUIRED"
                if self.severity == "INFO":
                    self.severity = "LOW"
                self.actionable = True
            else:
                self.applicability = "NOT_REQUIRED"
                self.actionable = False
        elif self.rule_id == "RPI-NET-002" and policy_profile == "hardened":
            self.severity = "LOW"
        elif self.rule_id == "RPI-APT-001" and policy_profile == "hardened":
            self.severity = "LOW"

        if self.coverage_gap and not self.aggregate:
            if self.applicability == "APPLICABLE" and policy_profile in {"hardened", "secure-boot-required"}:
                self.applicability = "REQUIRED"
            self.evidence_required = self.applicability == "REQUIRED"
            self.actionable = False

        if self.aggregate:
            self.actionable = False
            self.evidence_required = False

        if self.actionable is None:
            self.actionable = (
                not self.coverage_gap
                and not self.aggregate
                and self.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            )

        if not self.evidence_items:
            source_type, trust_level, method = infer_evidence_source(self.rule_id, self.category)
            self.evidence_items.append(EvidenceRecord(
                source_type=source_type,
                acquisition_method=method,
                trust_level=trust_level,
                raw=self.evidence,
            ))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "domain": self.domain,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "applicability": self.applicability,
            "coverage_gap": self.coverage_gap,
            "actionable": bool(self.actionable),
            "finding_class": self.finding_class,
            "evidence_required": bool(self.evidence_required),
            "aggregate": bool(self.aggregate),
            "blocked_by": list(self.blocked_by),
            "remediation_group": self.remediation_group,
            "expected": self.expected,
            "observed": self.observed,
            "rationale": self.rationale,
            "evidence_text": self.evidence,
            "evidence": [item.to_dict() for item in self.evidence_items],
            "remediation": self.remediation,
            "policy_profile": self.policy_profile,
            "references": list(self.cve_references),
        }


@dataclass
class PositiveCheck:
    check_id: str
    domain: str
    description: str
    status: str = "PASS"
    evidence: Dict[str, Any] = field(default_factory=dict)


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

# ==============================================================================
# 4. Cache Manager
# ==============================================================================

class CacheManager:
    def __init__(self):
        self.cache = {}
        self.ttl = 300
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            del self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        self.cache[key] = (value, time.time())
    
    def invalidate(self, key: str):
        if key in self.cache:
            del self.cache[key]

    def clear(self):
        self.cache.clear()

# ==============================================================================
# 5. Platform Detection
# ==============================================================================

def detect_platform() -> str:
    try:
        with open('/proc/device-tree/model', 'r') as f:
            model = f.read().strip().rstrip('\x00')
            if 'Raspberry Pi 5' in model:
                return "Raspberry Pi 5 (BCM2712)"
            elif 'Raspberry Pi 4' in model:
                return "Raspberry Pi 4 (BCM2711)"
            elif 'Raspberry Pi 3' in model:
                return "Raspberry Pi 3 (BCM2837)"
            elif 'Raspberry Pi 2' in model:
                return "Raspberry Pi 2 (BCM2836)"
            elif 'Compute Module 5' in model:
                return "Compute Module 5 (BCM2712)"
            elif 'Compute Module 4' in model:
                return "Compute Module 4 (BCM2711)"
            elif 'Compute Module 3' in model:
                return "Compute Module 3 (BCM2837)"
            elif 'Raspberry Pi Zero 2' in model:
                return "Raspberry Pi Zero 2 W (BCM2710A1)"
            elif 'Raspberry Pi Zero' in model:
                return "Raspberry Pi Zero (BCM2835)"
            elif 'Raspberry Pi 1' in model:
                return "Raspberry Pi 1 (BCM2835)"
            else:
                return f"Raspberry Pi ({model})"
    except Exception:
        return "Unknown Raspberry Pi"

def get_soc_generation(platform: str) -> str:
    if "BCM2712" in platform:
        return "BCM2712"
    elif "BCM2711" in platform:
        return "BCM2711"
    elif "BCM2710" in platform:
        return "BCM2710"
    elif "BCM2837" in platform:
        return "BCM2837"
    elif "BCM2836" in platform:
        return "BCM2836"
    elif "BCM2835" in platform:
        return "BCM2835"
    return "Unknown"

# ==============================================================================
# 6. Dependency Management
# ==============================================================================

def _find_executable(name: str, candidates: List[str]) -> Optional[str]:
    """Find an executable without depending on sudo's reduced PATH."""
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which(name)


def check_dependencies() -> Dict[str, Tuple[bool, str]]:
    deps = {
        'vcgencmd': {
            'paths': [
                '/usr/local/bin/vcgencmd', '/usr/bin/vcgencmd',
                '/opt/vc/bin/vcgencmd'
            ],
            'package': 'libraspberrypi-bin',
        },
        'rpi-eeprom-config': {
            'paths': [
                '/usr/local/bin/rpi-eeprom-config',
                '/usr/bin/rpi-eeprom-config',
                '/opt/rpi-eeprom/rpi-eeprom-config'
            ],
            'package': 'rpi-eeprom',
        },
        'rpi-eeprom-update': {
            'paths': [
                '/usr/local/bin/rpi-eeprom-update',
                '/usr/bin/rpi-eeprom-update',
                '/opt/rpi-eeprom/rpi-eeprom-update'
            ],
            'package': 'rpi-eeprom',
        },
        'rpi-eeprom-ab': {
            'paths': [
                '/usr/local/bin/rpi-eeprom-ab',
                '/usr/bin/rpi-eeprom-ab',
                '/usr/sbin/rpi-eeprom-ab'
            ],
            'package': 'rpieepromab',
        },
        'flashrom': {
            'paths': [
                '/usr/local/sbin/flashrom', '/usr/local/bin/flashrom',
                '/usr/sbin/flashrom', '/usr/bin/flashrom'
            ],
            'package': 'flashrom',
        },
    }

    results: Dict[str, Tuple[bool, str]] = {}
    for tool, info in deps.items():
        path = _find_executable(tool, info['paths'])
        results[tool] = (bool(path), path if path else info['package'])

    if PASSLIB_AVAILABLE:
        results['password_verification'] = (True, 'passlib (available)')
    elif CRYPT_AVAILABLE:
        results['password_verification'] = (True, 'crypt (available)')
    elif LIBCRYPT_AVAILABLE:
        results['password_verification'] = (True, 'libcrypt via ctypes (available)')
    else:
        results['password_verification'] = (False, 'disabled')

    return results



def parse_simple_config(text: str) -> Dict[str, str]:
    """Parse simple KEY=VALUE configuration while ignoring sections/comments."""
    values: Dict[str, str] = {}
    if not text or text.startswith('ERROR'):
        return values
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith('[') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip().upper()] = value.strip()
    return values


BOOT_MODE_MAP = {
    '0': 'SD_CARD_DETECT',
    '1': 'SD_CARD',
    '2': 'NETWORK',
    '3': 'RPIBOOT',
    '4': 'USB_MSD',
    '5': 'BCM_USB_MSD',
    '6': 'NVME',
    '7': 'HTTP',
    'e': 'STOP',
    'f': 'RESTART',
}


def decode_boot_order(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {'raw': value, 'valid': False, 'sequence': [], 'unknown_digits': []}
    cleaned = value.strip().lower()
    if cleaned.startswith('0x'):
        cleaned = cleaned[2:]
    sequence = []
    unknown = []
    for digit in reversed(cleaned):
        mode = BOOT_MODE_MAP.get(digit)
        if mode:
            sequence.append({'digit': digit, 'mode': mode})
        else:
            unknown.append(digit)
            sequence.append({'digit': digit, 'mode': 'UNKNOWN'})
    return {
        'raw': value,
        'read_direction': 'right-to-left',
        'valid': bool(cleaned) and not unknown,
        'sequence': sequence,
        'unknown_digits': unknown,
        'contains_network': any(item['mode'] in {'NETWORK', 'HTTP'} for item in sequence),
        'contains_rpiboot': any(item['mode'] == 'RPIBOOT' for item in sequence),
        'contains_external_media': any(item['mode'] in {'USB_MSD', 'BCM_USB_MSD', 'NVME'} for item in sequence),
    }


def parse_version_tuple(value: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r'(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?', value or '')
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
    )


def sha256_file(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None

# ==============================================================================
# 7. Parsers
# ==============================================================================

class ConfigTxtParser:
    """Parse config.txt while preserving order, duplicates, includes and provenance."""

    MAX_INCLUDE_DEPTH = 8

    @staticmethod
    def _section_applicability(section: str, platform: str) -> str:
        name = section.strip().lower()
        platform_lower = platform.lower()
        if name in {'all', ''}:
            return 'ACTIVE'
        if name == 'pi5':
            return 'ACTIVE' if 'raspberry pi 5' in platform_lower else 'INACTIVE'
        if name == 'pi4':
            return 'ACTIVE' if 'raspberry pi 4' in platform_lower else 'INACTIVE'
        if name == 'cm5':
            return 'ACTIVE' if 'compute module 5' in platform_lower else 'INACTIVE'
        if name == 'cm4':
            return 'ACTIVE' if 'compute module 4' in platform_lower else 'INACTIVE'
        if name.startswith('none'):
            return 'INACTIVE'
        # Board-revision and EDID filters require more context than model detection.
        return 'UNKNOWN'

    @classmethod
    def parse_detailed(
        cls,
        filepath: str,
        boot_dir: str = '',
        platform: str = 'Unknown Raspberry Pi',
    ) -> Dict[str, Any]:
        root = Path(filepath).expanduser().resolve()
        boot_root = Path(boot_dir or root.parent).expanduser().resolve()
        directives: List[Dict[str, Any]] = []
        includes: List[Dict[str, Any]] = []
        errors: List[str] = []
        parsed_files: List[str] = []
        sequence = 0

        def parse_file(path: Path, depth: int, inherited_section: str = 'all', stack: Optional[List[Path]] = None):
            nonlocal sequence
            stack = list(stack or [])
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if depth > cls.MAX_INCLUDE_DEPTH:
                errors.append(f'include depth exceeded at {resolved}')
                return
            if resolved in stack:
                errors.append(f'include cycle detected: {resolved}')
                return
            if not resolved.exists():
                errors.append(f'config file not found: {resolved}')
                return
            stack.append(resolved)
            parsed_files.append(str(resolved))
            section = inherited_section
            try:
                lines = resolved.read_text(encoding='utf-8', errors='replace').splitlines()
            except OSError as exc:
                errors.append(f'{resolved}: {exc}')
                return

            for line_number, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                section_match = re.match(r'^\[([^\]]+)\]$', line)
                if section_match:
                    section = section_match.group(1).strip().lower()
                    continue

                include_match = re.match(r'^include\s+(.+)$', line, re.IGNORECASE)
                if include_match:
                    include_name = include_match.group(1).strip()
                    include_path = (boot_root / include_name).resolve()
                    applicability = cls._section_applicability(section, platform)
                    includes.append({
                        'source': str(resolved),
                        'line': line_number,
                        'section': section,
                        'applicability': applicability,
                        'target': str(include_path),
                        'exists': include_path.exists(),
                    })
                    # Raspberry Pi includes inherit the current conditional context.
                    if applicability != 'INACTIVE':
                        parse_file(include_path, depth + 1, section, stack)
                    continue

                if '=' in line:
                    key, value = line.split('=', 1)
                else:
                    parts = line.split(None, 1)
                    key = parts[0]
                    value = parts[1] if len(parts) > 1 else ''

                sequence += 1
                directives.append({
                    'sequence': sequence,
                    'source': str(resolved),
                    'line': line_number,
                    'section': section,
                    'applicability': cls._section_applicability(section, platform),
                    'key': key.strip().lower(),
                    'value': value.strip(),
                    'raw': raw_line.rstrip('\n'),
                })

        parse_file(root, 0)

        sections: Dict[str, Dict[str, str]] = {'all': {}}
        active_config: Dict[str, Dict[str, str]] = {'all': {}}
        active_directives: List[Dict[str, Any]] = []
        for directive in directives:
            section = directive['section']
            sections.setdefault(section, {})[directive['key']] = directive['value']
            if directive['applicability'] == 'ACTIVE':
                active_config.setdefault(section, {})[directive['key']] = directive['value']
                active_directives.append(directive)

        return {
            'root_file': str(root),
            'boot_root': str(boot_root),
            'sections': sections,
            'active_config': active_config,
            'directives': directives,
            'active_directives': active_directives,
            'includes': includes,
            'parsed_files': list(dict.fromkeys(parsed_files)),
            'errors': errors,
        }

    @classmethod
    def parse(cls, filepath: str, boot_dir: str = '') -> Dict[str, Dict[str, str]]:
        return cls.parse_detailed(filepath, boot_dir).get('sections', {'all': {}})


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


# ============================================================================== 
# 8. Boot Integrity and Baseline Checker
# ============================================================================== 


class BootIntegrityChecker:
    BASELINE_SCHEMA = 'ggfw-boot-baseline/v2'

    def __init__(
        self,
        boot_dir: str,
        platform: str,
        config: Optional[Dict[str, Dict[str, str]]] = None,
        baseline_path: Optional[str] = None,
        boot_graph: Optional[Dict[str, Any]] = None,
    ):
        self.boot_dir = str(Path(boot_dir).resolve())
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.config = config or {}
        self.boot_graph = boot_graph or {}
        self.cache = CacheManager()
        self.baseline_path = baseline_path
        self.baseline: Optional[Dict[str, Any]] = None
        self.baseline_error: Optional[str] = None
        self.baseline_legacy: bool = False
        if baseline_path:
            self._load_baseline(baseline_path)

    def _load_baseline(self, path: str):
        try:
            payload = json.loads(Path(path).read_text(encoding='utf-8'))
            schema = payload.get('schema')
            if schema not in {self.BASELINE_SCHEMA, 'ggfw-boot-baseline/v1'}:
                raise ValueError(f"Unsupported baseline schema: {schema!r}")
            self.baseline_legacy = schema == 'ggfw-boot-baseline/v1'
            if not isinstance(payload.get('files'), dict):
                raise ValueError('Baseline does not contain a files object')
            self.baseline = payload
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.baseline_error = str(exc)

    def _all_config_values(self) -> Dict[str, str]:
        merged: Dict[str, str] = {}
        for values in self.config.values():
            merged.update(values)
        return merged

    @staticmethod
    def _safe_relative_name(name: str) -> Optional[str]:
        candidate = name.strip().replace('\\', '/')
        if not candidate or candidate.startswith('/'):
            return None
        normalised = os.path.normpath(candidate)
        if normalised == '..' or normalised.startswith('../'):
            return None
        return normalised

    def get_files_to_check(self) -> List[str]:
        files: Set[str] = set(self.boot_graph.get('active_files', []))
        if not files:
            files.update({'config.txt', 'cmdline.txt'})
            values = self._all_config_values()
            if self.soc == 'BCM2711':
                files.update({'start4.elf', 'fixup4.dat', 'kernel8.img', 'bcm2711-rpi-4-b.dtb'})
            elif self.soc == 'BCM2712':
                files.update({'kernel_2712.img', 'bcm2712-rpi-5-b.dtb'})
            else:
                files.update({'start.elf', 'fixup.dat', 'kernel7.img'})
            for key in ('kernel', 'device_tree', 'armstub'):
                value = values.get(key)
                if value and value.strip().lower() not in {'-', 'none', 'disable'}:
                    safe_name = self._safe_relative_name(value)
                    if safe_name:
                        files.add(safe_name)

        if self.baseline:
            for name in self.baseline.get('files', {}):
                safe_name = self._safe_relative_name(name)
                if safe_name:
                    files.add(safe_name)
        return sorted(name for name in files if self._safe_relative_name(name))

    def calculate_sha256(self, filepath: str) -> Optional[str]:
        cache_key = f'sha256_{filepath}'
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = sha256_file(filepath)
        if result:
            self.cache.set(cache_key, result)
        return result

    def verify_integrity(self) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        baseline_files = self.baseline.get('files', {}) if self.baseline else {}

        for filename in self.get_files_to_check():
            filepath = os.path.join(self.boot_dir, filename)
            file_hash = self.calculate_sha256(filepath)
            expected = baseline_files.get(filename)

            if file_hash is None:
                status = 'MISSING'
                results[filename] = {
                    'status': status,
                    'sha256': None,
                    'size': 0,
                    'expected_sha256': expected.get('sha256') if isinstance(expected, dict) else None,
                    'expected_size': expected.get('size') if isinstance(expected, dict) else None,
                }
                continue

            file_size = os.path.getsize(filepath)
            if isinstance(expected, dict):
                hash_matches = file_hash == expected.get('sha256')
                size_matches = file_size == expected.get('size')
                status = 'BASELINE_MATCH' if hash_matches and size_matches else 'BASELINE_MISMATCH'
            elif self.baseline:
                status = 'BASELINE_MISSING_ENTRY'
            else:
                status = 'PRESENT_HASHED'

            results[filename] = {
                'status': status,
                'sha256': file_hash,
                'size': file_size,
                'expected_sha256': expected.get('sha256') if isinstance(expected, dict) else None,
                'expected_size': expected.get('size') if isinstance(expected, dict) else None,
            }

        return results

    def build_baseline(self, integrity_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        files = {
            name: {
                'sha256': data['sha256'],
                'size': data['size'],
            }
            for name, data in integrity_results.items()
            if data.get('sha256') is not None
        }
        missing = sorted(
            name for name, data in integrity_results.items()
            if data.get('status') == 'MISSING'
        )
        return {
            'schema': self.BASELINE_SCHEMA,
            'tool_version': TOOL_VERSION,
            'created_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            'platform': self.platform,
            'soc': self.soc,
            'boot_path': self.boot_dir,
            'files': files,
            'resolved_chain': {
                'schema': self.boot_graph.get('schema'),
                'fingerprint': self.boot_graph.get('fingerprint'),
                'active_files': self.boot_graph.get('active_files', []),
            },
            'missing_at_creation': missing,
            'trust_note': (
                'This is a device-specific measured baseline, not an official vendor '
                'signature or a universal Raspberry Pi hash database.'
            ),
        }

    def write_baseline(
        self,
        path: str,
        integrity_results: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        payload = self.build_baseline(integrity_results)
        destination = Path(path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + '.tmp')
        temporary.write_text(
            json.dumps(payload, indent=4, ensure_ascii=False) + '\n',
            encoding='utf-8',
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        return payload

def read_os_release() -> Dict[str, str]:
    """Read /etc/os-release without executing shell content."""
    result: Dict[str, str] = {}
    try:
        for line in Path('/etc/os-release').read_text(encoding='utf-8', errors='replace').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            result[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return result


def assess_ssh_password_exposure() -> Dict[str, Any]:
    """Best-effort assessment of wildcard SSH plus effective password authentication."""
    assessment: Dict[str, Any] = {
        'wildcard_listener': False,
        'password_authentication': None,
        'kbd_interactive_authentication': None,
        'effective_config_source': None,
        'confirmed_remote_password_exposure': False,
    }
    try:
        result = subprocess.run(['ss', '-H', '-ltn'], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local_addr = parts[3]
            if local_addr.rsplit(':', 1)[-1] == '22' and (
                local_addr.startswith('0.0.0.0:')
                or local_addr.startswith('[::]:')
                or local_addr.startswith('*:')
            ):
                assessment['wildcard_listener'] = True
                break
    except OSError:
        pass

    sshd = shutil.which('sshd')
    if sshd:
        try:
            result = subprocess.run([sshd, '-T'], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                assessment['effective_config_source'] = 'sshd -T'
                for line in result.stdout.splitlines():
                    key, _, value = line.strip().partition(' ')
                    if key == 'passwordauthentication':
                        assessment['password_authentication'] = value.lower() == 'yes'
                    elif key == 'kbdinteractiveauthentication':
                        assessment['kbd_interactive_authentication'] = value.lower() == 'yes'
        except OSError:
            pass

    assessment['confirmed_remote_password_exposure'] = bool(
        assessment['wildcard_listener']
        and (
            assessment['password_authentication'] is True
            or assessment['kbd_interactive_authentication'] is True
        )
    )
    return assessment


# ==============================================================================
# 9. FAT and Host Policy Engine
# ==============================================================================

class FATPolicyEngine:
    def __init__(self, config: Dict, cmdline: Dict, report: GGFWReport, boot_dir: str = ""):
        self.config = config
        self.cmdline = cmdline
        self.report = report
        self.boot_dir = boot_dir
        self.cache = CacheManager()
        
        self.all_config_values = {}
        for section, values in config.items():
            self.all_config_values.update(values)

    def run_all_checks(self):
        self.check_debug_interfaces()
        self.check_usb_boot_gadget()
        self.check_kernel_mitigations()
        self.check_boot_chain_integrity()
        self.check_ssh_authorized_keys()
        self.check_network_services()
        self.check_default_credentials()
        self.check_apt_sources()
        self.check_critical_file_permissions()
        self.check_suspicious_processes()
        self.check_firewall()

    def check_debug_interfaces(self):
        if self.all_config_values.get('enable_jtag_gpio') == '1':
            self.report.add_finding(Finding(
                rule_id="RPI-DEBUG-001", severity="HIGH", category="DEBUG",
                description="JTAG interface is explicitly enabled.",
                evidence="enable_jtag_gpio=1",
                remediation="Remove 'enable_jtag_gpio=1' from config.txt"
            ))
            
        if self.all_config_values.get('uart_2ndstage') == '1':
             self.report.add_finding(Finding(
                rule_id="RPI-DEBUG-002", severity="MEDIUM", category="DEBUG",
                description="UART debug output enabled.",
                evidence="uart_2ndstage=1",
                remediation="Disable UART debug output for production environments."
            ))

    def check_usb_boot_gadget(self):
        overlays = self.all_config_values.get('dtoverlay', '')
        if 'dwc2' in overlays:
            self.report.add_finding(Finding(
                rule_id="RPI-BOOT-005", severity="CRITICAL", category="BOOT",
                description="USB Gadget mode (dwc2) is enabled.",
                evidence=f"dtoverlay={overlays}",
                remediation="Remove dwc2 overlay unless strictly required.",
                cve_references=["CVE-2014-4699", "CVE-2020-13800"]
            ))

        if self.all_config_values.get('program_usb_boot_mode') == '1':
            timeout = self.all_config_values.get('program_usb_boot_timeout')
            if not timeout:
                self.report.add_finding(Finding(
                    rule_id="RPI-BOOT-006", severity="HIGH", category="BOOT",
                    description="USB Boot mode enabled without timeout.",
                    evidence="program_usb_boot_mode=1",
                    remediation="Set program_usb_boot_timeout"
                ))

    def check_kernel_mitigations(self):
        if 'mitigations' in self.cmdline and self.cmdline['mitigations'] == 'off':
            self.report.add_finding(Finding(
                rule_id="RPI-KERNEL-001", severity="HIGH", category="KERNEL",
                description="CPU mitigations explicitly disabled.",
                evidence="cmdline: mitigations=off",
                remediation="Remove 'mitigations=off' from cmdline.txt.",
                cve_references=["CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754"]
            ))

        if self.cmdline.get('iomem') == 'relaxed':
            self.report.add_finding(Finding(
                rule_id="RPI-KERNEL-002", severity="CRITICAL", category="KERNEL",
                description="Strict /dev/mem is disabled.",
                evidence="cmdline: iomem=relaxed",
                remediation="Remove 'iomem=relaxed' to prevent MMIO exploits.",
                cve_references=["CVE-2019-17666"]
            ))

    def check_boot_chain_integrity(self):
        if 'armstub' in self.all_config_values:
            self.report.add_finding(Finding(
                rule_id="RPI-EL3-001", severity="MEDIUM", category="INTEGRITY",
                description="Custom ARM Trusted Firmware loaded.",
                evidence=f"armstub={self.all_config_values['armstub']}",
                remediation="Verify signature of armstub binary."
            ))

    def check_ssh_authorized_keys(self):
        ssh_dirs = [
            '/root/.ssh/authorized_keys',
            '/home/*/.ssh/authorized_keys'
        ]
        
        suspicious_keys = []
        weak_keys = []
        
        for pattern in ssh_dirs:
            for filepath in glob.glob(pattern):
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            keys = f.readlines()
                            for i, key in enumerate(keys):
                                key = key.strip()
                                if key and not key.startswith('#'):
                                    parts = key.split()
                                    if len(parts) >= 3:
                                        key_type = parts[0]
                                        comment = parts[2] if len(parts) > 2 else ""
                                        
                                        if key_type in ['ssh-dss', 'ssh-rsa']:
                                            weak_keys.append({
                                                'file': filepath,
                                                'line': i + 1,
                                                'type': key_type
                                            })
                                        
                                        suspicious_keywords = ['temp', 'test', 'debug', 'admin', 'root', 'backdoor']
                                        if any(kw in comment.lower() for kw in suspicious_keywords):
                                            suspicious_keys.append({
                                                'file': filepath,
                                                'line': i + 1,
                                                'comment': comment
                                            })
                    except PermissionError:
                        pass
        
        if suspicious_keys:
            evidence = "; ".join([f"{k['file']}:{k['line']} ({k['comment']})" for k in suspicious_keys])
            self.report.add_finding(Finding(
                rule_id="RPI-SSH-001", severity="HIGH", category="ACCESS",
                description="Suspicious SSH authorized keys detected.",
                evidence=evidence,
                remediation="Review and remove unauthorized SSH keys."
            ))
        
        if weak_keys:
            evidence = "; ".join([f"{k['file']}:{k['line']} ({k['type']})" for k in weak_keys])
            self.report.add_finding(Finding(
                rule_id="RPI-SSH-004", severity="MEDIUM", category="ACCESS",
                description="Weak SSH key types detected.",
                evidence=evidence,
                remediation="Replace weak keys with ed25519 or strong RSA.",
                cve_references=["CVE-2017-15906"]
            ))
        
        ssh_service = subprocess.run(['systemctl', 'is-active', 'ssh'], 
                                    capture_output=True, text=True).stdout.strip()
        if ssh_service == 'active':
            sshd_config = '/etc/ssh/sshd_config'
            if os.path.exists(sshd_config):
                try:
                    with open(sshd_config, 'r') as f:
                        content = f.read()
                        if re.search(r'^PermitRootLogin\s+(yes|without-password)', content, re.MULTILINE):
                            self.report.add_finding(Finding(
                                rule_id="RPI-SSH-002", severity="HIGH", category="ACCESS",
                                description="SSH root login is enabled.",
                                evidence="PermitRootLogin yes in sshd_config",
                                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
                            ))
                        if re.search(r'^PasswordAuthentication\s+yes', content, re.MULTILINE):
                            self.report.add_finding(Finding(
                                rule_id="RPI-SSH-003", severity="MEDIUM", category="ACCESS",
                                description="SSH password authentication is enabled.",
                                evidence="PasswordAuthentication yes in sshd_config",
                                remediation="Consider using SSH key-only authentication."
                            ))
                except PermissionError:
                    pass

    def check_network_services(self):
        """Classify listening sockets without treating a port number as proof of malware."""
        try:
            result = subprocess.run(
                ['ss', '-H', '-tlnp'], capture_output=True, text=True, check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return

        high_risk_ports = {'21': 'FTP', '23': 'Telnet'}
        remote_admin_ports = {'3389': 'RDP', '5900': 'VNC'}
        high_risk = []
        remote_admin = []
        all_interfaces = []
        listener_inventory: List[Dict[str, Any]] = []

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue

            local_addr = parts[3]
            port = local_addr.rsplit(':', 1)[-1]
            process_info = ' '.join(parts[5:]) if len(parts) > 5 else 'process unknown'
            wildcard = (
                local_addr.startswith('0.0.0.0:')
                or local_addr.startswith('[::]:')
                or local_addr.startswith('*:')
            )
            listener_inventory.append({
                'raw': line,
                'local_address': local_addr,
                'port': port,
                'process': process_info,
                'wildcard': wildcard,
            })

            if port in high_risk_ports:
                high_risk.append(f"{high_risk_ports[port]} port {port} ({process_info})")
            elif port in remote_admin_ports:
                remote_admin.append(f"{remote_admin_ports[port]} port {port} ({process_info})")

            if wildcard:
                all_interfaces.append(f"{port} ({process_info})")

        self.report.raw_artifacts['network_listeners'] = listener_inventory

        if high_risk:
            self.report.add_finding(Finding(
                rule_id="RPI-NET-001", severity="HIGH", category="NETWORK",
                description="Clear-text legacy network services are listening.",
                evidence="; ".join(sorted(set(high_risk))),
                remediation="Disable the service or replace it with an authenticated encrypted protocol."
            ))

        if remote_admin:
            self.report.add_finding(Finding(
                rule_id="RPI-NET-003", severity="MEDIUM", category="NETWORK",
                description="Remote administration services are listening.",
                evidence="; ".join(sorted(set(remote_admin))),
                remediation="Confirm that exposure is intended and restricted by authentication and firewall policy."
            ))

        if all_interfaces:
            self.report.add_finding(Finding(
                rule_id="RPI-NET-002", severity="INFO", category="NETWORK",
                description="Services are listening on wildcard addresses.",
                evidence="Listeners on all interfaces: " + "; ".join(sorted(set(all_interfaces))),
                remediation="Review whether each service must be reachable through every network interface."
            ))

    def check_default_credentials(self):
        """Audit local interactive accounts, privilege groups and weak passwords."""
        weak_passwords = (
            'raspberry', 'password', 'password1', 'admin', 'root',
            'toor', 'kali', '123456', '12345678', 'changeme',
        )
        non_login_shells = {
            '/usr/sbin/nologin', '/sbin/nologin', '/bin/false',
            '/usr/bin/false', '/bin/sync',
        }
        privilege_groups = ('sudo', 'wheel', 'adm', 'gpio', 'spi', 'dialout')

        try:
            passwd_entries = list(pwd.getpwall())
        except OSError as exc:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-000', severity='INFO', category='ACCESS',
                description='Local account database could not be read.',
                evidence=str(exc),
                remediation='Review /etc/passwd and NSS configuration manually.',
            ))
            return

        group_members: Dict[str, Set[str]] = {}
        for group_name in privilege_groups:
            try:
                entry = grp.getgrnam(group_name)
                members = set(entry.gr_mem)
                for account in passwd_entries:
                    if account.pw_gid == entry.gr_gid:
                        members.add(account.pw_name)
                group_members[group_name] = members
            except KeyError:
                group_members[group_name] = set()

        shadow_hashes: Dict[str, str] = {}
        try:
            with open('/etc/shadow', 'r', encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    fields = line.rstrip('\n').split(':')
                    if len(fields) >= 2:
                        shadow_hashes[fields[0]] = fields[1]
        except PermissionError:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-000', severity='INFO', category='ACCESS',
                description='Password-hash audit was skipped because /etc/shadow is unreadable.',
                evidence='Permission denied while reading /etc/shadow',
                remediation='Run GGFW as root to enable local password-hash checks.',
            ))
        except OSError as exc:
            logger.debug('Unable to read /etc/shadow: %s', exc)

        account_inventory: List[Dict[str, Any]] = []
        extra_uid_zero: List[str] = []
        empty_passwords: List[str] = []
        weak_password_matches: Dict[str, str] = {}

        for account in passwd_entries:
            interactive = bool(account.pw_shell) and account.pw_shell not in non_login_shells
            groups = sorted(
                name for name, members in group_members.items()
                if account.pw_name in members
            )
            password_hash = shadow_hashes.get(account.pw_name)
            locked = password_hash is None or password_hash.startswith(('!', '*'))
            algorithm = 'unknown'
            if password_hash:
                if password_hash.startswith('$y$'):
                    algorithm = 'yescrypt'
                elif password_hash.startswith('$6$'):
                    algorithm = 'sha512-crypt'
                elif password_hash.startswith('$5$'):
                    algorithm = 'sha256-crypt'
                elif password_hash.startswith('$1$'):
                    algorithm = 'md5-crypt'
                elif password_hash == '':
                    algorithm = 'empty'

            account_inventory.append({
                'username': account.pw_name,
                'uid': account.pw_uid,
                'gid': account.pw_gid,
                'shell': account.pw_shell,
                'interactive': interactive,
                'privilege_groups': groups,
                'password_locked_or_unavailable': locked,
                'password_hash_algorithm': algorithm,
            })

            if account.pw_uid == 0 and account.pw_name != 'root':
                extra_uid_zero.append(account.pw_name)

            if password_hash == '':
                empty_passwords.append(account.pw_name)
                continue

            should_test = (
                bool(password_hash)
                and not locked
                and interactive
                and (
                    account.pw_uid == 0
                    or account.pw_uid >= 1000
                    or account.pw_name == 'pi'
                    or bool({'sudo', 'wheel'} & set(groups))
                )
            )
            if should_test and (PASSLIB_AVAILABLE or CRYPT_AVAILABLE or LIBCRYPT_AVAILABLE):
                for candidate in weak_passwords:
                    if verify_password_against_hash(candidate, password_hash):
                        weak_password_matches[account.pw_name] = candidate
                        break

        os_release = read_os_release()
        ssh_exposure = assess_ssh_password_exposure()
        vendor_default_profiles: Dict[str, str] = {}
        if os_release.get('ID', '').lower() == 'kali' and weak_password_matches.get('kali') == 'kali':
            vendor_default_profiles['kali'] = 'KALI_PRECREATED_IMAGE_DEFAULT'
        if weak_password_matches.get('pi') == 'raspberry':
            vendor_default_profiles['pi'] = 'LEGACY_RASPBERRY_PI_OS_DEFAULT'

        self.report.raw_artifacts['local_accounts'] = {
            'accounts': account_inventory,
            'privileged_groups': {
                name: sorted(members) for name, members in group_members.items()
            },
            'weak_password_dictionary_size': len(weak_passwords),
            'password_verification_available': PASSLIB_AVAILABLE or CRYPT_AVAILABLE or LIBCRYPT_AVAILABLE,
            'weak_password_accounts': sorted(weak_password_matches),
            'vendor_default_profiles': vendor_default_profiles,
            'os_release': os_release,
            'ssh_password_exposure': ssh_exposure,
        }

        if extra_uid_zero:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-004', severity='CRITICAL', category='ACCESS',
                description='Additional UID 0 accounts were detected.',
                evidence=', '.join(sorted(extra_uid_zero)),
                remediation='Remove unintended UID 0 accounts and use sudo for delegated administration.',
            ))

        if empty_passwords:
            self.report.add_finding(Finding(
                rule_id='RPI-CRED-001', severity='CRITICAL', category='ACCESS',
                description='Interactive or local accounts have empty password hashes.',
                evidence=', '.join(sorted(empty_passwords)),
                remediation='Set strong passwords, lock the accounts, or remove unused accounts.',
            ))

        if weak_password_matches:
            accounts = sorted(weak_password_matches)
            privileged_accounts = sorted(
                account for account in accounts
                if any(
                    item['username'] == account
                    and (item['uid'] == 0 or bool({'sudo', 'wheel'} & set(item['privilege_groups'])))
                    for item in account_inventory
                )
            )
            vendor_accounts = sorted(vendor_default_profiles)
            remote_exposure = bool(ssh_exposure.get('confirmed_remote_password_exposure'))

            severity = 'CRITICAL' if privileged_accounts else 'HIGH'
            status = 'DETECTED'
            finding_class = 'CREDENTIAL_WEAKNESS'
            rationale_parts = []
            if vendor_accounts:
                status = 'VENDOR_DEFAULT_CREDENTIAL'
                finding_class = 'VENDOR_DEFAULT_CREDENTIAL'
                rationale_parts.append(
                    'The matched credential corresponds to a documented pre-created image default.'
                )
                # Keep a confirmed remotely reachable default credential CRITICAL.
                # Otherwise default-profile severity is HIGH so OS image hygiene
                # does not obscure boot-chain findings in the top-line summary.
                if not remote_exposure and self.report.policy_profile == 'default':
                    severity = 'HIGH'
            if remote_exposure:
                rationale_parts.append('Wildcard SSH with effective password authentication is enabled.')

            observed_parts = [f"accounts={','.join(accounts)}"]
            if vendor_accounts:
                observed_parts.append(
                    'vendor_profiles=' + ','.join(
                        f'{account}:{vendor_default_profiles[account]}' for account in vendor_accounts
                    )
                )
            observed_parts.append(f'remote_password_exposure={str(remote_exposure).lower()}')

            self.report.add_finding(Finding(
                rule_id='RPI-CRED-003', severity=severity, category='ACCESS',
                description='Common weak or default passwords were detected.',
                evidence='; '.join(observed_parts),
                remediation='Replace weak credentials and prefer key-based administrative access.',
                status=status,
                finding_class=finding_class,
                expected='No active interactive account matches the built-in weak/default credential set',
                observed='; '.join(observed_parts),
                rationale=' '.join(rationale_parts),
                evidence_items=[EvidenceRecord(
                    source_type='OS_OBSERVED',
                    source_path='/etc/shadow,/etc/passwd,/etc/group',
                    acquisition_method='offline hash verification plus account privilege inventory',
                    trust_level='MEDIUM',
                    raw='; '.join(observed_parts),
                    normalized={
                        'accounts': accounts,
                        'privileged_accounts': privileged_accounts,
                        'vendor_default_profiles': vendor_default_profiles,
                        'ssh_password_exposure': ssh_exposure,
                    },
                )],
            ))

        try:
            pi_account = pwd.getpwnam('pi')
        except KeyError:
            pi_account = None
        if pi_account:
            pi_interactive = pi_account.pw_shell not in non_login_shells
            pi_admin = bool({'sudo', 'wheel'} & {
                name for name, members in group_members.items() if 'pi' in members
            })
            if pi_interactive and pi_admin:
                self.report.add_finding(Finding(
                    rule_id='RPI-CRED-005', severity='MEDIUM', category='ACCESS',
                    description="The conventional 'pi' account remains interactive and administrative.",
                    evidence=f"shell={pi_account.pw_shell}; sudo_or_wheel={pi_admin}",
                    remediation="Rename, disable or de-privilege the 'pi' account when it is not operationally required.",
                ))
            else:
                self.report.add_finding(Finding(
                    rule_id='RPI-CRED-006', severity='INFO', category='ACCESS',
                    description="The conventional 'pi' account exists.",
                    evidence=f"shell={pi_account.pw_shell}; sudo_or_wheel={pi_admin}",
                    remediation="Confirm that the account is required and appropriately restricted.",
                ))

    def check_apt_sources(self):
        """Audit one-line and deb822 APT sources with apt-secure-aware severity."""
        source_files = (
            ['/etc/apt/sources.list']
            + glob.glob('/etc/apt/sources.list.d/*.list')
            + glob.glob('/etc/apt/sources.list.d/*.sources')
        )

        http_repos = []
        trusted_repos = []
        insecure_overrides = []
        unsigned_third_party = []
        unstable_repos = []
        suspicious_repos = []
        source_inventory: List[Dict[str, Any]] = []

        official_domain_suffixes = (
            'kali.org', 'debian.org', 'raspberrypi.com', 'raspberrypi.org',
            'raspbian.org', 'ubuntu.com', 'canonical.com'
        )
        suspicious_keywords = ('malware', 'crack', 'warez')

        def host_is_official(uri: str) -> bool:
            host = (urlparse(uri).hostname or '').lower().rstrip('.')
            return any(host == suffix or host.endswith('.' + suffix)
                       for suffix in official_domain_suffixes)

        def inspect_entry(source_file: str, location: str, uri: str,
                          options: str = '', signed_by: bool = False,
                          suite_text: str = ''):
            lowered = f"{uri} {options} {suite_text}".lower()
            label = f"{source_file}:{location} ({uri})"
            source_inventory.append({
                'source_file': source_file,
                'location': location,
                'uri': uri,
                'options': options,
                'signed_by_declared': signed_by,
                'suite_text': suite_text,
                'official_domain': host_is_official(uri),
            })

            if uri.lower().startswith('http://'):
                http_repos.append(label)
            if re.search(r'(^|[\s,])trusted\s*=\s*yes($|[\s,])', options, re.IGNORECASE):
                trusted_repos.append(label)
            if re.search(
                r'(allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*=\s*yes',
                options,
                re.IGNORECASE,
            ):
                insecure_overrides.append(label)
            if ('unstable' in suite_text.lower() or
                    'experimental' in suite_text.lower()):
                unstable_repos.append(label)
            if any(keyword in lowered for keyword in suspicious_keywords):
                suspicious_repos.append(label)
            if uri and not host_is_official(uri) and not signed_by:
                unsigned_third_party.append(label)

        for source_file in sorted(set(source_files)):
            if not os.path.isfile(source_file):
                continue
            try:
                content = Path(source_file).read_text(encoding='utf-8', errors='replace')
            except PermissionError:
                continue

            if source_file.endswith('.sources'):
                for block_index, block in enumerate(re.split(r'\n\s*\n', content), 1):
                    fields: Dict[str, str] = {}
                    current_key: Optional[str] = None
                    for raw_line in block.splitlines():
                        if not raw_line.strip() or raw_line.lstrip().startswith('#'):
                            continue
                        if raw_line[:1].isspace() and current_key:
                            fields[current_key] += ' ' + raw_line.strip()
                            continue
                        if ':' not in raw_line:
                            continue
                        key, value = raw_line.split(':', 1)
                        current_key = key.strip().lower()
                        fields[current_key] = value.strip()

                    if fields.get('enabled', 'yes').lower() == 'no':
                        continue
                    if 'deb' not in fields.get('types', 'deb').lower().split():
                        continue

                    options = ' '.join(
                        f"{key}={fields[key]}" for key in (
                            'trusted', 'allow-insecure', 'allow-weak',
                            'allow-downgrade-to-insecure'
                        ) if key in fields
                    )
                    signed_by = bool(fields.get('signed-by'))
                    suites = fields.get('suites', '')
                    for uri in fields.get('uris', '').split():
                        inspect_entry(
                            source_file, f"block {block_index}", uri,
                            options=options, signed_by=signed_by,
                            suite_text=suites,
                        )
            else:
                for line_num, raw_line in enumerate(content.splitlines(), 1):
                    line = raw_line.strip()
                    if not line or line.startswith('#') or not re.match(r'^deb(?:-src)?\s', line):
                        continue

                    remainder = re.sub(r'^deb(?:-src)?\s+', '', line, count=1)
                    options = ''
                    if remainder.startswith('['):
                        closing = remainder.find(']')
                        if closing != -1:
                            options = remainder[1:closing]
                            remainder = remainder[closing + 1:].strip()
                    tokens = remainder.split()
                    if not tokens:
                        continue
                    uri = tokens[0]
                    suites = ' '.join(tokens[1:])
                    signed_by = bool(re.search(r'(^|\s)signed-by\s*=', options, re.IGNORECASE))
                    inspect_entry(
                        source_file, str(line_num), uri,
                        options=options, signed_by=signed_by,
                        suite_text=suites,
                    )

        self.report.raw_artifacts['apt_sources'] = source_inventory

        if insecure_overrides:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-004", severity="CRITICAL", category="INTEGRITY",
                description="APT signature-security overrides are enabled.",
                evidence="; ".join(sorted(set(insecure_overrides))),
                remediation="Remove allow-insecure, allow-weak and downgrade-to-insecure overrides."
            ))

        if trusted_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-005", severity="HIGH", category="INTEGRITY",
                description="APT repositories bypass normal authentication with trusted=yes.",
                evidence="; ".join(sorted(set(trusted_repos))),
                remediation="Remove trusted=yes and configure a repository-specific signing key."
            ))

        if unsigned_third_party:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-006", severity="MEDIUM", category="INTEGRITY",
                description="Third-party APT repositories do not declare a repository-specific Signed-By key.",
                evidence="; ".join(sorted(set(unsigned_third_party))),
                remediation="Configure Signed-By with a dedicated keyring for each third-party repository."
            ))

        if http_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-001", severity="INFO", category="INTEGRITY",
                description="APT repositories use unencrypted HTTP transport.",
                evidence="; ".join(sorted(set(http_repos))),
                remediation=(
                    "Prefer HTTPS where available. Package authenticity still depends on "
                    "valid apt-secure Release/InRelease signatures."
                )
            ))

        if suspicious_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-003", severity="CRITICAL", category="INTEGRITY",
                description="Repository URI contains a strongly suspicious keyword.",
                evidence="; ".join(sorted(set(suspicious_repos))),
                remediation="Validate repository ownership and remove unauthorized sources."
            ))

        if unstable_repos:
            self.report.add_finding(Finding(
                rule_id="RPI-APT-002", severity="MEDIUM", category="INTEGRITY",
                description="Unstable or experimental APT suites are enabled.",
                evidence="; ".join(sorted(set(unstable_repos))),
                remediation="Confirm that unstable repositories are intentional for this device role."
            ))

    def check_critical_file_permissions(self):
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/boot/firmware/config.txt'
        ]
        
        for filepath in critical_files:
            if os.path.exists(filepath):
                try:
                    stat = os.stat(filepath)
                    mode = stat.st_mode & 0o777
                    
                    if mode & 0o002:
                        self.report.add_finding(Finding(
                            rule_id="RPI-PERM-001", severity="HIGH", category="ACCESS",
                            description=f"Critical file is world-writable: {filepath}",
                            evidence=f"Permissions: {oct(mode)}",
                            remediation=f"Run: chmod 644 {filepath}"
                        ))
                    
                    if 'shadow' in filepath and mode != 0o640:
                        self.report.add_finding(Finding(
                            rule_id="RPI-PERM-002", severity="CRITICAL", category="ACCESS",
                            description=f"Shadow file has incorrect permissions.",
                            evidence=f"Permissions: {oct(mode)} (expected 640)",
                            remediation=f"Run: chmod 640 {filepath}"
                        ))
                    
                    if 'sudoers' in filepath and mode != 0o440:
                        self.report.add_finding(Finding(
                            rule_id="RPI-PERM-003", severity="CRITICAL", category="ACCESS",
                            description=f"Sudoers file has incorrect permissions.",
                            evidence=f"Permissions: {oct(mode)} (expected 440)",
                            remediation=f"Run: chmod 440 {filepath}"
                        ))
                        
                except Exception as e:
                    logger.error(f"Error checking permissions for {filepath}: {e}")

    def check_suspicious_processes(self):
        """Inspect /proc using exact executable names and high-confidence argument patterns."""
        malware_names = {
            'meterpreter', 'metsrv', 'xmrig', 'minerd', 'cpuminer',
            'cryptominer', 'kinsing', 'kdevtmpfsi'
        }
        dual_use_names = {'nc', 'netcat', 'ncat', 'socat'}
        strong_argument_patterns = [
            re.compile(r'(?i)(?:^|[\s/])meterpreter(?:[\s/]|$)'),
            re.compile(r'(?i)stratum\+(?:tcp|ssl)://'),
            re.compile(r'(?i)(?:^|[\s_-])cryptonight(?:[\s_-]|$)'),
        ]
        shell_exec_pattern = re.compile(
            r'(?i)(?:-e|--exec|--sh-exec|exec:|system:)\s*[^\s]*(?:/bin/)?(?:sh|bash|dash|zsh)\b'
        )

        high_confidence = []
        dual_use = []
        own_pids = {os.getpid(), os.getppid()}

        for proc_dir in glob.glob('/proc/[0-9]*'):
            try:
                pid = int(os.path.basename(proc_dir))
            except ValueError:
                continue
            if pid in own_pids:
                continue

            try:
                comm = Path(proc_dir, 'comm').read_text(
                    encoding='utf-8', errors='replace'
                ).strip()
            except (OSError, PermissionError):
                comm = ''

            try:
                exe_path = os.readlink(os.path.join(proc_dir, 'exe'))
            except OSError:
                exe_path = ''

            try:
                raw_cmdline = Path(proc_dir, 'cmdline').read_bytes()
                cmdline = raw_cmdline.replace(b'\x00', b' ').decode(
                    'utf-8', errors='replace'
                ).strip()
            except (OSError, PermissionError):
                cmdline = ''

            executable = os.path.basename(exe_path) or comm
            executable_lower = executable.lower()
            cmdline_lower = cmdline.lower()
            evidence = f"pid={pid}; exe={exe_path or executable}; cmdline={cmdline[:500]}"

            if executable_lower in malware_names:
                high_confidence.append(evidence)
                continue

            if any(pattern.search(cmdline) for pattern in strong_argument_patterns):
                high_confidence.append(evidence)
                continue

            if executable_lower in dual_use_names:
                if shell_exec_pattern.search(cmdline):
                    high_confidence.append(evidence)
                else:
                    dual_use.append(evidence)

        if high_confidence:
            self.report.add_finding(Finding(
                rule_id="RPI-PROC-001", severity="HIGH", category="PROCESSES",
                description="High-confidence suspicious process indicators were detected.",
                evidence=(
                    f"Found {len(high_confidence)} process(es):\n"
                    + "\n".join(high_confidence[:10])
                ),
                remediation="Validate executable provenance, parent process and network activity before termination."
            ))

        if dual_use:
            self.report.add_finding(Finding(
                rule_id="RPI-PROC-002", severity="INFO", category="PROCESSES",
                description="Dual-use networking utilities are currently running.",
                evidence=(
                    f"Found {len(dual_use)} process(es):\n"
                    + "\n".join(dual_use[:10])
                ),
                remediation="Confirm that each utility and its command line are expected."
            ))

    def check_firewall(self):
        firewalls = [
            {'name': 'ufw', 'cmd': ['ufw', 'status'], 'check': 'active'},
            {'name': 'nftables', 'cmd': ['nft', 'list', 'ruleset'], 'check': 'table'},
            {'name': 'iptables', 'cmd': ['iptables', '-L'], 'check': 'Chain'}
        ]
        
        active_firewalls = []
        
        for fw in firewalls:
            try:
                result = subprocess.run(fw['cmd'], capture_output=True, text=True)
                if fw['name'] == 'ufw' and 'active' in result.stdout.lower():
                    active_firewalls.append(fw['name'])
                elif fw['name'] == 'nftables' and 'table' in result.stdout:
                    active_firewalls.append(fw['name'])
                elif fw['name'] == 'iptables' and 'Chain' in result.stdout and len(result.stdout.splitlines()) > 3:
                    active_firewalls.append(fw['name'])
            except (OSError, subprocess.SubprocessError):
                continue
        
        if not active_firewalls:
            self.report.add_finding(Finding(
                rule_id="RPI-FW-001", severity="HIGH", category="NETWORK",
                description="No active firewall detected.",
                evidence="ufw, nftables, iptables not active",
                remediation="Install and configure a firewall. Recommended: sudo apt install ufw && sudo ufw enable"
            ))

# ==============================================================================
# 10. Hardware Interrogator and SPI EEPROM/WP Assessment
# ==============================================================================

@dataclass
class SPIReadResult:
    attempted: bool = False
    source_type: str = "OS_MEDIATED_SPI_READ"
    trust_level: str = "MEDIUM"
    flashrom_path: Optional[str] = None
    device: Optional[str] = None
    programmer: Optional[str] = None
    expected_size: Optional[int] = None
    probe_ok: bool = False
    probe_returncode: Optional[int] = None
    probe_output: str = ""
    detected_chip: Optional[str] = None
    output_path: Optional[str] = None
    read_ok: bool = False
    read_returncode: Optional[int] = None
    read_output: str = ""
    size: Optional[int] = None
    size_matches_expected: Optional[bool] = None
    sha256: Optional[str] = None
    bootconf_path: Optional[str] = None
    bootconf: Optional[str] = None
    config_matches_live: Optional[bool] = None
    config_comparison: Dict[str, Any] = field(default_factory=dict)
    wp_attempted: bool = False
    wp_returncode: Optional[int] = None
    wp_output: str = ""
    wp_supported: Optional[bool] = None
    wp_enabled: Optional[bool] = None
    wp_start: Optional[int] = None
    wp_length: Optional[int] = None
    wp_full_chip: Optional[bool] = None
    wp_assessment: str = "NOT_TESTED"
    raw_status_registers_available: bool = False
    raw_status_registers: Dict[str, Any] = field(default_factory=dict)
    physical_wp_state: str = "NOT_MEASURED"
    ab_layout_magic_detected: Optional[bool] = None
    ab_layout_offsets: List[int] = field(default_factory=list)
    error: Optional[str] = None


class HardwareInterrogator:
    VCGENCMD_CANDIDATES = [
        '/usr/local/bin/vcgencmd', '/usr/bin/vcgencmd', '/opt/vc/bin/vcgencmd'
    ]
    RPI_EEPROM_CONFIG_CANDIDATES = [
        '/usr/local/bin/rpi-eeprom-config', '/usr/bin/rpi-eeprom-config',
        '/opt/rpi-eeprom/rpi-eeprom-config'
    ]
    RPI_EEPROM_UPDATE_CANDIDATES = [
        '/usr/local/bin/rpi-eeprom-update', '/usr/bin/rpi-eeprom-update',
        '/opt/rpi-eeprom/rpi-eeprom-update'
    ]
    RPI_EEPROM_AB_CANDIDATES = [
        '/usr/local/bin/rpi-eeprom-ab', '/usr/bin/rpi-eeprom-ab',
        '/usr/sbin/rpi-eeprom-ab'
    ]
    FLASHROM_CANDIDATES = [
        '/usr/local/sbin/flashrom', '/usr/local/bin/flashrom',
        '/usr/sbin/flashrom', '/usr/bin/flashrom'
    ]

    def __init__(self):
        self.vcgencmd_path = _find_executable('vcgencmd', self.VCGENCMD_CANDIDATES)
        self.rpi_eeprom_config_path = _find_executable(
            'rpi-eeprom-config', self.RPI_EEPROM_CONFIG_CANDIDATES
        )
        self.rpi_eeprom_update_path = _find_executable(
            'rpi-eeprom-update', self.RPI_EEPROM_UPDATE_CANDIDATES
        )
        self.rpi_eeprom_ab_path = _find_executable(
            'rpi-eeprom-ab', self.RPI_EEPROM_AB_CANDIDATES
        )
        self.flashrom_path = _find_executable('flashrom', self.FLASHROM_CANDIDATES)
        self.cache = CacheManager()

    @staticmethod
    def _run_completed(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    def _run_cmd(self, cmd: List[str], timeout: int = 30, cache: bool = True) -> str:
        cache_key = ' '.join(cmd)
        if cache:
            cached = self.cache.get(cache_key)
            if cached:
                return cached
        try:
            result = self._run_completed(cmd, timeout=timeout)
            output = '\n'.join(
                part.strip() for part in (result.stdout, result.stderr) if part and part.strip()
            )
            if result.returncode != 0:
                return f'ERROR_EXEC: {output}'
            if cache:
                self.cache.set(cache_key, output)
            return output
        except subprocess.TimeoutExpired:
            return f'ERROR_TIMEOUT: command exceeded {timeout}s'
        except FileNotFoundError:
            return 'ERROR_MISSING: Command not found'

    def get_otp_dump(self) -> Dict[str, str]:
        if not self.vcgencmd_path:
            return {}
        raw_output = self._run_cmd([self.vcgencmd_path, 'otp_dump'])
        otp_map: Dict[str, str] = {}
        if raw_output.startswith('ERROR'):
            return otp_map
        for line in raw_output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                otp_map[key.strip()] = value.strip()
        return otp_map

    def get_eeprom_config(self) -> str:
        if not self.rpi_eeprom_config_path:
            return 'ERROR_MISSING: rpi-eeprom-config not found'
        return self._run_cmd([self.rpi_eeprom_config_path])

    def get_bootloader_version(self) -> str:
        if not self.vcgencmd_path:
            return 'UNKNOWN'
        return self._run_cmd([self.vcgencmd_path, 'bootloader_version'])

    def get_tool_metadata(self) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            'kernel_release': py_platform.release(),
            'python_version': py_platform.python_version(),
        }

        if self.flashrom_path:
            output = self._run_cmd([self.flashrom_path, '--version'], cache=False)
            if output.startswith('ERROR'):
                output = self._run_cmd([self.flashrom_path, '-V'], cache=False)
            version = parse_version_tuple(output)
            metadata['flashrom'] = {
                'path': self.flashrom_path,
                'version_output': output[:1000],
                'version': '.'.join(map(str, version)) if version else None,
                'wp_cli_expected': bool(version and version >= (1, 3, 0)),
                'upstream_1_4_to_1_6_write_caution': bool(
                    version and (1, 4, 0) <= version < (1, 7, 0)
                ),
                'ggfw_usage': 'probe/read/wp-status only',
            }
        else:
            metadata['flashrom'] = {'path': None, 'version': None}

        if self.vcgencmd_path:
            metadata['vcgencmd'] = {
                'path': self.vcgencmd_path,
                'firmware_version': self._run_cmd(
                    [self.vcgencmd_path, 'version'], cache=False
                )[:2000],
            }
        else:
            metadata['vcgencmd'] = {'path': None}

        for name, path in (
            ('rpi-eeprom-config', self.rpi_eeprom_config_path),
            ('rpi-eeprom-update', self.rpi_eeprom_update_path),
            ('rpi-eeprom-ab', self.rpi_eeprom_ab_path),
        ):
            entry: Dict[str, Any] = {'path': path}
            if path:
                entry['sha256'] = sha256_file(path)
                if name == 'rpi-eeprom-ab':
                    entry['version_output'] = self._run_cmd(
                        [path, 'version'], cache=False
                    )[:1000]
            metadata[name] = entry

        return metadata



class SPIEEPROMReader:
    """Read-only acquisition of the Raspberry Pi boot EEPROM via flashrom."""

    DEFAULT_DEVICES = {
        "BCM2711": ["/dev/spidev0.0"],
        "BCM2712": ["/dev/spidev10.0"],
    }
    EXPECTED_SIZES = {
        "BCM2711": 512 * 1024,
        "BCM2712": 2 * 1024 * 1024,
    }

    def __init__(
        self,
        platform: str,
        flashrom_path: Optional[str],
        rpi_eeprom_config_path: Optional[str],
        report: GGFWReport,
        device_override: Optional[str] = None,
        spi_speed_khz: int = 16000,
    ):
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.flashrom_path = flashrom_path
        self.rpi_eeprom_config_path = rpi_eeprom_config_path
        self.report = report
        self.device_override = device_override
        self.spi_speed_khz = spi_speed_khz

    @staticmethod
    def _combined_output(result: subprocess.CompletedProcess) -> str:
        parts = []
        if result.stdout:
            parts.append(result.stdout.strip())
        if result.stderr:
            parts.append(result.stderr.strip())
        return "\n".join(part for part in parts if part)

    @staticmethod
    def _sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _detect_ab_layout_magic(path: str) -> Tuple[Optional[bool], List[int]]:
        """Heuristically identify BCM2712 A/B metadata markers in a 2 MiB dump."""
        marker = bytes.fromhex('55 aa f5 5f')
        try:
            size = os.path.getsize(path)
            offsets = [size - 0x2000, size - 0x1000]
            matched: List[int] = []
            with open(path, 'rb') as handle:
                for offset in offsets:
                    if offset < 0:
                        continue
                    handle.seek(offset)
                    if handle.read(len(marker)) == marker:
                        matched.append(offset)
            if len(matched) == len(offsets):
                return True, matched
            if matched:
                return None, matched
            return False, []
        except OSError:
            return None, []

    @staticmethod
    def _normalise_config(config: Optional[str]) -> str:
        if not config:
            return ""
        lines = []
        for line in config.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                lines.append(stripped)
        return "\n".join(lines)

    @staticmethod
    def _config_map(config: Optional[str]) -> Dict[str, str]:
        if not config:
            return {}
        parsed: Dict[str, str] = {}
        for raw_line in config.splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#') or line.startswith('[') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            parsed[key.strip().upper()] = value.strip()
        return parsed

    @classmethod
    def _compare_configs(cls, raw_config: Optional[str], live_config: Optional[str]) -> Dict[str, Any]:
        raw_map = cls._config_map(raw_config)
        live_map = cls._config_map(live_config)
        common = sorted(set(raw_map) & set(live_map))
        matching = [key for key in common if raw_map[key] == live_map[key]]
        different = [
            {'field': key, 'raw_spi': raw_map[key], 'live': live_map[key]}
            for key in common if raw_map[key] != live_map[key]
        ]
        only_raw = {key: raw_map[key] for key in sorted(set(raw_map) - set(live_map))}
        only_live = {key: live_map[key] for key in sorted(set(live_map) - set(raw_map))}
        if not raw_map or not live_map:
            result = 'NOT_COMPARABLE'
        elif not different and not only_raw and not only_live:
            result = 'FULL_MATCH'
        elif different:
            result = 'MISMATCH'
        else:
            result = 'PARTIAL_MATCH'
        return {
            'mode': 'NORMALIZED_KEY_VALUE',
            'raw_spi_source': 'bootconf extracted from OS-mediated SPI dump',
            'live_source': 'rpi-eeprom-config live firmware report',
            'compared_fields': common,
            'matching_fields': matching,
            'different_fields': different,
            'only_in_raw': only_raw,
            'only_in_live': only_live,
            'result': result,
        }

    @staticmethod
    def _unique_path(requested_path: str) -> str:
        path = Path(requested_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            return str(path)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return str(path.with_name(f"{path.stem}-{timestamp}{path.suffix}"))

    def _select_device(self) -> Optional[str]:
        if self.device_override:
            return self.device_override

        for device in self.DEFAULT_DEVICES.get(self.soc, []):
            if os.path.exists(device):
                return device
        return None

    @staticmethod
    def _extract_chip_name(output: str) -> Optional[str]:
        patterns = [
            r'Found\s+[^\n]*?flash chip\s+"([^"]+)"',
            r'Found\s+flash chip\s+"([^"]+)"',
            r'Found\s+([^\n]+?)\s+flash chip',
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def _parse_wp_status(output: str, expected_size: Optional[int]) -> Dict[str, Any]:
        """Parse flashrom --wp-status output, including the flashrom 1.6 format."""
        lowered = output.lower()
        unsupported_markers = (
            'not supported', 'unsupported', 'untested for operations: wp',
            'write protection is not supported', 'failed to get write protection',
            'cannot get write protection'
        )

        enabled: Optional[bool] = None
        if re.search(
            r'(?:write\s+)?protection(?:\s+mode)?\s*(?::|is)?\s*enabled',
            lowered,
        ):
            enabled = True
        elif re.search(
            r'(?:write\s+)?protection(?:\s+mode)?\s*(?::|is)?\s*disabled',
            lowered,
        ):
            enabled = False
        elif re.search(r'write\s+protect(?:ion)?\s+is\s+enabled', lowered):
            enabled = True
        elif re.search(r'write\s+protect(?:ion)?\s+is\s+disabled', lowered):
            enabled = False

        start: Optional[int] = None
        length: Optional[int] = None
        range_match = re.search(
            r'(?:(?:write\s+)?protection|write\s+protect|wp)'
            r'(?:\s+range)?\s*:\s*'
            r'start\s*=\s*(0x[0-9a-f]+|[0-9]+)'
            r'(?:\s*,?\s*)'
            r'(?:len|length)\s*=\s*(0x[0-9a-f]+|[0-9]+)',
            output,
            re.IGNORECASE,
        )
        if range_match:
            start = int(range_match.group(1), 0)
            length = int(range_match.group(2), 0)

        has_wp_data = (
            enabled is not None
            or range_match is not None
            or 'wp: status' in lowered
            or 'write protection mode' in lowered
            or 'protection mode:' in lowered
            or 'protection range:' in lowered
        )
        supported = has_wp_data and not any(marker in lowered for marker in unsupported_markers)

        full_chip: Optional[bool] = None
        if start is not None and length is not None and expected_size is not None:
            full_chip = start == 0 and length >= expected_size

        if not supported:
            assessment = 'UNKNOWN'
        elif full_chip and enabled is not False:
            assessment = 'FULL'
        elif length == 0 or enabled is False:
            assessment = 'DISABLED'
        elif length is not None and length > 0:
            assessment = 'PARTIAL'
        else:
            assessment = 'UNKNOWN'

        return {
            'supported': supported,
            'enabled': enabled,
            'start': start,
            'length': length,
            'full_chip': full_chip,
            'assessment': assessment,
        }

    def _record_wp_assessment(self, result: SPIReadResult):
        evidence = result.wp_output[-3000:] or 'No flashrom --wp-status output'

        if result.wp_assessment == 'FULL':
            self.report.add_check(
                'RPI-SPI-WP-PASS', 'BOOT_AND_EEPROM',
                'SPI EEPROM full-chip status-register protection is enabled.',
                source_type='OS_MEDIATED_SPI_READ',
                start=result.wp_start, length=result.wp_length,
                expected_size=result.expected_size,
                physical_wp_state=result.physical_wp_state,
            )
            return
        if result.wp_assessment == 'DISABLED':
            self.report.add_finding(Finding(
                rule_id="RPI-SPI-WP-001", severity="HIGH", category="HARDWARE",
                description="SPI EEPROM data range is not effectively write-protected.",
                evidence=evidence,
                remediation="Use the Raspberry Pi recovery process with eeprom_write_protect=1 to configure full-chip status-register protection, then verify it with flashrom --wp-status. Do not enable write operations from GGFW.",
                domain="BOOT_AND_EEPROM", status="DISABLED", confidence="HIGH",
                expected="Required: full-chip status-register protection; recommended additional hardware enforcement: physical #WP asserted",
                observed=(
                    f"range_start={result.wp_start}; range_length={result.wp_length}; "
                    f"mode_enabled={result.wp_enabled}; physical_wp={result.physical_wp_state}"
                ),
                rationale=("The zero-length status-register protection range conclusively means that no EEPROM address range is protected. "
                           "This finding remains valid regardless of the unmeasured physical #WP signal state; #WP cannot enforce "
                           "data-range protection when the status registers define no protected range."),
                evidence_items=[EvidenceRecord(
                    source_type="OS_MEDIATED_SPI_READ",
                    source_path=result.device or "",
                    acquisition_method="flashrom --wp-status via linux_spi",
                    trust_level="MEDIUM",
                    raw=evidence,
                    normalized={
                        "assessment": result.wp_assessment,
                        "enabled": result.wp_enabled,
                        "start": result.wp_start,
                        "length": result.wp_length,
                        "expected_size": result.expected_size,
                        "raw_status_registers_available": result.raw_status_registers_available,
                        "physical_wp_state": result.physical_wp_state,
                    },
                )],
            ))
            return
        if result.wp_assessment == 'PARTIAL':
            self.report.add_finding(Finding(
                rule_id="RPI-SPI-WP-002", severity="MEDIUM", category="HARDWARE",
                description="SPI EEPROM write protection covers only part of the flash chip.",
                evidence=(
                    f"start={result.wp_start!r}; length={result.wp_length!r}; "
                    f"expected_size={result.expected_size!r}\n{evidence}"
                ),
                remediation="Use the Raspberry Pi recovery process to configure full-chip EEPROM protection and verify the final range with flashrom --wp-status.",
                domain="BOOT_AND_EEPROM", status="PARTIAL", confidence="HIGH",
                expected="The entire EEPROM address range is protected",
                observed=f"start={result.wp_start}; length={result.wp_length}; size={result.expected_size}",
            ))
            return

        self.report.add_finding(Finding(
            rule_id="RPI-SPI-WP-000", severity="INFO", category="HARDWARE",
            description="SPI EEPROM write-protection state could not be conclusively determined.",
            evidence=evidence,
            remediation="Use a flashrom build and programmer combination that supports --wp-status for this chip."
        ))

    def _add_limitation(self, rule_id: str, description: str, evidence: str, remediation: str):
        self.report.add_finding(Finding(
            rule_id=rule_id,
            severity="INFO",
            category="HARDWARE",
            description=description,
            evidence=evidence,
            remediation=remediation,
        ))

    def acquire(self, output_path: str, live_config: Optional[str]) -> SPIReadResult:
        result = SPIReadResult(
            attempted=True,
            flashrom_path=self.flashrom_path,
            expected_size=self.EXPECTED_SIZES.get(self.soc),
        )

        if os.geteuid() != 0:
            result.error = "SPI acquisition requires root privileges"
            self._add_limitation(
                "RPI-SPI-000",
                "SPI EEPROM acquisition skipped because GGFW is not running as root.",
                "Effective UID is not 0",
                "Run GGFW with sudo for read-only SPI acquisition.",
            )
            return result

        if not self.flashrom_path:
            result.error = "flashrom not found"
            self._add_limitation(
                "RPI-SPI-001",
                "SPI EEPROM acquisition skipped because flashrom is unavailable.",
                "flashrom executable not found",
                "Install the flashrom package.",
            )
            return result

        device = self._select_device()
        result.device = device
        if not device:
            expected = ", ".join(self.DEFAULT_DEVICES.get(self.soc, [])) or "unknown"
            result.error = "Expected SPI device not present"
            self._add_limitation(
                "RPI-SPI-002",
                "Expected Raspberry Pi boot EEPROM SPI device is not available.",
                f"SoC={self.soc}; expected device={expected}",
                "Verify the SPI device node and platform-specific boot configuration.",
            )
            return result

        programmer = f"linux_spi:dev={device},spispeed={self.spi_speed_khz}"
        result.programmer = programmer

        probe_cmd = [self.flashrom_path, "-p", programmer]
        try:
            probe = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            result.probe_returncode = probe.returncode
            result.probe_output = self._combined_output(probe)
            result.probe_ok = probe.returncode == 0
            result.detected_chip = self._extract_chip_name(result.probe_output)
        except subprocess.TimeoutExpired:
            result.error = "flashrom probe timed out"
            result.probe_output = "Probe exceeded 45 seconds"
            self._add_limitation(
                "RPI-SPI-003",
                "SPI EEPROM probe timed out.",
                result.probe_output,
                "Check SPI device availability and flashrom compatibility.",
            )
            return result

        if not result.probe_ok:
            result.error = "flashrom probe failed"
            self._add_limitation(
                "RPI-SPI-003",
                "flashrom could not identify the boot EEPROM.",
                result.probe_output[-2000:] or "No flashrom output",
                "Verify the selected spidev node and use a flashrom build compatible with the EEPROM.",
            )
            return result

        result.wp_attempted = True
        wp_cmd = [self.flashrom_path, "-p", programmer, "--wp-status"]
        try:
            wp_result = subprocess.run(
                wp_cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            result.wp_returncode = wp_result.returncode
            result.wp_output = self._combined_output(wp_result)
            parsed_wp = self._parse_wp_status(result.wp_output, result.expected_size)
            result.wp_supported = parsed_wp['supported']
            result.wp_enabled = parsed_wp['enabled']
            result.wp_start = parsed_wp['start']
            result.wp_length = parsed_wp['length']
            result.wp_full_chip = parsed_wp['full_chip']
            result.wp_assessment = parsed_wp['assessment']
        except subprocess.TimeoutExpired:
            result.wp_output = "flashrom --wp-status exceeded 45 seconds"
            result.wp_supported = None
            result.wp_assessment = 'UNKNOWN'

        self._record_wp_assessment(result)

        final_output = self._unique_path(output_path)
        result.output_path = final_output
        read_cmd = [self.flashrom_path, "-p", programmer, "-r", final_output]

        try:
            read = subprocess.run(
                read_cmd,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            result.read_returncode = read.returncode
            result.read_output = self._combined_output(read)
            result.read_ok = read.returncode == 0 and os.path.isfile(final_output)
        except subprocess.TimeoutExpired:
            result.error = "flashrom read timed out"
            result.read_output = "Read exceeded 180 seconds"
            self._add_limitation(
                "RPI-SPI-004",
                "SPI EEPROM read timed out.",
                result.read_output,
                "Check SPI stability or reduce the SPI clock.",
            )
            return result

        if not result.read_ok:
            result.error = "flashrom read failed"
            self._add_limitation(
                "RPI-SPI-004",
                "SPI EEPROM read failed.",
                result.read_output[-2000:] or "No flashrom output",
                "Check flashrom compatibility, permissions and SPI signal stability.",
            )
            return result

        result.size = os.path.getsize(final_output)
        result.sha256 = self._sha256_file(final_output)
        if self.soc == "BCM2712":
            (
                result.ab_layout_magic_detected,
                result.ab_layout_offsets,
            ) = self._detect_ab_layout_magic(final_output)
        if result.expected_size is not None:
            result.size_matches_expected = result.size == result.expected_size
            if not result.size_matches_expected:
                self.report.add_finding(Finding(
                    rule_id="RPI-SPI-005",
                    severity="MEDIUM",
                    category="HARDWARE",
                    description="SPI EEPROM dump size differs from the expected platform size.",
                    evidence=(
                        f"SoC={self.soc}; observed={result.size} bytes; "
                        f"expected={result.expected_size} bytes"
                    ),
                    remediation="Confirm the detected flash chip and SPI mapping before analysing the dump.",
                ))

        if self.rpi_eeprom_config_path:
            bootconf_path = str(Path(final_output).with_suffix(".bootconf.txt"))
            config_cmd = [
                self.rpi_eeprom_config_path,
                final_output,
                "--out",
                bootconf_path,
            ]
            try:
                config_result = subprocess.run(
                    config_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if config_result.returncode == 0 and os.path.isfile(bootconf_path):
                    result.bootconf_path = bootconf_path
                    result.bootconf = Path(bootconf_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                    if live_config and not live_config.startswith("ERROR"):
                        result.config_comparison = self._compare_configs(result.bootconf, live_config)
                        result.config_matches_live = result.config_comparison['result'] == 'FULL_MATCH'
                        if result.config_comparison['result'] == 'MISMATCH':
                            self.report.add_finding(Finding(
                                rule_id="RPI-SPI-006",
                                severity="MEDIUM",
                                category="INTEGRITY",
                                description=(
                                    "Configuration parsed from the raw SPI dump differs "
                                    "from the live EEPROM configuration."
                                ),
                                evidence=json.dumps(result.config_comparison, ensure_ascii=False),
                                remediation=(
                                    "Review the field-level differences and confirm which EEPROM "
                                    "bank and boot path are active."
                                ),
                                expected="Raw SPI boot configuration and live firmware-reported configuration match",
                                observed=result.config_comparison['result'],
                                rationale="A mismatch can indicate a bank-selection difference, stale view or tampering.",
                            ))
                else:
                    result.read_output += (
                        "\nEEPROM config extraction failed: "
                        + self._combined_output(config_result)
                    )
            except subprocess.TimeoutExpired:
                result.read_output += "\nEEPROM config extraction timed out"

        return result


# ==============================================================================
# 11. OTP Decoder and Secure Boot Evidence Matrix
# ==============================================================================

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



# ==============================================================================
# 11A. Cryptographic Secure Boot chain validation
# ==============================================================================

RSA2048_SIGNATURE_SIZE = 256
RPI_PUBLIC_KEY_BIN_SIZE = 264
RPI_EEPROM_MAGIC = 0x55AAF00F
RPI_EEPROM_FILE_MAGIC = 0x55AAF11F
RPI_EEPROM_MAGIC_MASK = 0xFFFFF00F
RPI_EEPROM_FILE_HEADER_LEN = 20
RPI_EEPROM_FILENAME_LEN = 12
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

VALIDATION_VALID = 'VALID'
VALIDATION_INVALID = 'INVALID'
VALIDATION_UNVERIFIED = 'UNVERIFIED'

REASON_NONE = 'NONE'
REASON_KEY_UNAVAILABLE = 'KEY_UNAVAILABLE'
REASON_OTP_BINDING_UNAVAILABLE = 'OTP_BINDING_UNAVAILABLE'
REASON_ARTIFACT_NOT_FOUND = 'ARTIFACT_NOT_FOUND'
REASON_SIGNATURE_NOT_PRESENT = 'SIGNATURE_NOT_PRESENT'
REASON_FORMAT_INVALID = 'FORMAT_INVALID'
REASON_CRYPTOGRAPHIC_MISMATCH = 'CRYPTOGRAPHIC_MISMATCH'
REASON_TARGET_SOC_MISMATCH = 'TARGET_SOC_MISMATCH'
REASON_FRESHNESS_POLICY_FAILURE = 'FRESHNESS_POLICY_FAILURE'
REASON_IO_ERROR = 'IO_ERROR'
REASON_KEY_MISMATCH = 'KEY_MISMATCH'


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
    if offset >= len(data):
        raise SecureBootFormatError('Truncated DER length')
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise SecureBootFormatError('Unsupported DER length encoding')
    length = int.from_bytes(data[offset:offset + count], 'big')
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


def _parse_rsa_public_key_der(der: bytes, source: str = '') -> RSAPublicKeyMaterial:
    _, sequence, end = _der_read_tlv(der, 0, 0x30)
    if end != len(der):
        raise SecureBootFormatError('Trailing data after DER public key')

    # PKCS#1 RSAPublicKey starts directly with INTEGER modulus/exponent.
    try:
        _, modulus_bytes, pos = _der_read_tlv(sequence, 0, 0x02)
        _, exponent_bytes, pos = _der_read_tlv(sequence, pos, 0x02)
        if pos == len(sequence):
            modulus = int.from_bytes(modulus_bytes, 'big')
            exponent = int.from_bytes(exponent_bytes, 'big')
            key = RSAPublicKeyMaterial(modulus, exponent, source)
            key.to_pubkey_bin()
            return key
    except SecureBootFormatError:
        pass

    # SubjectPublicKeyInfo: AlgorithmIdentifier + BIT STRING containing PKCS#1.
    _, _, pos = _der_read_tlv(sequence, 0, 0x30)
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


def rsa_pkcs1_v15_sha256_verify_digest(
    digest: bytes, signature: bytes, key: RSAPublicKeyMaterial,
) -> bool:
    if len(digest) != 32 or len(signature) != RSA2048_SIGNATURE_SIZE or key.size_bits != 2048:
        return False
    encoded = pow(int.from_bytes(signature, 'big'), key.exponent, key.modulus).to_bytes(256, 'big')
    digest_info = SHA256_DIGEST_INFO_PREFIX + digest
    padding_len = 256 - len(digest_info) - 3
    if padding_len < 8:
        return False
    expected = b'\x00\x01' + (b'\xff' * padding_len) + b'\x00' + digest_info
    return encoded == expected


def rsa_pkcs1_v15_sha256_verify(data: bytes, signature: bytes, key: RSAPublicKeyMaterial) -> bool:
    return rsa_pkcs1_v15_sha256_verify_digest(hashlib.sha256(data).digest(), signature, key)


def parse_rpi_signature_text(content: str, source: str = '') -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'source': source,
        'format': 'RPI_EEPROM_DIGEST_TEXT_V1',
        'digest': None,
        'timestamp': None,
        'target_soc': None,
        'rsa2048_hex': None,
        'unknown_lines': [],
        'errors': [],
    }
    digest_seen = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(r'[0-9a-fA-F]{64}', line):
            if digest_seen:
                result['errors'].append('Duplicate SHA-256 digest line')
            else:
                result['digest'] = line.lower()
                digest_seen = True
            continue
        if line.startswith('ts:'):
            if result['timestamp'] is not None:
                result['errors'].append('Duplicate timestamp line')
            else:
                try:
                    result['timestamp'] = int(line.split(':', 1)[1].strip(), 10)
                except ValueError:
                    result['errors'].append('Invalid timestamp value')
            continue
        if line.startswith('target-soc:'):
            if result['target_soc'] is not None:
                result['errors'].append('Duplicate target-soc line')
            else:
                result['target_soc'] = line.split(':', 1)[1].strip()
            continue
        if line.startswith('rsa2048:'):
            if result['rsa2048_hex'] is not None:
                result['errors'].append('Duplicate rsa2048 line')
            else:
                value = re.sub(r'\s+', '', line.split(':', 1)[1])
                if not re.fullmatch(r'[0-9a-fA-F]{512}', value):
                    result['errors'].append('rsa2048 must contain exactly 256 bytes in hexadecimal')
                else:
                    result['rsa2048_hex'] = value.lower()
            continue
        result['unknown_lines'].append(line)
    if result['digest'] is None:
        result['errors'].append('Missing SHA-256 digest line')
    result['status'] = 'PARSED' if not result['errors'] else 'MALFORMED'
    return result


SIGNATURE_PADDING_BYTES = b'\x00\xff \t\r\n'


def classify_rpi_signature_blob(data: bytes, source: str = '') -> Tuple[Dict[str, Any], Optional[str]]:
    """Classify a Raspberry Pi digest/signature blob before parsing it.

    EEPROM file sections may exist even when their content is erased, zero-filled,
    padded, or contains only an unsigned digest. Those states are evidence gaps,
    not malformed-signature failures.
    """
    raw_size = len(data)
    effective = data.strip(SIGNATURE_PADDING_BYTES)
    trimmed_size = len(effective)
    non_whitespace = bytes(byte for byte in data if byte not in b' \t\r\n')
    byte_values = set(non_whitespace)

    summary: Dict[str, Any] = {
        'source': source,
        'section_present': True,
        'raw_size': raw_size,
        'trimmed_size': trimmed_size,
        'raw_sha256': hashlib.sha256(data).hexdigest(),
        'effective_sha256': hashlib.sha256(effective).hexdigest() if effective else None,
        'content_class': 'UNKNOWN',
        'effective_signature_present': False,
        'signature_intent_present': False,
        'ascii_decodable': None,
    }

    if raw_size == 0:
        summary['content_class'] = 'EMPTY_SECTION'
        summary['ascii_decodable'] = True
        return summary, ''
    if not effective:
        summary['ascii_decodable'] = True
        if byte_values and byte_values <= {0xFF}:
            summary['content_class'] = 'ERASED_PLACEHOLDER'
        elif byte_values and byte_values <= {0x00}:
            summary['content_class'] = 'ZERO_FILLED_PLACEHOLDER'
        elif byte_values and byte_values <= {0x00, 0xFF}:
            summary['content_class'] = 'ERASED_OR_ZERO_PLACEHOLDER'
        else:
            summary['content_class'] = 'WHITESPACE_PLACEHOLDER'
        return summary, ''

    try:
        text = effective.decode('ascii', errors='strict')
        summary['ascii_decodable'] = True
    except UnicodeDecodeError as exc:
        summary['ascii_decodable'] = False
        summary['content_class'] = 'NON_TEXT_BINARY'
        summary['signature_intent_present'] = True
        summary['decode_error'] = str(exc)
        return summary, None

    parsed = parse_rpi_signature_text(text, source)
    has_digest = parsed.get('digest') is not None
    has_rsa_label = bool(re.search(r'(?mi)^\s*rsa2048\s*:', text))
    has_valid_rsa = parsed.get('rsa2048_hex') is not None
    has_metadata_label = bool(re.search(r'(?mi)^\s*(?:ts|target-soc)\s*:', text))
    summary.update({
        'digest_present': has_digest,
        'rsa_label_present': has_rsa_label,
        'valid_rsa_payload_present': has_valid_rsa,
        'signature_intent_present': bool(has_digest or has_rsa_label or has_metadata_label),
        'parse_errors': list(parsed.get('errors', [])),
        'unknown_line_count': len(parsed.get('unknown_lines', [])),
    })

    if has_digest and not has_rsa_label:
        summary['content_class'] = 'DIGEST_ONLY'
        return summary, text
    if has_valid_rsa and not parsed.get('errors'):
        summary['content_class'] = 'SIGNED_TEXT'
        summary['effective_signature_present'] = True
        return summary, text
    if has_rsa_label or has_digest or has_metadata_label:
        summary['content_class'] = 'MALFORMED_SIGNATURE_TEXT'
        summary['effective_signature_present'] = has_rsa_label
        return summary, text

    summary['content_class'] = 'UNRECOGNIZED_TEXT'
    summary['signature_intent_present'] = True
    return summary, text


def validate_rpi_signed_file(
    image_path: Path,
    signature_path: Path,
    key: Optional[RSAPublicKeyMaterial],
    expected_soc: Optional[str] = None,
    max_age_days: Optional[int] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'image_path': str(image_path),
        'signature_path': str(signature_path),
        'image_present': image_path.is_file(),
        'signature_present': signature_path.is_file(),
        'effective_signature_present': False,
        'format_status': 'NOT_AVAILABLE',
        'digest_status': 'NOT_VERIFIED',
        'rsa_signature_status': 'NOT_VERIFIED',
        'target_soc_status': 'NOT_ASSESSED',
        'freshness_status': 'NOT_ASSESSED',
        'timestamp': None,
        'age_days': None,
        'max_age_days': max_age_days,
        'overall': VALIDATION_UNVERIFIED,
        'reason_code': REASON_ARTIFACT_NOT_FOUND,
        'reason_codes': [REASON_ARTIFACT_NOT_FOUND],
        'cryptographic_verification_performed': False,
        'errors': [],
    }
    image_present = image_path.is_file()
    signature_present = signature_path.is_file()
    if not image_present or not signature_present:
        if image_present and not signature_present:
            reason = REASON_SIGNATURE_NOT_PRESENT
        else:
            reason = REASON_ARTIFACT_NOT_FOUND
        result['reason_code'] = reason
        result['reason_codes'] = [reason]
        return result

    try:
        signature_bytes = signature_path.read_bytes()
    except OSError as exc:
        result['errors'].append(str(exc))
        result['reason_code'] = REASON_IO_ERROR
        result['reason_codes'] = [REASON_IO_ERROR]
        return result

    signature_content, signature_text = classify_rpi_signature_blob(
        signature_bytes, str(signature_path)
    )
    result['signature_content'] = signature_content
    result['effective_signature_present'] = bool(
        signature_content.get('effective_signature_present')
    )
    content_class = signature_content.get('content_class')

    placeholder_classes = {
        'EMPTY_SECTION', 'ERASED_PLACEHOLDER', 'ZERO_FILLED_PLACEHOLDER',
        'ERASED_OR_ZERO_PLACEHOLDER', 'WHITESPACE_PLACEHOLDER',
    }
    if content_class in placeholder_classes:
        result['format_status'] = 'NOT_PRESENT'
        result['rsa_signature_status'] = 'MISSING'
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_SIGNATURE_NOT_PRESENT
        result['reason_codes'] = [REASON_SIGNATURE_NOT_PRESENT]
        return result

    if content_class in {'NON_TEXT_BINARY', 'MALFORMED_SIGNATURE_TEXT', 'UNRECOGNIZED_TEXT'}:
        result['format_status'] = 'MALFORMED'
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        result['errors'].extend(signature_content.get('parse_errors', []))
        if signature_content.get('decode_error'):
            result['errors'].append(signature_content['decode_error'])
        if not result['errors']:
            result['errors'].append(f'Unrecognised signature content class: {content_class}')
        return result

    try:
        digest = hashlib.sha256()
        image_size = 0
        with image_path.open('rb') as image_handle:
            for block in iter(lambda: image_handle.read(1024 * 1024), b''):
                digest.update(block)
                image_size += len(block)
        actual_digest_bytes = digest.digest()
        result['image_size'] = image_size
    except OSError as exc:
        result['errors'].append(str(exc))
        result['reason_code'] = REASON_IO_ERROR
        result['reason_codes'] = [REASON_IO_ERROR]
        return result

    parsed = parse_rpi_signature_text(signature_text or '', str(signature_path))
    result['parsed'] = parsed
    result['format_status'] = parsed['status']
    if parsed['errors']:
        result['errors'].extend(parsed['errors'])
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        return result

    actual_digest = actual_digest_bytes.hex()
    result['image_sha256'] = actual_digest
    result['declared_sha256'] = parsed['digest']
    result['digest_status'] = 'MATCH' if actual_digest == parsed['digest'] else 'MISMATCH'

    target_soc = parsed.get('target_soc')
    if target_soc is None:
        result['target_soc_status'] = 'UNSPECIFIED'
    elif expected_soc and target_soc == expected_soc:
        result['target_soc_status'] = 'MATCH'
    elif expected_soc:
        result['target_soc_status'] = 'MISMATCH'
    else:
        result['target_soc_status'] = 'PRESENT_NOT_COMPARED'

    timestamp = parsed.get('timestamp')
    result['timestamp'] = timestamp
    freshness_failed = False
    if timestamp is None:
        result['freshness_status'] = 'TIMESTAMP_MISSING'
    else:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        age_seconds = now_ts - timestamp
        result['age_days'] = round(age_seconds / 86400.0, 3)
        if timestamp > now_ts + 300:
            result['freshness_status'] = 'FUTURE_TIMESTAMP'
            freshness_failed = True
        elif max_age_days is not None and age_seconds > max_age_days * 86400:
            result['freshness_status'] = 'STALE'
            freshness_failed = True
        elif max_age_days is not None:
            result['freshness_status'] = 'WITHIN_POLICY'
        else:
            result['freshness_status'] = 'TIMESTAMP_VALID_NO_MAX_AGE_POLICY'

    signature_hex = parsed.get('rsa2048_hex')
    if signature_hex is None:
        result['rsa_signature_status'] = 'MISSING'
    elif key is None:
        result['rsa_signature_status'] = 'KEY_UNAVAILABLE'
    else:
        signature = bytes.fromhex(signature_hex)
        result['cryptographic_verification_performed'] = True
        result['rsa_signature_status'] = (
            'VERIFIED' if rsa_pkcs1_v15_sha256_verify_digest(actual_digest_bytes, signature, key) else 'INVALID'
        )
        result['verification_key'] = key.summary()

    invalid_reasons: List[str] = []
    if result['digest_status'] == 'MISMATCH':
        invalid_reasons.append(REASON_CRYPTOGRAPHIC_MISMATCH)
    if result['rsa_signature_status'] == 'INVALID':
        invalid_reasons.append(REASON_CRYPTOGRAPHIC_MISMATCH)
    if result['target_soc_status'] == 'MISMATCH':
        invalid_reasons.append(REASON_TARGET_SOC_MISMATCH)
    if freshness_failed:
        invalid_reasons.append(REASON_FRESHNESS_POLICY_FAILURE)
    invalid_reasons = list(dict.fromkeys(invalid_reasons))

    if invalid_reasons:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = invalid_reasons[0]
        result['reason_codes'] = invalid_reasons
    elif signature_hex is None:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_SIGNATURE_NOT_PRESENT
        result['reason_codes'] = [REASON_SIGNATURE_NOT_PRESENT]
    elif key is None:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_KEY_UNAVAILABLE
        result['reason_codes'] = [REASON_KEY_UNAVAILABLE]
    elif result['digest_status'] == 'MATCH' and result['rsa_signature_status'] == 'VERIFIED':
        result['overall'] = VALIDATION_VALID
        result['reason_code'] = REASON_NONE
        result['reason_codes'] = []
    else:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_CRYPTOGRAPHIC_MISMATCH
        result['reason_codes'] = [REASON_CRYPTOGRAPHIC_MISMATCH]
    return result


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


class RaspberryPiEEPROMImage:
    """Read-only parser for the section format used by rpi-eeprom-config."""

    def __init__(self, path: str):
        self.path = str(Path(path).expanduser().resolve())
        self.data = Path(self.path).read_bytes()
        self.sections: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self._parse()

    def _parse(self) -> None:
        offset = 0
        max_sections = 4096
        while offset + 8 <= len(self.data) and len(self.sections) < max_sections:
            magic, length = struct.unpack_from('>II', self.data, offset)
            if magic in {0, 0xFFFFFFFF}:
                break
            if (magic & RPI_EEPROM_MAGIC_MASK) != RPI_EEPROM_MAGIC:
                self.errors.append(f'Invalid section magic 0x{magic:08x} at 0x{offset:x}')
                break
            section_end = offset + 8 + length
            if length < 0 or section_end > len(self.data):
                self.errors.append(f'Section at 0x{offset:x} exceeds EEPROM image')
                break
            filename = ''
            content_offset = offset + 8
            content_length = length
            if magic == RPI_EEPROM_FILE_MAGIC:
                if length < 16 or offset + 24 > len(self.data):
                    self.errors.append(f'Truncated file section at 0x{offset:x}')
                    break
                filename = self.data[offset + 8:offset + 20].decode('ascii', errors='replace').rstrip('\x00')
                content_offset = offset + 24
                content_length = length - 16
            self.sections.append({
                'magic': f'0x{magic:08x}',
                'offset': offset,
                'section_length': length,
                'filename': filename,
                'content_offset': content_offset,
                'content_length': content_length,
                'sha256': hashlib.sha256(
                    self.data[content_offset:content_offset + content_length]
                ).hexdigest(),
            })
            offset = (section_end + 7) & ~7
        if len(self.sections) >= max_sections:
            self.errors.append('Section-count safety limit reached')

    def get_all(self, filename: str) -> List[bytes]:
        return [
            self.data[item['content_offset']:item['content_offset'] + item['content_length']]
            for item in self.sections if item.get('filename') == filename
        ]

    def get_first(self, filename: str) -> Optional[bytes]:
        values = self.get_all(filename)
        return values[0] if values else None

    def summary(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'size': len(self.data),
            'sha256': hashlib.sha256(self.data).hexdigest(),
            'sections': self.sections,
            'errors': self.errors,
        }


def _normalise_sha256(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', value).lower()
    return cleaned if len(cleaned) == 64 else None


def _otp_hash_candidates(decoded: Dict[str, Any], metadata_bundle: Dict[str, Any]) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []
    metadata_hash = _normalise_sha256(metadata_bundle.get('metadata', {}).get('CUSTOMER_KEY_HASH'))
    if metadata_hash:
        candidates.append({'value': metadata_hash, 'encoding': 'RPIBOOT_METADATA', 'source': 'rpiboot -j'})
    decoded_hash = _normalise_sha256(
        decoded.get('security', {}).get('customer_key_hash', {}).get('value')
    )
    if decoded_hash:
        raw = bytes.fromhex(decoded_hash)
        variants = {
            'OTP_DECODED_DIRECT': raw.hex(),
            'OTP_DECODED_REVERSE_ALL': raw[::-1].hex(),
            'OTP_DECODED_REVERSE_BYTES_PER_WORD': b''.join(
                raw[index:index + 4][::-1] for index in range(0, 32, 4)
            ).hex(),
            'OTP_DECODED_REVERSE_WORD_ORDER': b''.join(
                raw[index:index + 4] for index in range(28, -1, -4)
            ).hex(),
        }
        for encoding, value in variants.items():
            if not any(item['value'] == value for item in candidates):
                candidates.append({'value': value, 'encoding': encoding, 'source': 'decoded OTP'})
    return candidates


def verify_bcm2712_customer_signed_blob(
    blob: bytes,
    expected_key: Optional[RSAPublicKeyMaterial],
    source: str,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'source': source,
        'format': 'RPI_SIGN_BOOTCODE_2712_CUSTOMER_TRAILER_V1',
        'overall': VALIDATION_UNVERIFIED,
        'reason_code': REASON_SIGNATURE_NOT_PRESENT,
        'reason_codes': [REASON_SIGNATURE_NOT_PRESENT],
        'signature_status': 'NOT_VERIFIED',
        'public_key_status': 'NOT_VERIFIED',
        'key_number': None,
        'private_version': None,
        'declared_input_length': None,
        'actual_input_length': None,
        'length_status': 'NOT_VERIFIED',
        'cryptographic_verification_performed': False,
        'errors': [],
    }
    trailer_size = 12 + RSA2048_SIGNATURE_SIZE + RPI_PUBLIC_KEY_BIN_SIZE
    if len(blob) < trailer_size:
        result['errors'].append('bootsys does not contain a complete BCM2712 customer-signing trailer')
        return result

    signature_start = len(blob) - (RSA2048_SIGNATURE_SIZE + RPI_PUBLIC_KEY_BIN_SIZE)
    metadata_start = signature_start - 12
    signed_prefix = blob[:signature_start]
    input_blob = blob[:metadata_start]
    declared_length, key_number, private_version = struct.unpack_from('<III', blob, metadata_start)
    signature = blob[signature_start:signature_start + RSA2048_SIGNATURE_SIZE]
    pubkey_bytes = blob[-RPI_PUBLIC_KEY_BIN_SIZE:]
    result.update({
        'declared_input_length': declared_length,
        'actual_input_length': len(input_blob),
        'key_number': key_number,
        'private_version': private_version,
        'signed_prefix_sha256': hashlib.sha256(signed_prefix).hexdigest(),
        'input_sha256': hashlib.sha256(input_blob).hexdigest(),
        'signature_sha256': hashlib.sha256(signature).hexdigest(),
        'embedded_pubkey_sha256': hashlib.sha256(pubkey_bytes).hexdigest(),
    })

    # The trailer has no magic. A key number other than 16 is treated conservatively
    # as absence of a customer trailer rather than proof of an invalid signature.
    if key_number != 16:
        result['errors'].append(f'No recognised customer trailer: key number is {key_number}, expected 16')
        return result

    result['length_status'] = 'MATCH' if declared_length == len(input_blob) else 'MISMATCH'
    if result['length_status'] == 'MISMATCH' or private_version > 32:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        if result['length_status'] == 'MISMATCH':
            result['errors'].append('Embedded input-length field does not match parsed input length')
        if private_version > 32:
            result['errors'].append(f'Private version outside documented range: {private_version}')
        return result

    try:
        trailer_key = parse_rpi_pubkey_bin(pubkey_bytes, f'{source}:customer-trailer')
        result['trailer_key'] = trailer_key.summary()
    except SecureBootFormatError as exc:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_FORMAT_INVALID
        result['reason_codes'] = [REASON_FORMAT_INVALID]
        result['errors'].append(str(exc))
        return result

    if expected_key is None:
        result['public_key_status'] = 'KEY_UNAVAILABLE'
        verification_key = trailer_key
    elif trailer_key.to_pubkey_bin() == expected_key.to_pubkey_bin():
        result['public_key_status'] = 'MATCH'
        verification_key = expected_key
    else:
        result['public_key_status'] = 'MISMATCH'
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_KEY_MISMATCH
        result['reason_codes'] = [REASON_KEY_MISMATCH]
        return result

    result['cryptographic_verification_performed'] = True
    signature_valid = rsa_pkcs1_v15_sha256_verify(signed_prefix, signature, verification_key)
    result['signature_status'] = 'VERIFIED' if signature_valid else 'INVALID'
    if not signature_valid:
        result['overall'] = VALIDATION_INVALID
        result['reason_code'] = REASON_CRYPTOGRAPHIC_MISMATCH
        result['reason_codes'] = [REASON_CRYPTOGRAPHIC_MISMATCH]
    elif expected_key is None:
        result['overall'] = VALIDATION_UNVERIFIED
        result['reason_code'] = REASON_KEY_UNAVAILABLE
        result['reason_codes'] = [REASON_KEY_UNAVAILABLE]
        result['signature_status'] = 'VERIFIED_EMBEDDED_KEY_UNBOUND'
    else:
        result['overall'] = VALIDATION_VALID
        result['reason_code'] = REASON_NONE
        result['reason_codes'] = []
    return result


def validate_secure_boot_chain(
    platform_name: str,
    boot_root: Path,
    spi_image_path: Optional[str],
    public_key_path: Optional[str],
    decoded: Dict[str, Any],
    metadata_bundle: Dict[str, Any],
    max_signature_age_days: Optional[int] = None,
    supplied_key_material: Optional[RSAPublicKeyMaterial] = None,
) -> Dict[str, Any]:
    soc = get_soc_generation(platform_name)
    result: Dict[str, Any] = {
        'schema': SECURE_BOOT_VALIDATION_SCHEMA,
        'tool_version': TOOL_VERSION,
        'platform': platform_name,
        'soc': soc,
        'public_key': {
            'supplied_path': str(Path(public_key_path).expanduser().resolve()) if public_key_path else None,
            'supplied_status': 'NOT_SUPPLIED',
            'eeprom_status': 'NOT_AVAILABLE',
            'source_relationship': 'UNAVAILABLE',
            'otp_binding': 'UNVERIFIED',
            'otp_binding_reason_code': REASON_OTP_BINDING_UNAVAILABLE,
            'otp_hash_candidates': [],
        },
        'eeprom': {'status': 'NOT_AVAILABLE'},
        'bootconf_signature': {
            'overall': VALIDATION_UNVERIFIED, 'reason_code': REASON_ARTIFACT_NOT_FOUND,
            'reason_codes': [REASON_ARTIFACT_NOT_FOUND],
        },
        'boot_image_signature': {
            'overall': VALIDATION_UNVERIFIED, 'reason_code': REASON_ARTIFACT_NOT_FOUND,
            'reason_codes': [REASON_ARTIFACT_NOT_FOUND],
        },
        'bootsys_customer_countersignature': (
            {'overall': 'NOT_APPLICABLE', 'reason_code': REASON_NONE, 'reason_codes': []}
            if soc != 'BCM2712' else
            {'overall': VALIDATION_UNVERIFIED, 'reason_code': REASON_ARTIFACT_NOT_FOUND,
             'reason_codes': [REASON_ARTIFACT_NOT_FOUND]}
        ),
        'vendor_bootrom_signature': {
            'status': 'BOOTROM_ENFORCED_NOT_INDEPENDENTLY_REPLAYED',
            'note': 'GGFW validates the customer chain; Raspberry Pi vendor-root signatures are enforced by BootROM but vendor public keys are not replay-verified here.',
        },
        'authenticity': 'UNVERIFIED',
        'completeness': 'INCOMPLETE',
        'freshness': 'NOT_ASSESSED',
        'overall': 'UNVERIFIED',
        'coverage_gap': True,
        'errors': [],
        'references': OFFICIAL_OTP_REFERENCES,
    }

    supplied_key: Optional[RSAPublicKeyMaterial] = supplied_key_material
    if supplied_key is not None:
        result['public_key']['supplied_status'] = 'PARSED'
        result['public_key']['supplied'] = supplied_key.summary()
    elif public_key_path:
        try:
            supplied_key = parse_pem_rsa_public_key(public_key_path)
            result['public_key']['supplied_status'] = 'PARSED'
            result['public_key']['supplied'] = supplied_key.summary()
        except (OSError, SecureBootFormatError) as exc:
            # CLI preflight prevents this path for explicit inputs. Direct callers receive
            # an UNVERIFIED result rather than a false signature failure.
            result['public_key']['supplied_status'] = 'INVALID_INPUT'
            result['public_key']['error'] = str(exc)
            result['errors'].append(f'Public key input: {exc}')

    eeprom_key: Optional[RSAPublicKeyMaterial] = None
    image: Optional[RaspberryPiEEPROMImage] = None
    if spi_image_path and Path(spi_image_path).is_file():
        try:
            image = RaspberryPiEEPROMImage(spi_image_path)
            result['eeprom'] = image.summary()
            result['eeprom']['status'] = 'PARSED' if not image.errors else 'PARTIAL'
            pubkey_blobs = image.get_all('pubkey.bin')
            result['eeprom']['pubkey_count'] = len(pubkey_blobs)
            if pubkey_blobs:
                parsed_keys: List[RSAPublicKeyMaterial] = []
                key_entries: List[Dict[str, Any]] = []
                for index, pubkey_bytes in enumerate(pubkey_blobs):
                    parsed_key = parse_rpi_pubkey_bin(pubkey_bytes, f'{spi_image_path}:pubkey.bin[{index}]')
                    parsed_keys.append(parsed_key)
                    key_entries.append({
                        'index': index,
                        'sha256': hashlib.sha256(pubkey_bytes).hexdigest(),
                        'key': parsed_key.summary(),
                    })
                result['eeprom']['pubkey_entries'] = key_entries
                canonical = parsed_keys[0].to_pubkey_bin()
                if all(key.to_pubkey_bin() == canonical for key in parsed_keys[1:]):
                    eeprom_key = parsed_keys[0]
                    result['eeprom']['pubkey_bin_hex'] = canonical.hex()
                    result['public_key']['eeprom_status'] = 'PARSED'
                    result['public_key']['eeprom_consistency'] = 'CONSISTENT'
                    result['public_key']['eeprom'] = eeprom_key.summary()
                else:
                    result['public_key']['eeprom_status'] = 'INCONSISTENT'
                    result['public_key']['eeprom_consistency'] = 'MISMATCH'
                    result['errors'].append('Multiple EEPROM pubkey.bin entries are not identical')
            else:
                result['public_key']['eeprom_status'] = 'ABSENT'
                result['public_key']['eeprom_consistency'] = 'NOT_AVAILABLE'
        except (OSError, SecureBootFormatError, struct.error) as exc:
            result['eeprom'] = {'status': 'FAILED', 'path': spi_image_path, 'error': str(exc)}
            result['errors'].append(f'EEPROM parse: {exc}')

    selected_key: Optional[RSAPublicKeyMaterial] = None
    if result['public_key'].get('eeprom_status') == 'INCONSISTENT':
        result['public_key']['source_relationship'] = 'EEPROM_KEYS_INCONSISTENT'
        selected_key = supplied_key
    elif supplied_key and eeprom_key:
        if supplied_key.to_pubkey_bin() == eeprom_key.to_pubkey_bin():
            result['public_key']['source_relationship'] = 'SUPPLIED_MATCHES_EEPROM'
            selected_key = supplied_key
        else:
            result['public_key']['source_relationship'] = 'SUPPLIED_MISMATCHES_EEPROM'
            selected_key = supplied_key
    elif supplied_key:
        result['public_key']['source_relationship'] = 'SUPPLIED_ONLY'
        selected_key = supplied_key
    elif eeprom_key:
        result['public_key']['source_relationship'] = 'EEPROM_ONLY'
        selected_key = eeprom_key

    candidates = _otp_hash_candidates(decoded, metadata_bundle)
    result['public_key']['otp_hash_candidates'] = candidates
    if selected_key and candidates:
        fingerprint = selected_key.fingerprint()
        result['public_key']['computed_pubkey_bin_sha256'] = fingerprint
        matches = [candidate for candidate in candidates if candidate['value'] == fingerprint]
        if matches:
            result['public_key']['otp_binding'] = 'MATCH'
            result['public_key']['otp_binding_reason_code'] = REASON_NONE
            result['public_key']['otp_binding_matches'] = matches
        else:
            result['public_key']['otp_binding'] = 'MISMATCH'
            result['public_key']['otp_binding_reason_code'] = REASON_KEY_MISMATCH
    elif selected_key:
        result['public_key']['otp_binding'] = 'HASH_UNAVAILABLE'
        result['public_key']['otp_binding_reason_code'] = REASON_OTP_BINDING_UNAVAILABLE
    elif candidates:
        result['public_key']['otp_binding'] = 'PUBLIC_KEY_UNAVAILABLE'
        result['public_key']['otp_binding_reason_code'] = REASON_KEY_UNAVAILABLE
    else:
        result['public_key']['otp_binding'] = 'UNVERIFIED'
        result['public_key']['otp_binding_reason_code'] = REASON_OTP_BINDING_UNAVAILABLE

    expected_soc = '2712' if soc == 'BCM2712' else ('2711' if soc == 'BCM2711' else None)
    result['boot_image_signature'] = validate_rpi_signed_file(
        boot_root / 'boot.img', boot_root / 'boot.sig', selected_key,
        expected_soc=expected_soc, max_age_days=max_signature_age_days,
    )

    if image is not None:
        bootconfs = image.get_all('bootconf.txt')
        bootconf_sigs = image.get_all('bootconf.sig')
        if bootconfs and len(bootconfs) == len(bootconf_sigs):
            entries: List[Dict[str, Any]] = []
            with tempfile.TemporaryDirectory(prefix='ggfw-sb-') as tmp:
                tmp_path = Path(tmp)
                for index, (bootconf, bootconf_sig) in enumerate(zip(bootconfs, bootconf_sigs)):
                    conf_path = tmp_path / f'bootconf-{index}.txt'
                    sig_path = tmp_path / f'bootconf-{index}.sig'
                    conf_path.write_bytes(bootconf)
                    sig_path.write_bytes(bootconf_sig)
                    entry = validate_rpi_signed_file(
                        conf_path, sig_path, selected_key, expected_soc=None, max_age_days=None,
                    )
                    entry['index'] = index
                    entry['source'] = f'{spi_image_path}:bootconf[{index}]'
                    entry['bootconf_sha256'] = hashlib.sha256(bootconf).hexdigest()
                    entry['signature_file_sha256'] = hashlib.sha256(bootconf_sig).hexdigest()
                    entries.append(entry)
            statuses = {entry.get('overall') for entry in entries}
            if statuses == {VALIDATION_VALID}:
                overall = VALIDATION_VALID
                reason_code = REASON_NONE
            elif VALIDATION_INVALID in statuses:
                overall = VALIDATION_INVALID
                invalid_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_INVALID)
                reason_code = invalid_entry.get('reason_code', REASON_CRYPTOGRAPHIC_MISMATCH)
            else:
                overall = VALIDATION_UNVERIFIED
                unverified_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_UNVERIFIED)
                reason_code = unverified_entry.get('reason_code', REASON_KEY_UNAVAILABLE)
            result['bootconf_signature'] = {
                'overall': overall,
                'reason_code': reason_code,
                'reason_codes': list(dict.fromkeys(
                    code for entry in entries for code in entry.get('reason_codes', [])
                )),
                'entry_count': len(entries),
                'section_present_count': len(entries),
                'effective_signature_present_count': sum(
                    bool(entry.get('effective_signature_present')) for entry in entries
                ),
                'content_classes': [
                    entry.get('signature_content', {}).get('content_class', 'UNKNOWN')
                    for entry in entries
                ],
                'entries': entries,
            }
        elif bootconfs or bootconf_sigs:
            reason = REASON_SIGNATURE_NOT_PRESENT if len(bootconfs) > len(bootconf_sigs) else REASON_ARTIFACT_NOT_FOUND
            result['bootconf_signature'] = {
                'overall': VALIDATION_UNVERIFIED,
                'reason_code': reason,
                'reason_codes': [reason],
                'bootconf_count': len(bootconfs),
                'bootconf_sig_count': len(bootconf_sigs),
                'section_present_count': len(bootconf_sigs),
                'effective_signature_present_count': 0,
                'content_classes': [],
                'error': 'The number of bootconf.txt and bootconf.sig entries differs',
            }

        if soc == 'BCM2712':
            bootsys_blobs = image.get_all('bootsys')
            if bootsys_blobs:
                entries = [
                    verify_bcm2712_customer_signed_blob(blob, selected_key, f'{spi_image_path}:bootsys[{index}]')
                    for index, blob in enumerate(bootsys_blobs)
                ]
                statuses = {entry.get('overall') for entry in entries}
                if statuses == {VALIDATION_VALID}:
                    overall = VALIDATION_VALID
                    reason_code = REASON_NONE
                elif VALIDATION_INVALID in statuses:
                    overall = VALIDATION_INVALID
                    invalid_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_INVALID)
                    reason_code = invalid_entry.get('reason_code', REASON_CRYPTOGRAPHIC_MISMATCH)
                else:
                    overall = VALIDATION_UNVERIFIED
                    unverified_entry = next(entry for entry in entries if entry.get('overall') == VALIDATION_UNVERIFIED)
                    reason_code = unverified_entry.get('reason_code', REASON_KEY_UNAVAILABLE)
                result['bootsys_customer_countersignature'] = {
                    'overall': overall,
                    'reason_code': reason_code,
                    'reason_codes': list(dict.fromkeys(
                        code for entry in entries for code in entry.get('reason_codes', [])
                    )),
                    'entries': entries,
                }

    enable_status = decoded.get('security', {}).get('secure_boot_enablement', {}).get('status', 'UNKNOWN')
    components = {
        'secure_boot_enablement': enable_status,
        'key_relationship': result['public_key']['source_relationship'],
        'otp_binding': result['public_key']['otp_binding'],
        'bootconf': result['bootconf_signature'].get('overall'),
        'boot_image': result['boot_image_signature'].get('overall'),
        'bootsys': result['bootsys_customer_countersignature'].get('overall'),
    }
    result['components'] = components
    failure_values = {
        'SUPPLIED_MISMATCHES_EEPROM', 'EEPROM_KEYS_INCONSISTENT', 'MISMATCH', VALIDATION_INVALID,
        'DISABLED', 'UNPROGRAMMED',
    }
    confirmed_failure = any(value in failure_values for value in components.values())
    bootsys_ok = (
        components['bootsys'] == VALIDATION_VALID if soc == 'BCM2712'
        else components['bootsys'] == 'NOT_APPLICABLE'
    )
    freshness = result['boot_image_signature'].get('freshness_status', 'NOT_ASSESSED')
    freshness_conclusive = freshness in {'WITHIN_POLICY', 'TIMESTAMP_VALID_NO_MAX_AGE_POLICY'}
    full_customer_chain = (
        components['secure_boot_enablement'] in {'ENABLED', 'PROVISIONED'}
        and components['otp_binding'] == 'MATCH'
        and components['bootconf'] == VALIDATION_VALID
        and components['boot_image'] == VALIDATION_VALID
        and bootsys_ok
        and components['key_relationship'] != 'SUPPLIED_MISMATCHES_EEPROM'
        and freshness_conclusive
    )

    result['freshness'] = freshness
    if confirmed_failure:
        result['authenticity'] = 'FAILED'
        result['overall'] = 'FAIL'
        result['coverage_gap'] = False
    elif full_customer_chain:
        result['authenticity'] = 'VERIFIED_CUSTOMER_CHAIN'
        result['completeness'] = 'SIGNED_CHAIN_COMPLETE'
        result['overall'] = 'PASS'
        result['coverage_gap'] = False
    else:
        verified = sum(value == VALIDATION_VALID for value in components.values())
        result['authenticity'] = 'PARTIALLY_VERIFIED' if verified else 'UNVERIFIED'
        result['completeness'] = 'PARTIAL' if verified else 'INCOMPLETE'
        result['overall'] = 'UNVERIFIED'
        result['coverage_gap'] = True
    result['component_reason_codes'] = {
        'public_key': result['public_key'].get('otp_binding_reason_code'),
        'bootconf': result['bootconf_signature'].get('reason_code'),
        'boot_image': result['boot_image_signature'].get('reason_code'),
        'bootsys': result['bootsys_customer_countersignature'].get('reason_code'),
    }
    return result


def build_secure_boot_evidence(
    platform_name: str, boot_root: Path, decoded: Dict[str, Any], metadata_bundle: Dict[str, Any],
    policy_profile: str, chain_validation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    security = decoded.get("security", {})
    key = security.get("customer_key_hash", {})
    enable = security.get("secure_boot_enablement", {})
    jtag = security.get("vc_jtag_lock", {})
    boot_img_present = (boot_root / "boot.img").is_file()
    boot_sig_present = (boot_root / "boot.sig").is_file()
    key_status = key.get("status", "UNKNOWN")
    enable_status = enable.get("status", "UNKNOWN")
    validation = chain_validation or {
        'schema': SECURE_BOOT_VALIDATION_SCHEMA,
        'overall': 'UNVERIFIED',
        'authenticity': 'UNVERIFIED',
        'completeness': 'INCOMPLETE',
        'freshness': 'NOT_ASSESSED',
        'coverage_gap': True,
        'boot_image_signature': {'overall': 'NOT_VERIFIED'},
        'bootconf_signature': {'overall': 'NOT_VERIFIED'},
        'bootsys_customer_countersignature': {'overall': 'NOT_VERIFIED'},
        'public_key': {'otp_binding': 'UNVERIFIED', 'source_relationship': 'UNAVAILABLE'},
    }

    if boot_img_present and boot_sig_present:
        pair_status = "PRESENT"
    elif boot_img_present or boot_sig_present:
        pair_status = "INCONSISTENT"
    else:
        pair_status = "ABSENT"

    explicitly_not_enforced = enable_status in {"DISABLED", "UNPROGRAMMED"} or key_status == "UNPROGRAMMED"
    validation_overall = validation.get('overall', 'UNVERIFIED')
    if explicitly_not_enforced:
        overall = "DISABLED"
        authenticity = "NOT_ENFORCED"
        coverage_gap = False
    elif pair_status == "INCONSISTENT":
        overall = "INCONSISTENT"
        authenticity = "FAILED"
        coverage_gap = False
    elif validation_overall == 'PASS':
        overall = 'PASS'
        authenticity = validation.get('authenticity', 'VERIFIED_CUSTOMER_CHAIN')
        coverage_gap = False
    elif validation_overall == 'FAIL':
        overall = 'FAIL'
        authenticity = 'FAILED'
        coverage_gap = False
    else:
        overall = "EVIDENCE_INCOMPLETE"
        authenticity = validation.get('authenticity', 'UNVERIFIED')
        coverage_gap = True

    completeness = validation.get('completeness')
    if not completeness or completeness == 'INCOMPLETE':
        completeness = "SIGNED_BUNDLE_PRESENT" if pair_status == "PRESENT" else (
            'SIGNED_BUNDLE_INCONSISTENT' if pair_status == 'INCONSISTENT' else 'SIGNED_BUNDLE_ABSENT'
        )
    freshness = validation.get('freshness', 'NOT_ASSESSED')

    if policy_profile == "secure-boot-required":
        if overall == 'PASS':
            policy = 'PASS'
        elif overall in {'DISABLED', 'INCONSISTENT', 'FAIL'} or pair_status == 'ABSENT':
            policy = 'FAIL'
        else:
            policy = 'UNVERIFIED'
    elif policy_profile == "hardened":
        policy = "PASS" if overall == 'PASS' else "REVIEW"
    else:
        policy = "NOT_REQUIRED"

    return {
        "schema": SECURE_BOOT_EVIDENCE_SCHEMA,
        "platform": platform_name,
        "soc": decoded.get("soc"),
        "decoder_profile": decoded.get("decoder_profile"),
        "decoder_status": decoded.get("decoder_status"),
        "policy_profile": policy_profile,
        "overall": overall,
        "coverage_gap": coverage_gap,
        "authenticity": authenticity,
        "completeness": completeness,
        "freshness": freshness,
        "policy": policy,
        "evidence": {
            "otp_acquisition": "SUCCESS" if decoded.get("raw_word_count", 0) else "FAILED",
            "otp_words_collected": decoded.get("raw_word_count", 0),
            "customer_key_hash": key,
            "secure_boot_enablement": enable,
            "vc_jtag_lock": jtag,
            "boot_img": {"status": "PRESENT" if boot_img_present else "ABSENT", "path": str(boot_root / "boot.img")},
            "boot_sig": {"status": "PRESENT" if boot_sig_present else "ABSENT", "path": str(boot_root / "boot.sig")},
            "eeprom_customer_public_key": validation.get('public_key', {}),
            "bootconf_signature": validation.get('bootconf_signature', {}),
            "bootsys_customer_countersignature": validation.get('bootsys_customer_countersignature', {}),
            "boot_img_signature": validation.get('boot_image_signature', {}),
            "vendor_bootrom_signature": validation.get('vendor_bootrom_signature', {}),
            "rpiboot_metadata": {
                "loaded": bool(metadata_bundle.get("loaded")),
                "files": metadata_bundle.get("files", []),
                "error": metadata_bundle.get("error"),
            },
        },
        "chain_validation": validation,
        "limitations": [
            "Raspberry Pi vendor-root signatures are enforced by BootROM but are not independently replay-verified by GGFW.",
            "BCM2712 customer-key state requires rpiboot metadata because public runtime OTP rows are not documented.",
        ],
        "references": OFFICIAL_OTP_REFERENCES,
    }

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


# ==============================================================================
# 11B. Hardware Policy Engine
# ==============================================================================

class HardwarePolicyEngine:
    def __init__(
        self,
        platform: str,
        otp: Dict[str, str],
        eeprom_conf: str,
        report: GGFWReport,
        otp_tool_available: bool = True,
        otp_metadata_bundle: Optional[Dict[str, Any]] = None,
    ):
        self.platform = platform
        self.otp = otp
        self.eeprom_conf = eeprom_conf
        self.report = report
        self.otp_tool_available = otp_tool_available
        self.otp_metadata_bundle = otp_metadata_bundle or load_rpiboot_metadata(None)
        self.decoded: Dict[str, Any] = {}
        self.secure_boot: Dict[str, Any] = {}

    def run_all_checks(self, defer_secure_boot: bool = False) -> Dict[str, Any]:
        self.check_otp_read()
        self.decode_otp()
        self.check_otp_security_fields()
        if not defer_secure_boot:
            self.check_secure_boot()
        self.check_eeprom_tool_availability()
        return self.secure_boot

    def _profile_severity(self, default: str = "INFO", hardened: str = "MEDIUM", required: str = "HIGH") -> Tuple[str, bool]:
        profile = self.report.policy_profile
        if profile == "secure-boot-required":
            return required, True
        if profile == "hardened":
            return hardened, True
        return default, default in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _otp_evidence_items(self) -> List[EvidenceRecord]:
        items = [EvidenceRecord(
            source_type="FIRMWARE_REPORTED", source_path="vcgencmd otp_dump",
            acquisition_method="firmware mailbox query", trust_level="MEDIUM",
            raw=f"OTP words collected: {len(self.otp)}",
            normalized={"otp_words_collected": len(self.otp), "decoder_profile": self.decoded.get("decoder_profile")},
        )]
        if self.otp_metadata_bundle.get("loaded"):
            items.append(EvidenceRecord(
                source_type="EXTERNAL_PROVISIONING_METADATA",
                source_path=self.otp_metadata_bundle.get("path", ""),
                acquisition_method="operator-supplied rpiboot -j recovery metadata",
                trust_level="HIGH",
                raw=json.dumps(self.otp_metadata_bundle.get("metadata", {}), ensure_ascii=False),
                normalized={
                    "files": self.otp_metadata_bundle.get("files", []),
                    "provenance_asserted_by_operator": True,
                    "cryptographically_authenticated": False,
                },
            ))
        return items

    def check_otp_read(self):
        if not self.otp_tool_available:
            return
        if not self.otp:
            self.report.add_finding(Finding(
                rule_id="HW-OTP-000", severity="INFO", category="HARDWARE",
                description="OTP state could not be read.",
                evidence="vcgencmd otp_dump returned no decoded OTP words",
                remediation="Run as root and verify that the installed vcgencmd supports otp_dump on this platform.",
                coverage_gap=True, finding_class="COVERAGE_GAP",
            ))

    def decode_otp(self):
        self.decoded = decode_otp_state(self.platform, self.otp, self.otp_metadata_bundle)
        self.report.raw_artifacts["otp_decoded"] = self.decoded
        self.report.raw_artifacts["otp_decoder_metadata"] = {
            "schema": OTP_DECODER_SCHEMA,
            "profile": self.decoded.get("decoder_profile"),
            "version": self.decoded.get("decoder_version"),
            "status": self.decoded.get("decoder_status"),
            "public_mapping": self.decoded.get("public_mapping"),
            "references": OFFICIAL_OTP_REFERENCES,
            "principle": "Undefined OTP rows and bits are never inferred.",
        }
        if self.decoded.get("decoder_status") in {"SUPPORTED", "PARTIAL"}:
            self.report.add_check(
                "RPI-OTP-DECODE-PASS", "PLATFORM_HARDWARE",
                "The model-specific public OTP mapping was decoded without inferring undocumented bits.",
                source_type="FIRMWARE_REPORTED", trust_level="MEDIUM",
                decoder_profile=self.decoded.get("decoder_profile"),
                decoder_status=self.decoded.get("decoder_status"),
            )

    def check_otp_security_fields(self):
        security = self.decoded.get("security", {})
        key = security.get("customer_key_hash", {})
        key_status = key.get("status", "UNKNOWN")
        jtag = security.get("vc_jtag_lock", {})
        jtag_status = jtag.get("status", "UNKNOWN")

        if key_status == "UNKNOWN":
            severity, actionable = self._profile_severity()
            self.report.add_finding(Finding(
                rule_id="RPI-OTP-002", severity=severity, category="HARDWARE",
                description="Customer Secure Boot key state could not be decoded from the available OTP evidence.",
                evidence=json.dumps(key, ensure_ascii=False),
                remediation=("For BCM2712, collect external provisioning metadata with `rpiboot -j` and pass it with "
                             "--otp-metadata. Do not infer undocumented OTP rows."),
                domain="BOOT_AND_EEPROM", status="EVIDENCE_INCOMPLETE", confidence="HIGH",
                coverage_gap=True, actionable=actionable, finding_class="COVERAGE_GAP",
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="Customer public-key hash state conclusively established",
                observed=key.get("note", "Customer key state unavailable"),
                rationale="The public BCM2712 runtime otp_dump map does not disclose the customer-key-hash rows.",
                evidence_items=self._otp_evidence_items(),
            ))
        elif key_status == "UNPROGRAMMED":
            severity, actionable = self._profile_severity()
            self.report.add_finding(Finding(
                rule_id="RPI-OTP-001", severity=severity, category="HARDWARE",
                description="The customer Secure Boot public-key hash is not programmed in OTP.",
                evidence=json.dumps(key, ensure_ascii=False),
                remediation="Provision customer-key Secure Boot only through the approved rpiboot recovery workflow.",
                domain="BOOT_AND_EEPROM", status="UNPROGRAMMED", actionable=actionable,
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="Customer public-key hash programmed when Secure Boot is required",
                observed="Customer key hash is all zero / reported unprogrammed",
                rationale="Without a programmed customer key hash, customer-key Secure Boot cannot be enforced.",
                evidence_items=self._otp_evidence_items(),
            ))
        elif key_status == "PROGRAMMED":
            self.report.add_check(
                "RPI-OTP-KEY-PASS", "BOOT_AND_EEPROM",
                "Customer Secure Boot public-key hash evidence is programmed.",
                source_type=("EXTERNAL_PROVISIONING_METADATA" if self.otp_metadata_bundle.get("loaded") else "FIRMWARE_REPORTED"),
                trust_level=("HIGH" if self.otp_metadata_bundle.get("loaded") else "MEDIUM"),
                decoder_profile=self.decoded.get("decoder_profile"),
            )

        if jtag_status in {"UNLOCKED", "PARTIAL"}:
            severity = "MEDIUM" if self.report.policy_profile in {"hardened", "secure-boot-required"} else "INFO"
            actionable = severity != "INFO"
            self.report.add_finding(Finding(
                rule_id="RPI-OTP-003", severity=severity, category="DEBUG",
                description="VideoCore JTAG is not fully locked.",
                evidence=json.dumps(jtag, ensure_ascii=False),
                remediation="Permanently lock JTAG only as part of an approved irreversible provisioning procedure.",
                domain="PLATFORM_HARDWARE", status=jtag_status, actionable=actionable,
                expected="VC JTAG locked for a production locked-appliance profile",
                observed=f"VC JTAG state: {jtag_status}",
                rationale="An unlocked debug path increases physical attack and post-compromise capability.",
                evidence_items=self._otp_evidence_items(),
            ))
        elif jtag_status == "LOCKED":
            self.report.add_check(
                "RPI-OTP-JTAG-PASS", "PLATFORM_HARDWARE", "VideoCore JTAG lock is asserted.",
                source_type=("EXTERNAL_PROVISIONING_METADATA" if self.otp_metadata_bundle.get("loaded") else "FIRMWARE_REPORTED"),
                trust_level=("HIGH" if self.otp_metadata_bundle.get("loaded") else "MEDIUM"),
            )

    def check_secure_boot(self, chain_validation: Optional[Dict[str, Any]] = None):
        boot_root = Path(self.report.target_path)
        self.secure_boot = build_secure_boot_evidence(
            self.platform, boot_root, self.decoded, self.otp_metadata_bundle,
            self.report.policy_profile, chain_validation=chain_validation,
        )
        self.report.raw_artifacts["secure_boot_assessment"] = self.secure_boot
        self.report.raw_artifacts["secure_boot_evidence"] = self.secure_boot
        overall = self.secure_boot.get("overall")
        pair = self.secure_boot.get("completeness")
        enable_status = self.secure_boot.get("evidence", {}).get("secure_boot_enablement", {}).get("status", "UNKNOWN")

        if pair == "INCONSISTENT":
            self.report.add_finding(Finding(
                rule_id="RPI-SB-002", severity="HIGH", category="BOOT",
                description="Secure Boot artifact evidence is internally inconsistent.",
                evidence=json.dumps(self.secure_boot, ensure_ascii=False),
                remediation="Restore a matching boot.img/boot.sig pair from an approved signed image.",
                domain="BOOT_AND_EEPROM", status="INCONSISTENT",
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="boot.img and boot.sig both present or both intentionally absent",
                observed=f"Secure Boot artifact pair: {pair}",
                rationale="A partial signed-boot artifact pair cannot establish an authenticated boot ramdisk.",
                evidence_items=self._otp_evidence_items() + [EvidenceRecord(
                    source_type="OS_MEDIATED_FILE_MEASURED", source_path=str(boot_root),
                    acquisition_method="boot filesystem presence check", trust_level="MEDIUM",
                    raw=json.dumps(self.secure_boot.get("evidence", {}), ensure_ascii=False),
                )],
            ))

        if overall == "DISABLED" and self.report.policy_profile != "secure-boot-required":
            severity, actionable = self._profile_severity(default="INFO", hardened="MEDIUM", required="HIGH")
            self.report.add_finding(Finding(
                rule_id="RPI-SB-001", severity=severity, category="BOOT",
                description="Customer-key Secure Boot is not enforced.",
                evidence=json.dumps(self.secure_boot, ensure_ascii=False),
                remediation="Provision and validate customer-key Secure Boot through the official irreversible workflow if policy requires it.",
                domain="BOOT_AND_EEPROM", status="DISABLED", actionable=actionable,
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="Customer-key Secure Boot enabled when required by policy",
                observed=f"OTP/provisioning evidence reports {enable_status}",
                rationale="The key/provisioning evidence conclusively indicates that customer-key Secure Boot is not enforced.",
                evidence_items=self._otp_evidence_items(),
            ))
            return

        boot_img_status = self.secure_boot.get("evidence", {}).get("boot_img", {}).get("status")
        boot_sig_status = self.secure_boot.get("evidence", {}).get("boot_sig", {}).get("status")

        validation = self.secure_boot.get('chain_validation', {})
        public_key_validation = validation.get('public_key', {})
        boot_image_validation = validation.get('boot_image_signature', {})
        bootconf_validation = validation.get('bootconf_signature', {})
        bootsys_validation = validation.get('bootsys_customer_countersignature', {})

        if self.report.policy_profile == "secure-boot-required":
            missing_controls: List[str] = []
            evidence_limits: List[str] = []
            enable_status = str(self.secure_boot.get('secure_boot_enablement', 'UNKNOWN'))
            if enable_status not in {'ENABLED', 'PROVISIONED'}:
                if enable_status in {'DISABLED', 'UNPROGRAMMED'}:
                    missing_controls.append('customer Secure Boot enforcement')
                else:
                    evidence_limits.append('Secure Boot enablement not conclusively evidenced')
            if boot_img_status != 'PRESENT':
                missing_controls.append('boot.img')
            if boot_sig_status != 'PRESENT':
                missing_controls.append('boot.sig')
            if bootconf_validation.get('overall') != VALIDATION_VALID:
                missing_controls.append('EEPROM bootconf customer signature')
            if get_soc_generation(self.platform) == 'BCM2712' and bootsys_validation.get('overall') != VALIDATION_VALID:
                missing_controls.append('BCM2712 bootsys customer countersignature')
            key_state = self.secure_boot.get('otp_customer_key', 'UNKNOWN')
            if key_state not in {'PROGRAMMED', 'MATCH'}:
                evidence_limits.append('customer OTP/provisioning key state unavailable')
            if public_key_validation.get('otp_binding') != 'MATCH':
                evidence_limits.append('public key to OTP binding not verified')

            missing_controls = list(dict.fromkeys(missing_controls))
            evidence_limits = list(dict.fromkeys(evidence_limits))
            if missing_controls:
                self.report.add_finding(Finding(
                    rule_id='RPI-SB-001', severity='HIGH', category='BOOT',
                    description='The secure-boot-required policy is not satisfied.',
                    evidence=json.dumps({
                        'missing_policy_controls': missing_controls,
                        'evidence_limits': evidence_limits,
                        'secure_boot': self.secure_boot,
                    }, ensure_ascii=False),
                    remediation=(
                        'Satisfy the missing policy controls listed in observed, provide the requested external '
                        'provisioning evidence where applicable, and rerun cryptographic validation.'
                    ),
                    domain='BOOT_AND_EEPROM', status='POLICY_FAIL', actionable=True,
                    finding_class='POLICY_FAILURE', remediation_group='SECURE_BOOT_ENABLEMENT',
                    expected='All controls required by secure-boot-required are present and cryptographically valid',
                    observed=(
                        f"missing_policy_controls={','.join(missing_controls)}; "
                        f"evidence_limits={','.join(evidence_limits) if evidence_limits else 'none'}"
                    ),
                    rationale=(
                        'This leaf finding records confirmed absence of controls required by the selected policy. '
                        'Evidence limitations remain separate coverage-gap findings.'
                    ),
                    evidence_items=self._otp_evidence_items() + [EvidenceRecord(
                        source_type='OS_MEDIATED_FILE_MEASURED', source_path=str(boot_root),
                        acquisition_method='secure-boot policy matrix evaluation', trust_level='MEDIUM',
                        raw=json.dumps({'missing_controls': missing_controls, 'evidence_limits': evidence_limits}),
                    )],
                ))

        if public_key_validation.get('source_relationship') == 'SUPPLIED_MISMATCHES_EEPROM' or public_key_validation.get('otp_binding') == 'MISMATCH':
            self.report.add_finding(Finding(
                rule_id='RPI-SB-004', severity='CRITICAL', category='BOOT',
                description='The Secure Boot customer public key does not match the EEPROM or OTP binding evidence.',
                evidence=json.dumps(public_key_validation, ensure_ascii=False),
                remediation='Restore the EEPROM image and signed artifacts that correspond to the provisioned customer key. Do not replace OTP-bound keys.',
                domain='BOOT_AND_EEPROM', status='KEY_BINDING_MISMATCH', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='Supplied key, EEPROM pubkey.bin and OTP customer-key hash form one consistent identity',
                observed=f"relationship={public_key_validation.get('source_relationship')}; otp_binding={public_key_validation.get('otp_binding')}",
                rationale='A key-identity mismatch breaks the customer chain of trust even when individual signatures are syntactically valid.',
                evidence_items=self._otp_evidence_items(),
            ))
        elif public_key_validation.get('otp_binding') == 'MATCH':
            self.report.add_check(
                'RPI-SB-KEY-BINDING-PASS', 'BOOT_AND_EEPROM',
                'The verification public key matches the EEPROM key and provisioned customer-key hash.',
                source_type='SIGNED_TRUSTED_ARTIFACT', trust_level='HIGH',
                pubkey_bin_sha256=public_key_validation.get('computed_pubkey_bin_sha256') or (
                    public_key_validation.get('supplied', {}) or public_key_validation.get('eeprom', {})
                ).get('pubkey_bin_sha256'),
            )

        if boot_image_validation.get('overall') == VALIDATION_INVALID:
            self.report.add_finding(Finding(
                rule_id='RPI-SB-003', severity='CRITICAL', category='BOOT',
                description='Cryptographic validation of boot.img against boot.sig failed.',
                evidence=json.dumps(boot_image_validation, ensure_ascii=False),
                remediation='Replace boot.img and boot.sig with an approved matching pair signed by the provisioned customer key.',
                domain='BOOT_AND_EEPROM', status='SIGNATURE_INVALID', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='SHA-256 digest and RSA PKCS#1 v1.5 signature both verify',
                observed=(f"digest={boot_image_validation.get('digest_status')}; "
                          f"rsa={boot_image_validation.get('rsa_signature_status')}; "
                          f"target_soc={boot_image_validation.get('target_soc_status')}"),
                rationale='The official boot.sig format signs boot.img directly with RSA-2048/SHA-256.',
                evidence_items=[EvidenceRecord(
                    source_type='OS_MEDIATED_FILE_MEASURED', source_path=str(boot_root),
                    acquisition_method='SHA-256 and RSA PKCS#1 v1.5 verification', trust_level='MEDIUM',
                    raw=json.dumps(boot_image_validation, ensure_ascii=False),
                )],
            ))
        elif boot_image_validation.get('overall') == VALIDATION_VALID:
            self.report.add_check(
                'RPI-SB-BOOT-IMAGE-PASS', 'BOOT_AND_EEPROM',
                'boot.img digest and RSA PKCS#1 v1.5 signature verified.',
                source_type='SIGNED_TRUSTED_ARTIFACT',
                trust_level='HIGH' if public_key_validation.get('otp_binding') == 'MATCH' else 'MEDIUM',
                image_sha256=boot_image_validation.get('image_sha256'),
                timestamp=boot_image_validation.get('timestamp'),
            )

        if bootconf_validation.get('overall') == VALIDATION_INVALID:
            self.report.add_finding(Finding(
                rule_id='RPI-SB-005', severity='CRITICAL', category='BOOT',
                description='The EEPROM boot configuration signature is cryptographically invalid.',
                evidence=json.dumps(bootconf_validation, ensure_ascii=False),
                remediation='Restore a bootconf.txt/bootconf.sig pair signed by the OTP-bound customer key.',
                domain='BOOT_AND_EEPROM', status='BOOTCONF_SIGNATURE_INVALID', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='EEPROM bootconf.txt digest and customer RSA signature verify',
                observed=(f"bootconf validation={bootconf_validation.get('overall')}; "
                          f"reason={bootconf_validation.get('reason_code')}; "
                          f"content_classes={bootconf_validation.get('content_classes', [])}"),
                rationale='A parsed customer signature was present and failed format, digest, key, or RSA validation. Missing or placeholder signatures are reported as UNVERIFIED instead.',
                evidence_items=[EvidenceRecord(
                    source_type='OS_MEDIATED_SPI_READ', source_path=str(validation.get('eeprom', {}).get('path', '')),
                    acquisition_method='EEPROM section extraction and RSA verification', trust_level='MEDIUM',
                    raw=json.dumps(bootconf_validation, ensure_ascii=False),
                )],
            ))
        elif bootconf_validation.get('overall') == VALIDATION_VALID:
            self.report.add_check(
                'RPI-SB-BOOTCONF-PASS', 'BOOT_AND_EEPROM',
                'EEPROM bootconf.txt digest and customer signature verified.',
                source_type='SIGNED_TRUSTED_ARTIFACT',
                trust_level='HIGH' if public_key_validation.get('otp_binding') == 'MATCH' else 'MEDIUM',
            )

        if bootsys_validation.get('overall') == VALIDATION_INVALID:
            self.report.add_finding(Finding(
                rule_id='RPI-SB-006', severity='CRITICAL', category='BOOT',
                description='BCM2712 bootsys customer counter-signature validation failed.',
                evidence=json.dumps(bootsys_validation, ensure_ascii=False),
                remediation='Install a Raspberry Pi-signed bootsys that is counter-signed by the provisioned customer key.',
                domain='BOOT_AND_EEPROM', status='BOOTSYS_COUNTERSIGNATURE_INVALID', actionable=True,
                remediation_group='SECURE_BOOT_ENABLEMENT',
                expected='Every detected bootsys customer trailer verifies with key number 16',
                observed=(f"bootsys validation={bootsys_validation.get('overall')}; "
                          f"reason={bootsys_validation.get('reason_code')}"),
                rationale='BCM2712 Secure Boot requires the Raspberry Pi second stage to be counter-signed by the customer key.',
                evidence_items=[EvidenceRecord(
                    source_type='OS_MEDIATED_SPI_READ', source_path=str(validation.get('eeprom', {}).get('path', '')),
                    acquisition_method='BCM2712 signed-blob trailer parsing and RSA verification', trust_level='MEDIUM',
                    raw=json.dumps(bootsys_validation, ensure_ascii=False),
                )],
            ))
        elif bootsys_validation.get('overall') == VALIDATION_VALID:
            self.report.add_check(
                'RPI-SB-BOOTSYS-PASS', 'BOOT_AND_EEPROM',
                'BCM2712 bootsys customer counter-signature verified.',
                source_type='SIGNED_TRUSTED_ARTIFACT',
                trust_level='HIGH' if public_key_validation.get('otp_binding') == 'MATCH' else 'MEDIUM',
            )

        if self.secure_boot.get('overall') == 'PASS':
            self.report.add_check(
                'RPI-SB-CHAIN-PASS', 'BOOT_AND_EEPROM',
                'The complete customer Secure Boot chain was cryptographically validated.',
                source_type='SIGNED_TRUSTED_ARTIFACT', trust_level='HIGH',
                authenticity=self.secure_boot.get('authenticity'),
                freshness=self.secure_boot.get('freshness'),
            )

        if self.secure_boot.get("coverage_gap"):
            severity, actionable = self._profile_severity(default="INFO", hardened="MEDIUM", required="HIGH")
            secure_boot_blockers = [
                finding.rule_id for finding in self.report.findings
                if finding.rule_id in {
                    "RPI-OTP-001", "RPI-OTP-002", "RPI-SB-001", "RPI-SB-002",
                    "RPI-SB-003", "RPI-SB-004", "RPI-SB-005", "RPI-SB-006",
                }
            ]
            self.report.add_finding(Finding(
                rule_id="HW-SEC-001", severity=severity, category="HARDWARE",
                description="Secure Boot chain could not be conclusively evaluated.",
                evidence=json.dumps(self.secure_boot, ensure_ascii=False),
                remediation=("Resolve the leaf findings listed in blocked_by, then rerun cryptographic validation "
                             "until the chain is VERIFIED or a specific cryptographic INVALID finding is produced."),
                domain="BOOT_AND_EEPROM", status="UNVERIFIED", confidence="HIGH",
                coverage_gap=True, actionable=actionable,
                aggregate=True, blocked_by=secure_boot_blockers,
                remediation_group="SECURE_BOOT_ENABLEMENT",
                expected="AUTHENTICITY, COMPLETENESS, FRESHNESS and POLICY conclusively evaluated",
                observed=(f"overall={overall}; authenticity={self.secure_boot.get('authenticity')}; "
                          f"completeness={self.secure_boot.get('completeness')}; "
                          f"chain_validation={self.secure_boot.get('chain_validation', {}).get('overall')}"),
                rationale=(f"GGFW {TOOL_VERSION_DISPLAY} validates available customer-chain signatures, but "
                           "returns UNVERIFIED whenever a required key, OTP binding, artifact, or BCM2712 counter-signature is unavailable."),
                finding_class="COVERAGE_GAP",
                evidence_items=self._otp_evidence_items() + [EvidenceRecord(
                    source_type="OS_MEDIATED_FILE_MEASURED", source_path=str(boot_root),
                    acquisition_method="boot filesystem presence check", trust_level="MEDIUM",
                    raw=f"boot.img={boot_img_status}; boot.sig={boot_sig_status}",
                )],
            ))

    def check_eeprom_tool_availability(self):
        if "ERROR_MISSING" in self.eeprom_conf:
            self.report.add_finding(Finding(
                rule_id="HW-EEPROM-002", severity="INFO", category="HARDWARE",
                description="EEPROM audit skipped: rpi-eeprom-config tool not available.",
                evidence="rpi-eeprom-config not found",
                remediation="This is an auditor limitation, not a device vulnerability."
            ))


# ============================================================================== 
# 12. EEPROM Update Policy and A/B Assessment
# ============================================================================== 

class EEPROMUpdatePolicyEngine:
    def __init__(
        self,
        platform: str,
        eeprom_conf: str,
        report: GGFWReport,
        interrogator: HardwareInterrogator,
    ):
        self.platform = platform
        self.soc = get_soc_generation(platform)
        self.eeprom_conf = eeprom_conf
        self.config = parse_simple_config(eeprom_conf)
        self.report = report
        self.interrogator = interrogator
        self.defaults = self._read_update_defaults()
        self.service_state = self._read_service_state()

    @staticmethod
    def _read_update_defaults() -> Dict[str, str]:
        path = Path('/etc/default/rpi-eeprom-update')
        values: Dict[str, str] = {}
        try:
            for raw_line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip().strip('"\'')
        except OSError:
            pass
        return values

    @staticmethod
    def _systemctl_state(action: str, unit: str) -> str:
        systemctl = shutil.which('systemctl')
        if not systemctl:
            return 'UNAVAILABLE'
        try:
            result = subprocess.run(
                [systemctl, action, unit],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            output = (result.stdout or result.stderr).strip()
            return output or f'RETURNCODE_{result.returncode}'
        except (OSError, subprocess.TimeoutExpired):
            return 'UNKNOWN'

    def _read_service_state(self) -> Dict[str, str]:
        return {
            'enabled': self._systemctl_state('is-enabled', 'rpi-eeprom-update.service'),
            'active': self._systemctl_state('is-active', 'rpi-eeprom-update.service'),
        }

    def run_pre_spi(self):
        freeze_raw = self.config.get('FREEZE_VERSION')
        self_update_raw = self.config.get('ENABLE_SELF_UPDATE')
        freeze_state = (
            'ENABLED' if freeze_raw == '1'
            else 'DISABLED' if freeze_raw == '0'
            else 'UNSET_OR_DEFAULT'
        )
        self_update_state = (
            'ENABLED' if self_update_raw == '1'
            else 'DISABLED' if self_update_raw == '0'
            else 'UNSET_OR_DEFAULT'
        )

        boot_order_raw = self.config.get('BOOT_ORDER')
        boot_order_decoded = decode_boot_order(boot_order_raw)
        policy = {
            'freeze_version': freeze_state,
            'enable_self_update': self_update_state,
            'boot_order': boot_order_raw,
            'boot_order_decoded': boot_order_decoded,
            'boot_uart': self.config.get('BOOT_UART'),
            'net_install_at_power_on': self.config.get('NET_INSTALL_AT_POWER_ON'),
            'net_install_enabled': self.config.get('NET_INSTALL_ENABLED'),
            'update_defaults': self.defaults,
            'update_service': self.service_state,
        }
        self.report.raw_artifacts['eeprom_update_policy'] = policy

        if freeze_state != 'ENABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-UPDATE-001', severity='INFO', category='HARDWARE',
                description='EEPROM bootloader version is not explicitly frozen.',
                evidence=f'FREEZE_VERSION={freeze_raw!r}; state={freeze_state}',
                remediation=(
                    'Set FREEZE_VERSION=1 only when policy requires pinned firmware. '
                    'Otherwise retain a controlled and authenticated update process.'
                ),
            ))

        if self_update_state == 'ENABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-UPDATE-002', severity='INFO', category='HARDWARE',
                description='EEPROM self-update is explicitly enabled.',
                evidence='ENABLE_SELF_UPDATE=1',
                remediation='Confirm that self-update is required and that update artifacts are authenticated.',
            ))


        if self.config.get('BOOT_UART') == '1':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-DEBUG-001', severity='INFO', category='HARDWARE',
                description='EEPROM bootloader UART debug output is enabled.',
                evidence='BOOT_UART=1; GPIO14/GPIO15; default baud 115200 unless UART_BAUD overrides it',
                remediation='Disable BOOT_UART on production systems unless early boot diagnostics are required.',
                domain='BOOT_AND_EEPROM',
                status='OBSERVED',
                finding_class='CONFIGURATION_OBSERVATION',
                expected='Bootloader UART disabled unless explicitly required by policy',
                observed='BOOT_UART=1',
            ))

        if self.config.get('NET_INSTALL_AT_POWER_ON') == '1':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-NETINSTALL-001', severity='INFO', category='HARDWARE',
                description='Network Install UI is enabled briefly after cold power-on.',
                evidence='NET_INSTALL_AT_POWER_ON=1',
                remediation='Disable the power-on Network Install UI for locked appliances when it is not required.',
                domain='BOOT_AND_EEPROM',
                status='OBSERVED',
                finding_class='CONFIGURATION_OBSERVATION',
                expected='Network Install exposure matches the deployment policy',
                observed='NET_INSTALL_AT_POWER_ON=1',
            ))

        if boot_order_raw:
            self.report.add_check(
                'RPI-BOOT-ORDER-000', 'BOOT_AND_EEPROM',
                'EEPROM BOOT_ORDER was decoded.',
                raw=boot_order_raw, decoded=boot_order_decoded,
            )
            if boot_order_decoded.get('contains_network') or boot_order_decoded.get('contains_rpiboot'):
                self.report.add_finding(Finding(
                    rule_id='RPI-BOOT-ORDER-001', severity='INFO', category='HARDWARE',
                    description='EEPROM boot order includes a network or provisioning boot path.',
                    evidence=json.dumps(boot_order_decoded, ensure_ascii=False),
                    remediation='Confirm that every alternative boot path is required and compatible with Secure Boot policy.',
                    domain='BOOT_AND_EEPROM',
                    finding_class='CONFIGURATION_OBSERVATION',
                    expected='Only approved boot sources are present in BOOT_ORDER',
                    observed=', '.join(item['mode'] for item in boot_order_decoded.get('sequence', [])),
                ))

    def _assess_ab_with_tool(self) -> Dict[str, Any]:
        path = self.interrogator.rpi_eeprom_ab_path
        if not path:
            return {'status': 'TOOL_UNAVAILABLE', 'assessment_method': 'TOOL_LOOKUP', 'authoritative_runtime_state': False}
        try:
            result = subprocess.run(
                [path, 'committed'],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            output = '\n'.join(
                part.strip() for part in (result.stdout, result.stderr) if part and part.strip()
            )
            if result.returncode == 0 and re.fullmatch(r'\d+', result.stdout.strip()):
                return {
                    'status': 'ENABLED',
                    'assessment_method': 'RPI_EEPROM_AB_COMMITTED',
                    'authoritative_runtime_state': True,
                    'committed_partition': int(result.stdout.strip()),
                    'output': output,
                }
            if 'ab partitioning is not being used' in output.lower():
                return {
                    'status': 'DISABLED',
                    'assessment_method': 'RPI_EEPROM_AB_COMMITTED',
                    'authoritative_runtime_state': True,
                    'output': output,
                }
            return {
                'status': 'UNKNOWN',
                'assessment_method': 'RPI_EEPROM_AB_COMMITTED',
                'authoritative_runtime_state': False,
                'returncode': result.returncode,
                'output': output,
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {'status': 'UNKNOWN', 'assessment_method': 'RPI_EEPROM_AB_COMMITTED', 'authoritative_runtime_state': False, 'output': str(exc)}

    def _bootloader_release_date(self) -> Optional[datetime]:
        output = str(self.report.raw_artifacts.get('bootloader_version', ''))
        match = re.search(r'(20\d{2})[/-](\d{2})[/-](\d{2})', output)
        if not match:
            return None
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return None

    def run_post_spi(self, spi_result: SPIReadResult):
        if self.soc != 'BCM2712':
            self.report.raw_artifacts['eeprom_ab_assessment'] = {
                'status': 'NOT_APPLICABLE',
                'applicability': 'NOT_APPLICABLE',
                'reason': 'A/B bootloader EEPROM updates are BCM2712-specific.',
            }
            return

        assessment = self._assess_ab_with_tool()
        if assessment['status'] in {'TOOL_UNAVAILABLE', 'UNKNOWN'}:
            if spi_result.ab_layout_magic_detected is True:
                assessment = {
                    'status': 'HEURISTIC_ENABLED',
                    'assessment_method': 'SPI_TRAILER_MARKER_HEURISTIC',
                    'authoritative_runtime_state': False,
                    'confidence': 'MEDIUM',
                    'offsets': spi_result.ab_layout_offsets,
                }
            elif spi_result.ab_layout_magic_detected is False:
                release_date = self._bootloader_release_date()
                ab_support_date = datetime(2026, 5, 13)
                if release_date and release_date < ab_support_date:
                    assessment = {
                        'status': 'UNSUPPORTED_BY_FIRMWARE',
                        'assessment_method': 'RELEASE_CAPABILITY_MAP',
                        'authoritative_runtime_state': False,
                        'confidence': 'HIGH',
                        'installed_release_date': release_date.date().isoformat(),
                        'ab_support_release_date': ab_support_date.date().isoformat(),
                    }
                else:
                    assessment = {
                        'status': 'UNKNOWN',
                        'assessment_method': 'SPI_TRAILER_ABSENCE',
                        'authoritative_runtime_state': False,
                        'confidence': 'LOW',
                        'reason': 'No A/B trailer markers found; absence is not authoritative.',
                    }

        self.report.raw_artifacts['eeprom_ab_assessment'] = assessment

        if assessment['status'] == 'DISABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-001', severity='INFO', category='HARDWARE',
                description='A/B EEPROM bootloader updates are not enabled.',
                evidence=assessment.get('output', 'rpi-eeprom-ab reported disabled'),
                domain='BOOT_AND_EEPROM', status='DISABLED', finding_class='CAPABILITY_GAP',
                expected='A/B availability matches the resilience policy', observed='DISABLED',
                remediation='Consider A/B EEPROM updates on supported BCM2712 systems where update resilience is required.',
            ))
        elif assessment['status'] == 'UNSUPPORTED_BY_FIRMWARE':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-003', severity='INFO', category='HARDWARE',
                description='Installed bootloader firmware predates BCM2712 A/B EEPROM update support.',
                evidence=json.dumps(assessment, ensure_ascii=False),
                domain='BOOT_AND_EEPROM', status='UNSUPPORTED', finding_class='CAPABILITY_GAP',
                expected='A/B capability only when required by resilience policy', observed='UNSUPPORTED_BY_FIRMWARE',
                remediation='Update the bootloader through an approved process before considering A/B EEPROM enablement.',
            ))
        elif assessment['status'] == 'HEURISTIC_ENABLED':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-002', severity='INFO', category='HARDWARE',
                description='A/B EEPROM layout markers were detected heuristically.',
                evidence=f"marker_offsets={assessment.get('offsets')}",
                domain='BOOT_AND_EEPROM', status='HEURISTIC_ENABLED', finding_class='CAPABILITY_GAP',
                expected='Runtime A/B state reported by rpi-eeprom-ab', observed='HEURISTIC_ENABLED',
                remediation='Install rpi-eeprom-ab and query the committed partition for authoritative confirmation.',
            ))
        elif assessment['status'] == 'UNKNOWN':
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-AB-000', severity='INFO', category='HARDWARE',
                description='A/B EEPROM update state could not be conclusively determined.',
                evidence=json.dumps(assessment, ensure_ascii=False),
                domain='BOOT_AND_EEPROM', status='UNVERIFIED', finding_class='COVERAGE_GAP',
                coverage_gap=True, expected='A/B runtime state established', observed='UNKNOWN',
                remediation='Install a compatible rpi-eeprom-ab tool or validate the EEPROM layout independently.',
            ))

        immediate = self.defaults.get('RPI_EEPROM_IMMEDIATE_UPDATE') == '1'
        flash_meta = self.report.raw_artifacts.get('tool_metadata', {}).get('flashrom', {})
        risky_flashrom = bool(flash_meta.get('upstream_1_4_to_1_6_write_caution'))
        ab_enabled = assessment['status'] in {'ENABLED', 'HEURISTIC_ENABLED'}
        if immediate and risky_flashrom and not ab_enabled:
            self.report.add_finding(Finding(
                rule_id='RPI-EEPROM-UPDATE-003', severity='HIGH', category='HARDWARE',
                description='Immediate EEPROM updates may use a flashrom version with known upstream erase-path cautions.',
                evidence=(
                    f"RPI_EEPROM_IMMEDIATE_UPDATE=1; flashrom={flash_meta.get('version')}; "
                    f"A/B={assessment['status']}"
                ),
                remediation=(
                    'Disable immediate flashrom updates, use the staged recovery path, '
                    'or install a Raspberry Pi-patched/newer flashrom build.'
                ),
            ))

# ==============================================================================
# 13. Pi5 Specific Checks
# ==============================================================================

class Pi5PolicyEngine:
    def __init__(self, config: Dict, report: GGFWReport, platform: str):
        self.config = config
        self.report = report
        self.platform = platform
        
        self.all_config_values = {}
        for section, values in config.items():
            self.all_config_values.update(values)
    
    def run_all_checks(self):
        if "BCM2712" not in self.platform:
            return
        
        dtparam = self.all_config_values.get('dtparam', '')
        if 'pciex1' in dtparam:
            self.report.add_finding(Finding(
                rule_id="RPI-PCIE-001", severity="INFO", category="HARDWARE",
                description="Pi5 PCIe x1 interface is enabled.",
                evidence=f"dtparam={dtparam}",
                remediation="Ensure connected PCIe devices are trusted."
            ))

# ==============================================================================
# 14. Evidence Package (.ggcap)
# ==============================================================================

class EvidencePackageBuilder:
    """Create a timestamped evidence directory and ZIP-based .ggcap package."""

    def __init__(self, evidence_root: str, scan_id: str):
        self.root = Path(evidence_root).expanduser().resolve()
        self.scan_id = scan_id
        self.scan_dir = self.root / scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.scan_dir, 0o700)
        except OSError:
            pass

    def path(self, relative: str) -> Path:
        destination = self.scan_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        return destination

    def write_text(self, relative: str, content: str) -> Path:
        destination = self.path(relative)
        destination.write_text(content, encoding='utf-8')
        return destination

    def write_bytes(self, relative: str, content: bytes) -> Path:
        destination = self.path(relative)
        destination.write_bytes(content)
        return destination

    def write_json(self, relative: str, payload: Any) -> Path:
        return self.write_text(relative, json.dumps(payload, indent=4, ensure_ascii=False) + '\n')

    def copy_file(self, source: Optional[str], relative: str) -> Optional[Path]:
        if not source:
            return None
        src = Path(source).expanduser().resolve()
        if not src.is_file():
            return None
        destination = self.path(relative)
        try:
            if src == destination.resolve():
                return destination
        except OSError:
            pass
        shutil.copy2(src, destination)
        return destination

    def collect(
        self,
        report: GGFWReport,
        boot_path: str,
        config_detail: Dict[str, Any],
        baseline_path: Optional[str],
        spi_result: Optional[SPIReadResult],
    ) -> None:
        boot_root = Path(boot_path).expanduser().resolve()

        # Boot configuration and resolved chain.
        for parsed in config_detail.get('parsed_files', []):
            source = Path(parsed)
            try:
                relative = source.resolve().relative_to(boot_root)
            except (OSError, ValueError):
                continue
            self.copy_file(str(source), f'evidence/boot/{relative}')
        self.copy_file(str(boot_root / 'cmdline.txt'), 'evidence/boot/cmdline.txt')
        self.write_json('evidence/boot/config-parse.json', config_detail)
        if 'boot_resolution_graph' in report.raw_artifacts:
            graph = report.raw_artifacts['boot_resolution_graph']
            self.write_json('evidence/boot/resolved-chain.json', graph)
            self.write_text('evidence/boot/resolved-chain.txt', graph.get('text', '') + '\n')
        if 'boot_integrity' in report.raw_artifacts:
            self.write_json('evidence/boot/file-hashes.json', report.raw_artifacts['boot_integrity'])
        if baseline_path:
            self.copy_file(baseline_path, 'evidence/boot/baseline.json')
        public_key_path = report.execution.get('secure_boot_public_key')
        if public_key_path:
            self.copy_file(public_key_path, 'evidence/boot/customer-public-key.pem')

        # Platform and firmware-reported evidence.
        self.write_json('evidence/platform/otp-raw.json', report.raw_artifacts.get('otp_raw', {}))
        self.write_json('evidence/platform/otp-decoded.json', report.raw_artifacts.get('otp_decoded', {}))
        self.write_json('evidence/platform/otp-decoder-metadata.json', report.raw_artifacts.get('otp_decoder_metadata', {}))
        self.write_json('evidence/platform/rpiboot-metadata.json', report.raw_artifacts.get('otp_metadata', {}))
        self.write_text(
            'evidence/platform/bootloader-version.txt',
            str(report.raw_artifacts.get('bootloader_version', '')) + '\n',
        )
        self.write_text(
            'evidence/platform/eeprom-config-live.txt',
            str(report.raw_artifacts.get('eeprom_config', '')) + '\n',
        )
        self.write_json(
            'evidence/platform/tool-metadata.json',
            report.raw_artifacts.get('tool_metadata', {}),
        )
        self.write_json(
            'evidence/boot/secure-boot-evidence.json',
            report.raw_artifacts.get('secure_boot_evidence', report.raw_artifacts.get('secure_boot_assessment', {})),
        )
        secure_validation = report.raw_artifacts.get('secure_boot_validation', {})
        self.write_json('evidence/boot/secure-boot-validation.json', secure_validation)
        self.write_json('evidence/spi/eeprom-files.json', secure_validation.get('eeprom', {}))
        pubkey_hex = secure_validation.get('eeprom', {}).get('pubkey_bin_hex')
        if isinstance(pubkey_hex, str):
            try:
                self.write_bytes('evidence/spi/pubkey.bin', bytes.fromhex(pubkey_hex))
            except ValueError:
                pass
        self.write_json(
            'evidence/platform/eeprom-update-policy.json',
            report.raw_artifacts.get('eeprom_update_policy', {}),
        )
        self.write_json(
            'evidence/platform/eeprom-ab-assessment.json',
            report.raw_artifacts.get('eeprom_ab_assessment', {}),
        )

        # SPI evidence. The acquisition remains OS-mediated.
        if spi_result:
            self.copy_file(spi_result.output_path, 'evidence/spi/eeprom.bin')
            self.copy_file(spi_result.bootconf_path, 'evidence/spi/bootconf.txt')
            self.write_text('evidence/spi/probe.txt', spi_result.probe_output + '\n')
            self.write_text('evidence/spi/read.txt', spi_result.read_output + '\n')
            self.write_text('evidence/spi/wp-status.txt', spi_result.wp_output + '\n')
            self.write_json('evidence/spi/config-comparison.json', spi_result.config_comparison)
            self.write_json('evidence/spi/acquisition.json', asdict(spi_result))

        # Human-readable semantics for reviewers and CI integrators.
        evidence_model = report.raw_artifacts.get('evidence_model', {})
        readme_lines = [
            f"GGFW {TOOL_VERSION_DISPLAY} evidence package",
            "",
            "Exit codes:",
            "  0 = scan completed and the selected policy gate was not triggered",
            "  1 = tool, runtime, argument, acquisition, baseline, or packaging failure",
            "  2 = scan completed successfully but --fail-on policy was triggered",
            "",
            "OTP / Secure Boot decoder semantics:",
            "  BCM2711 public runtime rows are decoded from vcgencmd otp_dump.",
            "  BCM2712 customer-key hash and JTAG lock are not inferred from undocumented runtime rows.",
            "  Supply rpiboot -j metadata with --otp-metadata to add independent provisioning evidence.",
            f"  GGFW {TOOL_VERSION_DISPLAY} verifies boot.img/boot.sig, EEPROM bootconf signatures, key-to-OTP binding,",
            "  and BCM2712 customer bootsys counter-signatures when the required evidence is available.",
            "  Raspberry Pi vendor-root signatures remain BootROM-enforced and are not independently replay-verified.",
            "",
            "Cryptographic engine self-test:",
            "  Run --crypto-self-test to execute embedded known-answer tests without accessing platform state.",
            "  The KAT covers valid/tampered boot.img, wrong key, malformed boot.sig, bootconf, and BCM2712 bootsys.",
            "",
            "Cryptographic validation states:",
            "  VALID      = the required artifact and key were available and verification succeeded",
            "  INVALID    = verification was actually performed or the signed format was parsed and a mismatch was proven",
            "  UNVERIFIED = a required key, binding, signature, or artifact was unavailable; this is not proof of invalidity",
            "  Empty, 0x00-filled, 0xff-erased, padding-only, and digest-only .sig sections are",
            "  classified as SIGNATURE_NOT_PRESENT. FORMAT_INVALID requires non-placeholder content",
            "  that represents an attempted signature file but cannot be parsed correctly.",
            "",
            "Secure Boot policy semantics:",
            "  secure-boot-required separates confirmed policy-control failures from evidence limitations.",
            "  Severity-based --fail-on gates use leaf SECURITY_FINDING/POLICY_FAILURE findings by default.",
            "  COVERAGE_GAP findings remain visible but require --fail-on-coverage or --fail-on COVERAGE_GAP to gate.",
            "",
            "Gate semantics:",
            "  Aggregate findings never trigger process exit; only leaf findings are evaluated.",
            "  --fail-on-coverage opts coverage gaps into severity-based gates.",
            "  --gate-exclude remains available for explicit additional filtering.",
            "  Exclusions affect only process gating; they do not suppress findings, counts, evidence, or remediation groups.",
            "",
            "Finding relations:",
            "  aggregate=true marks an outcome-level finding rather than an independent root task.",
            "  blocked_by lists findings that must be resolved before the aggregate can close.",
            "  remediation_group de-duplicates related findings into independent remediation tasks.",
            "",
            "Evidence trust:",
            "  HIGH   = independently acquired offline/external evidence or a verified trusted artifact",
            "  MEDIUM = evidence mediated by the examined operating system, firmware interface, or local baseline",
            "  LOW    = indirect, heuristic, or incomplete evidence",
            "",
            "For an in-band scan, MEDIUM is normally the maximum attainable trust level. HIGH generally",
            "requires an external SPI programmer, offline media acquisition, or a separately verified signed artifact.",
            "",
            "Acquisition context:",
            f"  {json.dumps(report.summary.get('evidence_context', {}), ensure_ascii=False)}",
            "",
            "Policy gate:",
            f"  {json.dumps(report.execution, ensure_ascii=False)}",
        ]
        self.write_text('README.txt', '\n'.join(readme_lines) + '\n')
        self.write_json('evidence/evidence-model.json', evidence_model)

        # OS/runtime posture evidence already normalised by the scanner.
        for key, filename in (
            ('local_accounts', 'accounts.json'),
            ('network_listeners', 'listeners.json'),
            ('apt_sources', 'apt-sources.json'),
            ('loaded_modules', 'loaded-modules.json'),
        ):
            if key in report.raw_artifacts:
                self.write_json(f'evidence/os/{filename}', report.raw_artifacts[key])

    def _manifest_entries(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for path in sorted(self.scan_dir.rglob('*')):
            if not path.is_file() or path.name == 'manifest.json':
                continue
            entries.append({
                'path': str(path.relative_to(self.scan_dir)),
                'size': path.stat().st_size,
                'sha256': sha256_file(str(path)),
            })
        return entries

    def finalise(self, report: GGFWReport, package_path: str) -> Dict[str, Any]:
        package = Path(package_path).expanduser().resolve()
        package.parent.mkdir(parents=True, exist_ok=True)
        report.raw_artifacts['evidence_package'] = {
            'schema': EVIDENCE_SCHEMA,
            'scan_directory': str(self.scan_dir),
            'package_path': str(package),
            'format': 'ZIP',
            'spi_source_type': 'OS_MEDIATED_SPI_READ',
        }
        self.write_text('report.json', report.to_json() + '\n')
        manifest = {
            'schema': EVIDENCE_SCHEMA,
            'tool_version': TOOL_VERSION,
            'scan_id': self.scan_id,
            'created_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            'platform': report.platform_guess,
            'policy_profile': report.policy_profile,
            'files': self._manifest_entries(),
        }
        self.write_json('manifest.json', manifest)

        temporary = package.with_name(package.name + '.tmp')
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in sorted(self.scan_dir.rglob('*')):
                if path.is_file():
                    archive.write(path, arcname=str(path.relative_to(self.scan_dir)))
        os.replace(temporary, package)
        try:
            os.chmod(package, 0o600)
        except OSError:
            pass
        package_hash = sha256_file(str(package))
        Path(str(package) + '.sha256').write_text(f'{package_hash}  {package.name}\n', encoding='utf-8')
        return {
            'scan_directory': str(self.scan_dir),
            'package_path': str(package),
            'package_sha256': package_hash,
            'manifest_entries': len(manifest['files']),
        }


# ==============================================================================
# 15. Remediation Summary
# ==============================================================================

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

# ==============================================================================
# 15. Main Execution
# ==============================================================================

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


def run_audit():
    parser = GGFWArgumentParser(
        description='GGFW Raspberry Pi Unified Auditor (Kali compatible, read-only SPI)',
        epilog=(
            'Exit codes: 0=completed/no gate, 1=tool or runtime failure, 2=policy gate triggered. '
            'Severity gates evaluate leaf security/policy findings. Coverage gaps require --fail-on-coverage '
            'or --fail-on COVERAGE_GAP; aggregate findings never trigger exit.'
        ),
    )
    parser.add_argument('--boot-path', default='/boot/firmware', help='Mounted boot filesystem path')
    parser.add_argument(
        '--output', default=None,
        help='Output .ggcap package path. A legacy .json value writes JSON there and creates a sibling .ggcap.'
    )
    parser.add_argument('--json-output', help='Optional additional standalone report JSON path')
    parser.add_argument('--evidence-root', default='ggfw-evidence', help='Root directory for timestamped evidence')
    parser.add_argument(
        '--policy-profile', default='default',
        choices=('default', 'hardened', 'secure-boot-required', 'resilient-appliance'),
        help='Policy profile used for applicability and severity adjustments',
    )
    parser.add_argument(
        '--min-severity', default='INFO',
        choices=('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
        help='Minimum severity displayed in the detailed terminal listing',
    )
    parser.add_argument('--summary-only', action='store_true', help='Suppress the detailed terminal listing')
    parser.add_argument('--show-passed', action='store_true', help='Print recorded positive checks')
    parser.add_argument('--show-trust-model', action='store_true', help='Print evidence trust legend and acquisition context')
    parser.add_argument('--show-otp', action='store_true', help='Print the model-specific OTP decoder summary')
    parser.add_argument('--secure-boot-evidence', action='store_true', help='Print the Secure Boot evidence matrix')
    parser.add_argument('--crypto-self-test', action='store_true', help='Run embedded cryptographic known-answer tests and exit')
    parser.add_argument('--otp-only', action='store_true', help='Run OTP/Secure-Boot evidence collection without host posture, baseline or SPI acquisition')
    parser.add_argument('--otp-metadata', help='rpiboot -j metadata JSON file or directory for external provisioning evidence')
    parser.add_argument(
        '--secure-boot-public-key',
        help='Customer RSA-2048 public key in PEM format used to validate boot.sig and EEPROM signatures',
    )
    parser.add_argument(
        '--max-boot-signature-age-days', type=int, default=None,
        help='Optional maximum accepted age of the boot.sig timestamp; stale signatures fail validation',
    )
    parser.add_argument(
        '--fail-on', default='NONE',
        choices=('NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ACTIONABLE', 'COVERAGE_GAP', 'ANY'),
        help='Exit with status 2 for matching leaf security/policy findings; coverage gaps are separate by default',
    )
    parser.add_argument('--fail-on-coverage', action='store_true', help='Include leaf COVERAGE_GAP findings in severity-based --fail-on gates')
    parser.add_argument(
        '--gate-exclude', action='append', default=[],
        choices=('COVERAGE_GAP', 'AGGREGATE'),
        help=(
            'Exclude a finding attribute from --fail-on evaluation without removing it from the report. '
            'Repeat for multiple exclusions.'
        ),
    )
    parser.add_argument('--skip-integrity', action='store_true', help='Skip boot measurement and baseline comparison')
    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument('--baseline', help='Compare boot files and resolved chain with a GGFW baseline')
    baseline_group.add_argument('--create-baseline', help='Create or replace a device-specific boot baseline')
    parser.add_argument('--skip-spi', action='store_true', help='Skip read-only SPI EEPROM acquisition')
    parser.add_argument('--spi-device', help='Override the platform-default spidev node')
    parser.add_argument('--spi-output', default=None, help='Optional external SPI dump path')
    parser.add_argument('--spi-speed', type=int, default=16000, help='flashrom linux_spi clock in kHz')
    args = parser.parse_args()
    # Preserve user order while de-duplicating repeatable gate exclusions.
    args.gate_exclude = list(dict.fromkeys(args.gate_exclude))

    if args.spi_speed <= 0:
        parser.error('--spi-speed must be a positive integer')
    if args.max_boot_signature_age_days is not None and args.max_boot_signature_age_days < 0:
        parser.error('--max-boot-signature-age-days must be zero or greater')
    if args.otp_only and (args.baseline or args.create_baseline):
        parser.error('--otp-only cannot be combined with --baseline or --create-baseline')
    if args.otp_only:
        args.skip_integrity = True
        args.skip_spi = True
    if args.skip_integrity and (args.baseline or args.create_baseline):
        parser.error('--skip-integrity cannot be combined with --baseline or --create-baseline')

    if args.crypto_self_test:
        return run_crypto_self_test()

    preflight_otp_metadata, preflight_public_key = preflight_explicit_external_inputs(args)

    boot_path = str(Path(args.boot_path).expanduser().resolve())
    config_txt = os.path.join(boot_path, 'config.txt')
    cmdline_txt = os.path.join(boot_path, 'cmdline.txt')
    if not os.path.isdir(boot_path):
        raise GGFWRuntimeError(f'Boot path is not a directory: {boot_path}')
    if not os.path.isfile(config_txt) and not args.otp_only:
        raise GGFWRuntimeError(f'config.txt was not found at: {config_txt}')

    print(f'[*] GGFW {TOOL_VERSION_DISPLAY} Cryptographic Secure-Boot Chain Auditor starting...')
    print(f'[*] Target boot path: {boot_path}')
    print(f'[*] Policy profile: {args.policy_profile}')

    platform = detect_platform()
    soc = get_soc_generation(platform)
    print(f'[*] Detected platform: {platform}')

    now_utc = datetime.now(timezone.utc)
    scan_id = f"ggfw-{now_utc.strftime('%Y%m%dT%H%M%SZ')}-{soc.lower()}"
    evidence_builder = EvidencePackageBuilder(args.evidence_root, scan_id)

    legacy_json_output: Optional[Path] = None
    if args.output:
        requested_output = Path(args.output).expanduser().resolve()
        if requested_output.name.endswith('.json'):
            legacy_json_output = requested_output
            package_name = requested_output.name[:-5]
            if not package_name.endswith('.ggcap'):
                package_name += '.ggcap'
            package_path = requested_output.with_name(package_name)
        else:
            package_path = requested_output
    else:
        package_path = evidence_builder.root / f'{scan_id}.ggcap'

    report = GGFWReport(
        target_path=boot_path,
        platform_guess=platform,
        scan_timestamp=now_utc.isoformat(),
        scan_id=scan_id,
        policy_profile=args.policy_profile,
    )

    report.raw_artifacts['evidence_model'] = {
        'schema': EVIDENCE_SCHEMA,
        'acquisition_context': 'IN_BAND',
        'policy_gate_semantics': (
            'In secure-boot-required, an UNVERIFIED Secure Boot state is HIGH because the required control '
            'could not be demonstrated. This is a policy failure and coverage gap, not evidence that Secure Boot is disabled.'
        ),
        'gate_exclusion_semantics': {
            'COVERAGE_GAP': 'Do not let evidence-coverage gaps trigger the selected --fail-on gate.',
            'AGGREGATE': 'Do not let aggregate outcome findings trigger the selected --fail-on gate.',
            'scope': 'Exclusions affect process gating only; findings remain in reports and counts.',
        },
        'exit_codes': {
            '0': 'scan completed; policy gate not triggered',
            '1': 'tool/runtime/argument/acquisition/baseline/packaging failure',
            '2': 'scan completed; --fail-on policy triggered',
        },
        'trust_legend': {
            'HIGH': 'independent offline/external evidence or a verified trusted artifact',
            'MEDIUM': 'evidence mediated by the examined OS, firmware interface, or local baseline',
            'LOW': 'indirect, heuristic, or incomplete evidence',
        },
        'source_types': {
            'EXTERNAL_SPI_DUMP': {
                'trust_level': 'HIGH',
                'description': 'Independent programmer acquisition while the target platform is not mediating the read.',
            },
            'OFFLINE_FILE_MEASURED': {
                'trust_level': 'HIGH',
                'description': 'File measurement from offline or write-blocked media outside the examined runtime.',
            },
            'SIGNED_TRUSTED_ARTIFACT': {
                'trust_level': 'HIGH',
                'description': 'Artifact independently verified against a trusted signing key or attestation root.',
            },
            'EXTERNAL_PROVISIONING_METADATA': {
                'trust_level': 'HIGH',
                'description': 'Operator-supplied rpiboot recovery metadata acquired outside the examined OS; file provenance is asserted, not cryptographically authenticated.',
            },
            'OPERATOR_SUPPLIED_PUBLIC_KEY': {
                'trust_level': 'MEDIUM',
                'description': 'Customer public key supplied by the operator; becomes HIGH only after matching EEPROM and OTP binding evidence.',
            },
            'OS_MEDIATED_SPI_READ': {
                'trust_level': 'MEDIUM',
                'description': 'flashrom/linux_spi acquisition mediated by the running kernel.',
            },
            'FIRMWARE_REPORTED': {
                'trust_level': 'MEDIUM',
                'description': 'State reported by vcgencmd or rpi-eeprom tools.',
            },
            'OS_OBSERVED': {
                'trust_level': 'MEDIUM',
                'description': 'Runtime state observed through procfs, sysfs, NSS and local tools.',
            },
            'OS_MEDIATED_FILE_MEASURED': {
                'trust_level': 'MEDIUM',
                'description': 'File size, digest or resolved-chain measurement performed by the examined operating system.',
            },
            'USER_BASELINE': {
                'trust_level': 'MEDIUM',
                'description': 'Operator-created device-specific measured baseline.',
            },
        },
    }

    print('[*] Checking dependencies...')
    deps = check_dependencies()
    for tool, (found, info) in deps.items():
        status = 'OK' if found else 'MISSING'
        print(f'    [{status}] {tool}: {info}')
    report.raw_artifacts['dependencies'] = {
        tool: {'available': found, 'info': info}
        for tool, (found, info) in deps.items()
    }

    print('[*] Parsing config.txt and resolving the active boot chain...')
    if args.otp_only and not os.path.isfile(config_txt):
        config_detail = {"active_config": {"all": {}}, "sections": {}, "directives": [], "includes": [],
                         "parsed_files": [], "errors": [], "otp_only_without_boot_config": True}
    else:
        config_detail = ConfigTxtParser.parse_detailed(config_txt, boot_path, platform)
    config_data = config_detail.get('active_config', {'all': {}})
    cmdline_data = CmdlineTxtParser.parse(cmdline_txt)
    boot_graph = BootResolutionGraphBuilder(boot_path, platform, config_detail).build()

    report.raw_artifacts['config_txt_parsed'] = config_detail.get('sections', {})
    report.raw_artifacts['config_txt_active'] = config_data
    report.raw_artifacts['config_txt_directives'] = config_detail.get('directives', [])
    report.raw_artifacts['config_txt_includes'] = config_detail.get('includes', [])
    report.raw_artifacts['cmdline_txt_parsed'] = cmdline_data
    report.raw_artifacts['boot_resolution_graph'] = boot_graph
    report.add_check(
        'RPI-BOOT-GRAPH-000', 'BOOT_AND_EEPROM',
        'The active boot chain was resolved from config.txt.',
        source_type='OS_MEDIATED_FILE_MEASURED', trust_level='MEDIUM',
        fingerprint=boot_graph.get('fingerprint'),
        active_files=boot_graph.get('active_files', []),
    )
    report.raw_artifacts['baseline_assessment'] = {
        'requested': bool(args.baseline),
        'path': str(args.baseline or ''),
        'status': 'NOT_REQUESTED' if not args.baseline else 'PENDING',
        'file_match_count': 0,
        'file_mismatch_count': 0,
        'resolved_chain_match': None,
    }

    if config_detail.get('errors'):
        report.add_finding(Finding(
            rule_id='RPI-CONFIG-000', severity='MEDIUM', category='BOOT',
            description='One or more config.txt includes could not be resolved safely.',
            evidence='; '.join(config_detail['errors']),
            remediation='Correct missing, cyclic or excessively nested config.txt includes.',
            domain='BOOT_AND_EEPROM', status='INCOMPLETE', coverage_gap=True,
            expected='Every active config.txt include is parsed', observed='Include parsing errors',
            finding_class='COVERAGE_GAP',
        ))

    if not args.otp_only:
        fat_engine = FATPolicyEngine(config_data, cmdline_data, report, boot_path)
        fat_engine.run_all_checks()
        print('[*] Running Pi5-specific checks...')
        Pi5PolicyEngine(config_data, report, platform).run_all_checks()
    else:
        print('[*] OTP-only mode: host posture and Pi5 runtime policy checks skipped.')

    integrity_checker: Optional[BootIntegrityChecker] = None
    integrity_results: Dict[str, Dict[str, Any]] = {}
    if not args.skip_integrity:
        action = 'Measuring resolved boot files'
        if args.baseline:
            action = f'Comparing resolved boot chain with baseline: {args.baseline}'
        elif args.create_baseline:
            action = f'Creating boot baseline: {args.create_baseline}'
        print(f'[*] {action}...')

        integrity_checker = BootIntegrityChecker(
            boot_path,
            platform,
            config=config_data,
            baseline_path=args.baseline,
            boot_graph=boot_graph,
        )
        integrity_results = integrity_checker.verify_integrity()
        report.raw_artifacts['boot_integrity'] = integrity_results

        if integrity_checker.baseline_error:
            report.add_finding(Finding(
                rule_id='RPI-INTEGRITY-000', severity='MEDIUM', category='INTEGRITY',
                description='Boot baseline could not be loaded or validated.',
                evidence=integrity_checker.baseline_error,
                remediation='Regenerate the baseline from a trusted system state and protect it from modification.',
                expected='Valid GGFW baseline', observed=integrity_checker.baseline_error,
            ))
        elif integrity_checker.baseline:
            if integrity_checker.baseline_legacy:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-005', severity='INFO', category='INTEGRITY',
                    description='A legacy v1 baseline was loaded without a resolved-chain fingerprint.',
                    evidence='schema=ggfw-boot-baseline/v1',
                    remediation=(f'Regenerate the baseline with GGFW {TOOL_VERSION} to cover the resolved boot graph.'),
                    status='LEGACY_BASELINE', finding_class='COVERAGE_GAP', coverage_gap=True,
                    expected='ggfw-boot-baseline/v2', observed='ggfw-boot-baseline/v1',
                ))
            baseline_platform = integrity_checker.baseline.get('platform')
            baseline_soc = integrity_checker.baseline.get('soc')
            if baseline_platform != platform or baseline_soc != soc:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-003', severity='MEDIUM', category='INTEGRITY',
                    description='Boot baseline platform metadata differs from the scanned device.',
                    evidence=(
                        f'baseline_platform={baseline_platform!r}; current_platform={platform!r}; '
                        f'baseline_soc={baseline_soc!r}; current_soc={soc!r}'
                    ),
                    remediation='Use a baseline created for this board class and intended software image.',
                ))

            mismatched = [name for name, result in integrity_results.items() if result['status'] == 'BASELINE_MISMATCH']
            if mismatched:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-001', severity='HIGH', category='INTEGRITY',
                    description='Boot files differ from the selected measured baseline.',
                    evidence=', '.join(mismatched),
                    remediation='Validate the changes against an approved update or restore the trusted image.',
                    expected='All measured boot files match the selected baseline',
                    observed=f'Mismatched files: {", ".join(mismatched)}',
                    evidence_items=[
                        EvidenceRecord(
                            source_type='OS_MEDIATED_FILE_MEASURED', source_path=boot_path,
                            acquisition_method='SHA-256 and size measurement through the running OS', trust_level='MEDIUM',
                            raw=', '.join(mismatched), normalized={'mismatched_files': mismatched},
                        ),
                        EvidenceRecord(
                            source_type='USER_BASELINE', source_path=str(args.baseline or ''),
                            acquisition_method='operator-selected baseline comparison', trust_level='MEDIUM',
                            raw=str(args.baseline or ''),
                        ),
                    ],
                ))

            untracked = [name for name, result in integrity_results.items() if result['status'] == 'BASELINE_MISSING_ENTRY']
            if untracked:
                report.add_finding(Finding(
                    rule_id='RPI-INTEGRITY-004', severity='INFO', category='INTEGRITY',
                    description='Resolved boot files are present but absent from the selected baseline.',
                    evidence=', '.join(untracked),
                    remediation='Review the files and regenerate the baseline after approving the resolved boot chain.',
                    finding_class='COVERAGE_GAP', coverage_gap=True,
                    expected='Every resolved boot file represented in baseline',
                    observed=f'Untracked files: {", ".join(untracked)}',
                ))

            baseline_chain = integrity_checker.baseline.get('resolved_chain', {})
            baseline_fingerprint = baseline_chain.get('fingerprint')
            if baseline_fingerprint:
                if baseline_fingerprint == boot_graph.get('fingerprint'):
                    report.add_check(
                        'RPI-BOOT-GRAPH-001', 'BOOT_AND_EEPROM',
                        'Resolved boot-chain fingerprint matches the baseline.',
                        source_type='OS_MEDIATED_FILE_MEASURED', trust_level='MEDIUM',
                        fingerprint=baseline_fingerprint,
                    )
                else:
                    report.add_finding(Finding(
                        rule_id='RPI-BOOT-GRAPH-001', severity='HIGH', category='INTEGRITY',
                        description='The resolved boot chain differs from the selected baseline.',
                        evidence=(
                            f'baseline={baseline_fingerprint}; current={boot_graph.get("fingerprint")}'
                        ),
                        remediation='Review config.txt directives, includes and selected boot components.',
                        expected=baseline_fingerprint,
                        observed=str(boot_graph.get('fingerprint')),
                        evidence_items=[
                            EvidenceRecord(
                                source_type='OS_MEDIATED_FILE_MEASURED', source_path='config.txt/resolved-chain',
                                acquisition_method='resolved-chain fingerprint calculated through the running OS', trust_level='MEDIUM',
                                raw=str(boot_graph.get('fingerprint')),
                                normalized={'active_files': boot_graph.get('active_files', [])},
                            ),
                            EvidenceRecord(
                                source_type='USER_BASELINE', source_path=str(args.baseline or ''),
                                acquisition_method='baseline fingerprint lookup', trust_level='MEDIUM',
                                raw=str(baseline_fingerprint),
                            ),
                        ],
                    ))

        missing_files = [name for name, result in integrity_results.items() if result['status'] == 'MISSING']
        if missing_files:
            report.add_finding(Finding(
                rule_id='RPI-INTEGRITY-002', severity='MEDIUM', category='INTEGRITY',
                description='Expected or baseline-tracked boot files are missing.',
                evidence=', '.join(missing_files),
                remediation='Verify the active boot configuration and boot filesystem completeness.',
            ))

        matching_files = [name for name, result in integrity_results.items() if result['status'] == 'BASELINE_MATCH']
        if matching_files:
            report.add_check(
                'RPI-INTEGRITY-PASS', 'BOOT_AND_EEPROM',
                'Measured boot files match the selected baseline.',
                source_type='OS_MEDIATED_FILE_MEASURED', trust_level='MEDIUM',
                count=len(matching_files), files=matching_files,
            )

        if args.baseline:
            baseline_assessment = report.raw_artifacts['baseline_assessment']
            baseline_assessment['file_match_count'] = sum(
                1 for result in integrity_results.values() if result.get('status') == 'BASELINE_MATCH'
            )
            baseline_assessment['file_mismatch_count'] = sum(
                1 for result in integrity_results.values()
                if result.get('status') in {'BASELINE_MISMATCH', 'MISSING'}
            )
            baseline_assessment['untracked_count'] = sum(
                1 for result in integrity_results.values() if result.get('status') == 'BASELINE_MISSING_ENTRY'
            )
            if integrity_checker.baseline_error:
                baseline_assessment['status'] = 'ERROR'
            elif integrity_checker.baseline:
                expected_fp = integrity_checker.baseline.get('resolved_chain', {}).get('fingerprint')
                current_fp = boot_graph.get('fingerprint')
                baseline_assessment['resolved_chain_match'] = (
                    None if not expected_fp else expected_fp == current_fp
                )
                if baseline_assessment['file_mismatch_count'] or baseline_assessment['resolved_chain_match'] is False:
                    baseline_assessment['status'] = 'DRIFT'
                elif integrity_checker.baseline_legacy or baseline_assessment['untracked_count']:
                    baseline_assessment['status'] = 'MATCH_WITH_COVERAGE_GAP'
                else:
                    baseline_assessment['status'] = 'MATCH'
            else:
                baseline_assessment['status'] = 'ERROR'

        if args.create_baseline:
            baseline_payload = integrity_checker.write_baseline(args.create_baseline, integrity_results)
            report.raw_artifacts['baseline_assessment'] = {
                'requested': False,
                'path': str(Path(args.create_baseline).expanduser().resolve()),
                'status': 'CREATED',
                'file_match_count': 0,
                'file_mismatch_count': 0,
                'resolved_chain_match': None,
            }
            report.raw_artifacts['baseline_created'] = {
                'path': str(Path(args.create_baseline).expanduser().resolve()),
                'schema': baseline_payload['schema'],
                'files': len(baseline_payload['files']),
                'resolved_chain_fingerprint': boot_graph.get('fingerprint'),
                'missing_at_creation': baseline_payload['missing_at_creation'],
            }
            print(
                f"[+] Baseline saved: {Path(args.create_baseline).expanduser().resolve()} "
                f"({len(baseline_payload['files'])} files)"
            )
    else:
        report.raw_artifacts['boot_integrity'] = {'attempted': False, 'reason': 'Disabled with --skip-integrity'}

    print('[*] Interrogating hardware...')
    hw_interrogator = HardwareInterrogator()
    report.raw_artifacts['tool_metadata'] = hw_interrogator.get_tool_metadata()
    flash_metadata = report.raw_artifacts['tool_metadata'].get('flashrom', {})
    if flash_metadata.get('path') and not flash_metadata.get('wp_cli_expected', True):
        report.add_finding(Finding(
            rule_id='RPI-TOOL-001', severity='INFO', category='TOOLING',
            description='Installed flashrom version predates expected write-protection CLI support.',
            evidence=json.dumps(flash_metadata, ensure_ascii=False),
            remediation='Use flashrom 1.3 or newer for --wp-status assessment.',
            finding_class='TOOLING_LIMITATION', coverage_gap=True,
        ))

    otp_data: Dict[str, str] = {}
    eeprom_conf = 'ERROR_MISSING: hardware interrogation unavailable'
    hw_interrogator.cache.clear()

    if hw_interrogator.vcgencmd_path:
        print(f'[*] Using vcgencmd at: {hw_interrogator.vcgencmd_path}')
        otp_data = hw_interrogator.get_otp_dump()
        report.raw_artifacts['otp_raw'] = otp_data
        report.raw_artifacts['bootloader_version'] = hw_interrogator.get_bootloader_version()
    else:
        print('[-] vcgencmd not found. OTP and bootloader-version checks skipped.')
        report.add_finding(Finding(
            rule_id='HW-OTP-000', severity='INFO', category='HARDWARE',
            description='vcgencmd not found; OTP interrogation was skipped.',
            evidence='vcgencmd binary missing',
            remediation='Install a compatible vcgencmd build if OTP checks are required.',
            coverage_gap=True, finding_class='TOOLING_LIMITATION',
        ))

    if hw_interrogator.rpi_eeprom_config_path:
        print(f'[*] Using rpi-eeprom-config at: {hw_interrogator.rpi_eeprom_config_path}')
        eeprom_conf = hw_interrogator.get_eeprom_config()
    else:
        print('[-] rpi-eeprom-config not found. EEPROM config parsing may be limited.')

    report.raw_artifacts['eeprom_config'] = eeprom_conf
    otp_metadata_bundle = preflight_otp_metadata or load_rpiboot_metadata(None)
    report.raw_artifacts['otp_metadata'] = otp_metadata_bundle
    if args.otp_metadata:
        if otp_metadata_bundle.get('loaded'):
            print(f"[+] rpiboot OTP metadata loaded: {len(otp_metadata_bundle.get('files', []))} JSON file(s)")
        else:
            print(f"[-] rpiboot OTP metadata could not be loaded: {otp_metadata_bundle.get('error')}")
    hardware_policy_engine = HardwarePolicyEngine(
        platform, otp_data, eeprom_conf, report,
        otp_tool_available=bool(hw_interrogator.vcgencmd_path),
        otp_metadata_bundle=otp_metadata_bundle,
    )
    hardware_policy_engine.run_all_checks(defer_secure_boot=True)

    update_policy_engine = EEPROMUpdatePolicyEngine(
        platform=platform,
        eeprom_conf=eeprom_conf,
        report=report,
        interrogator=hw_interrogator,
    )
    
    if not args.otp_only:
        update_policy_engine.run_pre_spi()

    spi_result: Optional[SPIReadResult] = None
    if not args.skip_spi and not args.otp_only:
        default_spi_path = evidence_builder.path('evidence/spi/eeprom.bin')
        spi_output = args.spi_output or str(default_spi_path)
        print('[*] Starting read-only SPI EEPROM acquisition...')
        if hw_interrogator.flashrom_path:
            print(f'[*] Using flashrom at: {hw_interrogator.flashrom_path}')

        spi_reader = SPIEEPROMReader(
            platform=platform,
            flashrom_path=hw_interrogator.flashrom_path,
            rpi_eeprom_config_path=hw_interrogator.rpi_eeprom_config_path,
            report=report,
            device_override=args.spi_device,
            spi_speed_khz=args.spi_speed,
        )
        spi_result = spi_reader.acquire(spi_output, eeprom_conf)
        report.raw_artifacts['spi_eeprom'] = asdict(spi_result)
        flash_runtime = report.raw_artifacts.get('tool_metadata', {}).get('flashrom', {})
        flash_runtime['wp_status_runtime_supported'] = spi_result.wp_supported
        flash_runtime['detected_chip'] = spi_result.detected_chip
        flash_runtime['probe_ok'] = spi_result.probe_ok
        if not args.otp_only:
            update_policy_engine.run_post_spi(spi_result)

        if spi_result.read_ok:
            report.add_check(
                'RPI-SPI-READ-PASS', 'BOOT_AND_EEPROM',
                'OS-mediated SPI EEPROM acquisition completed successfully.',
                source_type='OS_MEDIATED_SPI_READ', trust_level='MEDIUM',
                chip=spi_result.detected_chip,
                size=spi_result.size,
                sha256=spi_result.sha256,
            )
            print(f'[+] SPI EEPROM read: {spi_result.output_path}')
            print(f'[+] SPI EEPROM size: {spi_result.size} bytes')
            print(f'[+] SPI EEPROM SHA-256: {spi_result.sha256}')
            if spi_result.detected_chip:
                print(f'[+] SPI flash chip: {spi_result.detected_chip}')
            if spi_result.bootconf_path:
                print(f'[+] EEPROM bootconf: {spi_result.bootconf_path}')
            if spi_result.config_comparison:
                print(f"[*] Raw SPI vs live EEPROM config: {spi_result.config_comparison.get('result')}")
            print(f'[*] SPI EEPROM write protection: {spi_result.wp_assessment}')
            if spi_result.wp_start is not None and spi_result.wp_length is not None:
                print(
                    f'[*] SPI WP range: start=0x{spi_result.wp_start:08x}, '
                    f'length=0x{spi_result.wp_length:08x}'
                )
        else:
            print(f'[-] SPI EEPROM acquisition not completed: {spi_result.error}')
    elif args.otp_only:
        spi_result = SPIReadResult(attempted=False)
        report.raw_artifacts['spi_eeprom'] = {
            'attempted': False, 'reason': 'OTP-only mode', 'wp_assessment': 'NOT_TESTED'
        }
    else:
        spi_result = SPIReadResult(attempted=False)
        report.raw_artifacts['spi_eeprom'] = {
            'attempted': False, 'reason': 'Disabled with --skip-spi', 'wp_assessment': 'NOT_TESTED'
        }
        report.add_finding(Finding(
            rule_id='RPI-SPI-WP-000', severity='INFO', category='HARDWARE',
            description='SPI EEPROM write-protection assessment was not performed.',
            evidence='SPI acquisition disabled with --skip-spi',
            remediation='Run without --skip-spi to query flashrom --wp-status.',
            coverage_gap=True, finding_class='COVERAGE_GAP',
        ))
        update_policy_engine.run_post_spi(spi_result)

    spi_image_for_validation = None
    if spi_result is not None and spi_result.read_ok:
        spi_image_for_validation = spi_result.output_path
    print('[*] Validating the customer Secure Boot chain...')
    secure_boot_validation = validate_secure_boot_chain(
        platform_name=platform,
        boot_root=Path(boot_path),
        spi_image_path=spi_image_for_validation,
        public_key_path=args.secure_boot_public_key,
        decoded=report.raw_artifacts.get('otp_decoded', {}),
        metadata_bundle=otp_metadata_bundle,
        max_signature_age_days=args.max_boot_signature_age_days,
        supplied_key_material=preflight_public_key,
    )
    report.raw_artifacts['secure_boot_validation'] = secure_boot_validation
    hardware_policy_engine.check_secure_boot(chain_validation=secure_boot_validation)
    print(
        f"[*] Secure Boot chain validation: {secure_boot_validation.get('overall')} "
        f"(boot.img={secure_boot_validation.get('boot_image_signature', {}).get('overall')}, "
        f"bootconf={secure_boot_validation.get('bootconf_signature', {}).get('overall')}, "
        f"bootsys={secure_boot_validation.get('bootsys_customer_countersignature', {}).get('overall')})"
    )

    # Determine tool/runtime failures separately from a successfully completed policy gate.
    runtime_issues: List[str] = []
    if args.baseline and report.raw_artifacts.get('baseline_assessment', {}).get('status') == 'ERROR':
        runtime_issues.append('BASELINE_LOAD_OR_VALIDATION_FAILED')
    if not args.skip_spi and not args.otp_only:
        if not deps.get('flashrom', (False, ''))[0]:
            runtime_issues.append('FLASHROM_MISSING')
        elif spi_result is None or not spi_result.read_ok:
            runtime_issues.append('SPI_ACQUISITION_FAILED')

    gate_accounting = build_gate_accounting(
        report, args.fail_on, args.gate_exclude, args.fail_on_coverage
    )
    triggered_rules = list(gate_accounting['matching_rules'])
    excluded_triggered_rules = list(gate_accounting['excluded_rules'])
    match_details = list(gate_accounting['matching_findings'])
    excluded_match_details = list(gate_accounting['excluded_findings'])
    policy_exit_code = 2 if triggered_rules else 0
    if runtime_issues:
        final_exit_code = 1
        execution_classification = 'TOOL_ERROR'
        execution_status = 'FAILED'
    elif policy_exit_code == 2:
        final_exit_code = 2
        execution_classification = 'POLICY_TRIGGERED'
        execution_status = 'COMPLETED'
    else:
        final_exit_code = 0
        execution_classification = 'SUCCESS'
        execution_status = 'COMPLETED'

    report.execution = {
        'status': execution_status,
        'classification': execution_classification,
        'policy_triggered': policy_exit_code == 2,
        'exit_code': final_exit_code,
        'fail_on': args.fail_on,
        'gate_exclusions': list(args.gate_exclude),
        'fail_on_coverage': bool(args.fail_on_coverage),
        'gate_semantics': {
            'leaf_findings_only': True,
            'aggregates_can_trigger': False,
            'coverage_gaps_in_severity_gate': bool(args.fail_on_coverage),
        },
        'matching_rules': triggered_rules,
        'matching_findings': match_details,
        'excluded_matching_rules': excluded_triggered_rules,
        'excluded_matching_findings': excluded_match_details,
        'gate_accounting': gate_accounting,
        'runtime_issues': runtime_issues,
        'secure_boot_public_key': args.secure_boot_public_key,
        'max_boot_signature_age_days': args.max_boot_signature_age_days,
        'secure_boot_validation': secure_boot_validation.get('overall'),
        'secure_boot_policy_note': (
            'Secure-boot-required may produce HIGH coverage gaps, but severity-based gates exclude them by default. '
            'Use --fail-on-coverage or --fail-on COVERAGE_GAP to gate evidence completeness.'
        ),
        'gate_exclusion_note': (
            'Gate exclusions affect process gating only. Excluded findings remain in the report, '
            'summary counts, evidence package, and remediation model.'
        ),
    }

    secure_boot_policy_rollup = build_secure_boot_policy_rollup(
        report, args.policy_profile, report.raw_artifacts.get('secure_boot_evidence', {})
    )
    report.raw_artifacts['secure_boot_policy_rollup'] = secure_boot_policy_rollup

    # Calculate summary before evidence collection so README.txt can include trust context.
    report.calculate_summary()

    # Build and package all collected evidence.
    evidence_builder.collect(
        report=report,
        boot_path=boot_path,
        config_detail=config_detail,
        baseline_path=args.baseline or args.create_baseline,
        spi_result=spi_result,
    )
    package_info = evidence_builder.finalise(report, str(package_path))
    report.raw_artifacts['evidence_package'].update(package_info)

    standalone_json_paths: List[Path] = []
    if legacy_json_output:
        standalone_json_paths.append(legacy_json_output)
    if args.json_output:
        standalone_json_paths.append(Path(args.json_output).expanduser().resolve())
    for json_path in standalone_json_paths:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(report.to_json() + '\n', encoding='utf-8')

    print(f'\n[+] Unified analysis complete. Found {len(report.findings)} findings.')
    print(f"[+] Evidence directory: {package_info['scan_directory']}")
    print(f"[+] GGCap package: {package_info['package_path']}")
    print(f"[+] GGCap SHA-256: {package_info['package_sha256']}")
    for json_path in standalone_json_paths:
        print(f'[+] Standalone JSON: {json_path}')

    baseline_assessment = report.raw_artifacts.get('baseline_assessment', {})
    baseline_status = baseline_assessment.get('status', 'NOT_REQUESTED')
    if baseline_status != 'NOT_REQUESTED':
        print(
            f"[+] Baseline result: {baseline_status} "
            f"(matched={baseline_assessment.get('file_match_count', 0)}, "
            f"drift={baseline_assessment.get('file_mismatch_count', 0)}, "
            f"chain_match={baseline_assessment.get('resolved_chain_match')})"
        )

    policy_rollup = report.raw_artifacts.get('secure_boot_policy_rollup', {})
    print_secure_boot_policy_rollup(policy_rollup, args.policy_profile)

    print_scan_summary(report)

    if not args.summary_only:
        severity_rank = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        minimum = severity_rank[args.min_severity]
        print('\n' + '-' * 68)
        print(f'  DETAILED FINDINGS (minimum severity: {args.min_severity})')
        print('-' * 68)
        for domain in ('BOOT_AND_EEPROM', 'PLATFORM_HARDWARE', 'OS_RUNTIME', 'EVIDENCE_COVERAGE'):
            visible = sort_findings_for_display([
                finding for finding in report.findings
                if finding.domain == domain and severity_rank.get(finding.severity, 0) >= minimum
            ])
            if not visible:
                continue
            print(f'\n  [{domain}]')
            for finding in visible:
                flags = []
                if finding.coverage_gap:
                    flags.append('COVERAGE_GAP')
                if finding.applicability in {'NOT_REQUIRED', 'NOT_APPLICABLE'}:
                    flags.append(finding.applicability)
                flag_text = f" [{'|'.join(flags)}]" if flags else ''
                print(
                    f'  [{finding.severity}] {finding.rule_id}: {finding.description}'
                    f' (status={finding.status}, confidence={finding.confidence}){flag_text}'
                )
                if finding.actionable or finding.coverage_gap:
                    print(f'    Observed: {terminal_excerpt(finding.observed)}')
                if finding.severity in {'CRITICAL', 'HIGH'} and finding.expected:
                    print(f'    Expected: {terminal_excerpt(finding.expected)}')
                if finding.severity in {'CRITICAL', 'HIGH'} and finding.rationale:
                    print(f'    Rationale: {terminal_excerpt(finding.rationale)}')
                if finding.evidence_required:
                    print('    Evidence acquisition required: yes')
                if finding.aggregate:
                    print('    Aggregate finding: yes')
                if finding.blocked_by:
                    print(f"    Blocked by: {', '.join(finding.blocked_by)}")
                if finding.remediation_group:
                    print(f'    Remediation group: {finding.remediation_group}')
                if finding.evidence_items:
                    sources = ', '.join(sorted({
                        f'{item.source_type}/{item.trust_level}' for item in finding.evidence_items
                    }))
                    print(f'    Evidence source: {sources}')

    if args.show_passed:
        print_positive_checks(report)
    if args.show_trust_model:
        print_trust_model(report)
    if args.show_otp or args.otp_only:
        print_otp_summary(report)
    if args.secure_boot_evidence or args.otp_only:
        print_secure_boot_matrix(report)

    print_remediation_summary(report)
    print_gate_accounting(
        args.fail_on, policy_exit_code, gate_accounting, list(args.gate_exclude)
    )
    if runtime_issues:
        print(f"[-] Runtime issues: {', '.join(runtime_issues)}")
    print(f'[*] Process exit classification: {execution_classification}')
    print(f'[*] Process exit code: {final_exit_code}')
    return final_exit_code


def main() -> int:
    try:
        return run_audit()
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


if __name__ == "__main__":
    sys.exit(main())
