"""Extracted GGFW component: models.findings."""
from ggfw._compat import (
    Any, Dict, List, Optional, Tuple, dataclass, field,
)
from ggfw.models.evidence import EvidenceRecord

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
