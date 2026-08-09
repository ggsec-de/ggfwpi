"""Extracted GGFW component: engines.pi5_policy."""
from ggfw._compat import Dict
from ggfw.models.findings import Finding
from ggfw.models.report import GGFWReport

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
