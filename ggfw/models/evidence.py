"""Extracted GGFW component: models.evidence."""
from ggfw._compat import (
    Any, Dict, asdict, dataclass, field,
)

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
