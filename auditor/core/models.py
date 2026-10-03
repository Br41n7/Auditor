from dataclasses import dataclass, asdict, field
from typing import Any
import hashlib

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    evidence: str
    recommendation: str
    url: str | None = None
    confidence: str = "medium"
    check_id: str = ""
    references: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.severity = self.severity.upper()
        self.confidence = self.confidence.lower()
        if not self.check_id:
            raw = f"{self.category}|{self.title}".encode()
            self.check_id = "AUD-" + hashlib.sha1(raw).hexdigest()[:8].upper()

    @property
    def fingerprint(self) -> str:
        raw = f"{self.check_id}|{self.url or ''}|{self.evidence}".encode()
        return hashlib.sha1(raw).hexdigest()[:16]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data
