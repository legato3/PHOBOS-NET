from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class TimelineEvent:
    ts: int
    type: str
    severity: str
    title: str
    detail: Optional[str]
    source: str
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "meta": self.meta or {},
        }
