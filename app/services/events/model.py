from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EventRecord:
    id: str
    ts: int
    source: str
    severity: str
    title: str
    summary: str
    tags: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    rule_id: Optional[str] = None
    dedupe_key: Optional[str] = None
    window_sec: Optional[int] = None
    count: int = 1
    kind: str = "activity"  # activity | notable
    primary_entity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "tags": self.tags,
            "evidence": self.evidence,
            "rule_id": self.rule_id,
            "dedupe_key": self.dedupe_key,
            "window_sec": self.window_sec,
            "count": self.count,
            "kind": self.kind,
            "primary_entity": self.primary_entity,
        }
