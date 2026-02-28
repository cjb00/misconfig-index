from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List
from abc import ABC, abstractmethod


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@dataclass
class Finding:
    rule_id: str
    line_start: int | None
    line_end: int | None
    snippet: str
    extra: dict[str, Any] = field(default_factory=dict)


class Rule(ABC):
    id: str
    category: str
    title: str
    description: str
    severity: Severity
    tags: List[str]
    remediation: str = ""   # one-line fix hint shown in CLI and JSON output

    @abstractmethod
    def match(self, content: str, filename: str) -> List[Finding]:
        """
        Evaluate content and return findings for this rule.
        """

    def __repr__(self) -> str:  # helpful for debug output
        return f"<Rule id={self.id} severity={self.severity}>"
