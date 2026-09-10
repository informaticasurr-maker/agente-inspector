"""
Modelos de datos para el Agente Inspector.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order.get(self, 0)

    @property
    def color(self) -> str:
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
        }
        return colors.get(self, "white")

    @property
    def badge(self) -> str:
        badges = {
            Severity.CRITICAL: "🚨 CRÍTICO",
            Severity.HIGH: "⚠️ ALTO",
            Severity.MEDIUM: "⚡ MEDIO",
            Severity.LOW: "ℹ️ BAJO",
            Severity.INFO: "🔍 INFO",
        }
        return badges.get(self, self.value)


class Category(str, Enum):
    SECRETS = "SECRETS"
    SECURITY = "SECURITY"
    QUALITY = "QUALITY"
    PERFORMANCE = "PERFORMANCE"
    ARCHITECTURE = "ARCHITECTURE"


@dataclass
class Finding:
    """Representa un hallazgo o problema detectado durante la inspección."""
    id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    snippet: Optional[str] = None
    suggestion: Optional[str] = None
    rule_id: Optional[str] = None
    auto_fixable: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InspectionSummary:
    """Resumen consolidado de la ejecución de inspección."""
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    scanners_executed: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def has_critical_or_high(self) -> bool:
        return (self.critical_count + self.high_count) > 0

    @property
    def score(self) -> float:
        """Puntuación de salud del código de 0 a 100."""
        if self.total_files_scanned == 0:
            return 100.0
        penalty = (
            self.critical_count * 25.0 +
            self.high_count * 10.0 +
            self.medium_count * 3.0 +
            self.low_count * 1.0
        )
        return max(0.0, round(100.0 - penalty, 1))
