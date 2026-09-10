"""
Módulo de escáneres del Agente Inspector.
"""
from abc import ABC, abstractmethod
from typing import List
from inspector.models import Finding
from inspector.config import InspectorConfig


class BaseScanner(ABC):
    """Clase base para todos los escáneres de inspección."""

    name: str = "BaseScanner"
    description: str = "Scanner base"

    def __init__(self, config: InspectorConfig):
        self.config = config

    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Analiza un archivo individual y retorna una lista de hallazgos."""
        pass
