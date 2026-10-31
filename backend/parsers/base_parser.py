"""Abstract base parser interface."""
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseParser(ABC):
    @abstractmethod
    def parse_record(self, raw_data: Any) -> Dict[str, Any]:
        """Parse raw telemetry record into preliminary dictionary."""
        pass
