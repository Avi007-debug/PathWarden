"""Registry mapping format IDs to parser instances."""
from typing import Dict, Type
from parsers.base_parser import BaseParser

class ParserRegistry:
    def __init__(self):
        self._registry: Dict[str, BaseParser] = {}

    def register(self, format_name: str, parser_instance: BaseParser):
        self._registry[format_name] = parser_instance

    def get(self, format_name: str) -> BaseParser:
        return self._registry.get(format_name)
