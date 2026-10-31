"""Parser registry — routes source_type to the correct parser + adapter pair."""

from typing import Tuple, Any
from parsers.formats.text_parser    import TextParser
from parsers.formats.jsonl_parser   import JSONLParser
from parsers.adapters.network_adapter   import NetworkAdapter
from parsers.adapters.endpoint_adapter  import EndpointAdapter
from parsers.base_parser import BaseParser


class ParserRegistry:
    """Maps source_type strings to (parser, adapter) pairs.

    Supported source_type values:
        'firewall' → TextParser + NetworkAdapter
        'windows'  → JSONLParser + EndpointAdapter

    Usage:
        registry = ParserRegistry()
        parser, adapter = registry.get("firewall")
        parsed  = parser.parse_record(raw_line)
        adapted = adapter.adapt(parsed)
    """

    def __init__(self):
        # Each entry: source_type → (parser_instance, adapter_instance)
        # Instances are created once and reused — they are stateless.
        self._registry = {
            "firewall": (TextParser(),    NetworkAdapter()),
            "windows" : (JSONLParser(),   EndpointAdapter()),
        }

    def get(self, source_type: str) -> Tuple[BaseParser, Any]:
        """Return (parser, adapter) for the given source_type.

        Raises:
            KeyError if source_type is not registered.
        """
        if source_type not in self._registry:
            raise KeyError(
                f"No parser registered for source_type={source_type!r}. "
                f"Available: {list(self._registry.keys())}"
            )
        return self._registry[source_type]

    def supported_types(self):
        return list(self._registry.keys())
