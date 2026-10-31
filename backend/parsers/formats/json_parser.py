"""JSON log parser."""
import json
from parsers.base_parser import BaseParser

class JSONParser(BaseParser):
    def parse_record(self, raw_data):
        if isinstance(raw_data, str):
            return json.loads(raw_data)
        return raw_data
