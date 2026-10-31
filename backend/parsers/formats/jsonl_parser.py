"""Line-delimited JSON parser."""
import json
from parsers.base_parser import BaseParser

class JSONLParser(BaseParser):
    def parse_record(self, raw_data):
        if isinstance(raw_data, str):
            return json.loads(raw_data.strip())
        return raw_data
