"""CSV row log parser."""
from parsers.base_parser import BaseParser

class CSVParser(BaseParser):
    def __init__(self, headers=None):
        self.headers = headers

    def parse_record(self, raw_data):
        if isinstance(raw_data, dict):
            return raw_data
        return dict(zip(self.headers, raw_data))
