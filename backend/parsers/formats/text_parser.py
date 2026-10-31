"""Syslog and regex text log parser."""
import re
from parsers.base_parser import BaseParser

class TextParser(BaseParser):
    def __init__(self, regex_pattern: str):
        self.regex = re.compile(regex_pattern)

    def parse_record(self, raw_data):
        match = self.regex.match(str(raw_data).strip())
        return match.groupdict() if match else {"raw": str(raw_data)}
