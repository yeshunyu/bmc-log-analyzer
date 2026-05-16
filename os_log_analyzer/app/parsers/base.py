from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class LogLine:
    raw: str
    timestamp: str
    hostname: str = ""
    program: str = ""
    pid: str = ""
    message: str = ""

class BaseParser(ABC):
    name: str = ""

    @abstractmethod
    def detect(self, content: str) -> bool:
        """Return True if content matches this parser's format."""
        pass

    @abstractmethod
    def parse(self, content: str) -> list[LogLine]:
        """Parse content and return list of LogLine."""
        pass

    def parse_lines(self, content: str) -> list[LogLine]:
        """Default implementation splits by newline."""
        return [LogLine(raw=l, timestamp="", message=l) for l in content.splitlines() if l.strip()]
