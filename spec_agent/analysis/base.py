from typing import Protocol
from pathlib import Path
from ..models import ProgramModel
class ProgramAnalyzer(Protocol):
    def analyze(self, sources: list[Path]) -> ProgramModel: ...
