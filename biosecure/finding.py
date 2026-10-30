
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class SecurityFinding:
    """
    Standard structure for storing a security finding.
    """

    module: str
    severity: str
    title: str
    file: str
    description: str
    recommendation: str

    line: Optional[int] = None
    confidence: str = "MEDIUM"

    def to_dict(self):
        """
        Convert the finding into a dictionary.
        """
        return asdict(self)
