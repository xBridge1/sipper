from dataclasses import dataclass, field


@dataclass
class Finding:
    type: str
    severity: str
    confidence: float

    source_ip: str
    destination_ip: str

    description: str

    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""