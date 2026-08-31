from dataclasses import dataclass, field

@dataclass
class TCPFlow:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    packet_count: int = 0
    byte_count: int = 0

    first_timestamp: float | None = None
    last_timestamp: float | None = None

    syn_timestamp: float | None = None
    syn_ack_timestamp: float | None = None

    packets_forward: int = 0
    packets_reverse: int = 0

    syn: bool = False
    syn_ack: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False

    packets: list = field(default_factory=list)

    @property
    def established(self):
        return self.syn and self.syn_ack and self.ack

    @property
    def duration(self):
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0

        return self.last_timestamp - self.first_timestamp

    @property
    def handshake_time(self):
        if self.syn_timestamp is None or self.syn_ack_timestamp is None:
            return None

        return self.syn_ack_timestamp - self.syn_timestamp

@dataclass
class Finding:
    type: str
    severity: str
    confidence: float
    source_ip: str
    destination_ip: str
    description: str
    evidence: list[str]
    recommendation: str = ""

@dataclass
class UDPFlow:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    packet_count: int = 0
    byte_count: int = 0

    first_timestamp: float | None = None
    last_timestamp: float | None = None

    packets_forward: int = 0
    packets_reverse: int = 0

    packets: list = field(default_factory=list)

    @property
    def response_packets(self):
        return self.packets_reverse

    @property
    def duration(self):
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0

        return self.last_timestamp - self.first_timestamp
