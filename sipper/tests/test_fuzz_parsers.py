"""Property-based robustness: no input may crash the parsers or the engine.

A malformed message must either parse (and be reported) or be ignored; it
must never raise, because one bad packet would hide the whole capture.
"""

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402

from ciper.engine import analyze_pcap  # noqa: E402
from ciper.rtp import parse_rtp_packet  # noqa: E402
from ciper.sip import parse_sip_message  # noqa: E402
from tests.test_sip_header_hygiene import _invite, _response  # noqa: E402

# derandomize keeps CI reproducible; raise max_examples locally to hunt harder.
FUZZ = settings(max_examples=150, deadline=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])
SEEDS = [_invite(call_id="fuzz"), _response(200, b"OK", call_id="fuzz"), _response(486, b"Busy Here", call_id="fuzz")]
INTERESTING = [b"\r\n", b"\n", b":", b";", b"<", b">", b'"', b"\x00", b"\xff", b"${", b"%", b" ", b"Call-ID: x\r\n", b"SIP/2.0"]


@st.composite
def mutated_sip(draw):
    data = bytearray(draw(st.sampled_from(SEEDS)))
    for _ in range(draw(st.integers(0, 8))):
        operation = draw(st.integers(0, 3))
        position = draw(st.integers(0, max(0, len(data) - 1)))
        if operation == 0 and data:
            del data[position:position + draw(st.integers(1, 20))]
        elif operation == 1:
            data[position:position] = draw(st.sampled_from(INTERESTING))
        elif operation == 2 and data:
            data[position] = draw(st.integers(0, 255))
        else:
            data[position:position] = draw(st.binary(max_size=30))
    return bytes(data)


def _udp(payload, sport=5060, dport=5060):
    return IP(src="198.51.100.10", dst="10.0.0.20") / UDP(sport=sport, dport=dport) / payload


@FUZZ
@given(mutated_sip())
def test_mutated_sip_never_crashes_the_parser(payload):
    message = parse_sip_message(_udp(payload))
    if message is not None:
        assert message.call_id


@FUZZ
@given(st.binary(max_size=400))
def test_random_bytes_never_crash_sip_or_rtp_parsers(payload):
    parse_sip_message(_udp(payload))
    parse_rtp_packet(_udp(payload, 30000, 30002))


@settings(max_examples=40, deadline=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(mutated_sip(), min_size=1, max_size=6), st.booleans())
def test_mutated_dialogs_never_crash_the_engine(payloads, over_tcp):
    packets = []
    for index, payload in enumerate(payloads):
        if over_tcp:
            packet = IP(src="198.51.100.10", dst="10.0.0.20") / TCP(sport=5060, dport=5060, flags="PA", seq=1 + index * 2000) / payload
        else:
            packet = _udp(payload)
        packet.time = 1.0 + index * 0.1
        packets.append(packet)
    result = analyze_pcap(packets)
    assert "diagnosis" in result
