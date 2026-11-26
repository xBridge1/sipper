"""Generate the synthetic part of the regression corpus.

Each scenario is a small capture whose correct verdict is known by
construction. Run ``python -m tests.corpus.generate_corpus`` after changing
a scenario; real captures go through ``tests/corpus/record.py`` instead.
"""

from pathlib import Path

from scapy.utils import wrpcap

from tests.corpus.record import record
from tests.test_culprit_precision import EXTENSION, _leg_b_invite
from tests.test_rtp import make_rtp_packet
from tests.test_sip_header_hygiene import CALLER, PBX, _invite, _packet, _response

SYNTHETIC = Path(__file__).resolve().parent / "synthetic"
FREESWITCH = {"target_platform": "freeswitch", "target_platform_ips": PBX}
OK_CONTACT = b"Contact: <sip:1000@10.0.0.20>\r\n"


def _ack(call_id):
    return (
        b"ACK sip:1000@10.0.0.20 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-a\r\n"
        b"Max-Forwards: 70\r\nFrom: <sip:alice@198.51.100.10>;tag=from1\r\nTo: <sip:1000@10.0.0.20>;tag=to1\r\n"
        b"Call-ID: " + call_id.encode() + b"\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
    )


def _rtp(source, destination, sport, dport, ssrc, start, count=150, payload=b"\x00" * 160):
    packets = []
    for sequence in range(1, count + 1):
        packet = make_rtp_packet(source, destination, sport, dport, sequence, 160 * sequence, ssrc, payload=payload)
        packet.time = start + sequence * 0.02
        packets.append(packet)
    return packets


def scenarios():
    yield "duplicate_header_400", FREESWITCH, [
        _packet(_invite(call_id="dup", extra=b"Call-ID: dup-copy\r\n"), timestamp=1.0),
        _packet(_response(400, b"Bad Request", call_id="dup"), PBX, CALLER, 1.05),
    ]
    yield "leg_b_busy", FREESWITCH, [
        _packet(_invite(call_id="leg-a"), timestamp=1.0),
        _packet(_leg_b_invite(), PBX, EXTENSION, 1.1),
        _packet(_response(486, b"Busy Here", call_id="leg-b"), EXTENSION, PBX, 2.0),
        _packet(_response(486, b"Busy Here", call_id="leg-a"), PBX, CALLER, 2.05),
    ]
    yield "codec_488", {**FREESWITCH, "freeswitch_codecs": "G722"}, [
        _packet(_invite(call_id="codec"), timestamp=1.0),
        _packet(_response(488, b"Not Acceptable Here", call_id="codec"), PBX, CALLER, 1.1),
    ]
    yield "clean_call", FREESWITCH, [
        _packet(_invite(call_id="clean"), timestamp=1.0),
        _packet(_response(200, b"OK", call_id="clean", extra=OK_CONTACT), PBX, CALLER, 1.5),
        _packet(_ack("clean"), timestamp=1.6),
        *_rtp(CALLER, PBX, 4000, 20000, 11, 1.7),
        *_rtp(PBX, CALLER, 20000, 4000, 12, 1.7),
    ]
    yield "silent_caller", FREESWITCH, [
        _packet(_invite(call_id="mute"), timestamp=1.0),
        _packet(_response(200, b"OK", call_id="mute", extra=OK_CONTACT), PBX, CALLER, 1.5),
        _packet(_ack("mute"), timestamp=1.6),
        *_rtp(CALLER, PBX, 4000, 20000, 21, 1.7, payload=b"\xff" * 160),
        *_rtp(PBX, CALLER, 20000, 4000, 22, 1.7),
    ]


def main():
    SYNTHETIC.mkdir(parents=True, exist_ok=True)
    for name, overrides, packets in scenarios():
        pcap = SYNTHETIC / f"{name}.pcap"
        wrpcap(str(pcap), packets)
        print(record(pcap, overrides))


if __name__ == "__main__":
    main()
