"""Generate a large synthetic VoIP capture for performance benchmarking.

Usage:
    python tests/pcaps/generate_benchmark_pcap.py OUTPUT.pcap [--calls N] [--seconds S]

The capture contains N SIP/UDP calls (INVITE/100/180/200/ACK/BYE/200) with
bidirectional G.711 RTP at 50 packets per second, some packet loss, a few
failed calls, TCP connections and ICMP echo traffic. Packets are written with
struct directly so generating hundreds of thousands of packets is fast.
"""

import argparse
import random
import struct
from pathlib import Path

ETH_HEADER = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ip_bytes(ip):
    return bytes(int(part) for part in ip.split("."))


def _ipv4(src, dst, proto, payload):
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, _ip_bytes(src), _ip_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def udp_frame(src, sport, dst, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ETH_HEADER + _ipv4(src, dst, 17, udp)


def tcp_frame(src, sport, dst, dport, flags, seq, ack, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return ETH_HEADER + _ipv4(src, dst, 6, tcp)


def icmp_frame(src, dst, icmp_type, ident, seq):
    body = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq) + b"x" * 32
    body = body[:2] + struct.pack("!H", _checksum(body)) + body[4:]
    return ETH_HEADER + _ipv4(src, dst, 1, body)


def sip_message(start_line, call_id, cseq, method, from_tag, to_tag, src, sport, dst, body=""):
    to_header = f"<sip:2000@{dst}>" + (f";tag={to_tag}" if to_tag else "")
    lines = [
        start_line,
        f"Via: SIP/2.0/UDP {src}:{sport};branch=z9hG4bK{call_id[:8]}{cseq}",
        f"From: <sip:1000@{src}>;tag={from_tag}",
        f"To: {to_header}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        f"Contact: <sip:1000@{src}:{sport}>",
        "Max-Forwards: 70",
        "User-Agent: SIPPER-Benchmark",
    ]
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("ascii")


def sdp_body(ip, port):
    return (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {ip}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=sendrecv\r\n"
    )


def rtp_payload(seq, timestamp, ssrc):
    return struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc) + b"\xff" * 160


def generate(calls, seconds, seed=7):
    rng = random.Random(seed)
    frames = []
    base = 1_700_000_000.0
    proxy = "10.0.0.1"

    for index in range(calls):
        caller = f"10.1.{index // 250}.{index % 250 + 2}"
        call_id = f"bench-{index:05d}@{caller}"
        start = base + index * 0.5
        caller_rtp = 20000 + index * 2
        callee_rtp = 40000 + index * 2
        failed = index % 25 == 24

        def sip(at, src, dst, line, cseq, method, to_tag, body=""):
            sport = 5060
            frames.append((at, udp_frame(src, sport, dst, 5060, sip_message(
                line, call_id, cseq, method, "f" + str(index), to_tag, src, sport, dst, body,
            ))))

        sip(start, caller, proxy, f"INVITE sip:2000@{proxy} SIP/2.0", 1, "INVITE", None, sdp_body(caller, caller_rtp))
        sip(start + 0.01, proxy, caller, "SIP/2.0 100 Trying", 1, "INVITE", None)
        if failed:
            sip(start + 0.5, proxy, caller, "SIP/2.0 486 Busy Here", 1, "INVITE", "t" + str(index))
            sip(start + 0.51, caller, proxy, f"ACK sip:2000@{proxy} SIP/2.0", 1, "ACK", "t" + str(index))
            continue
        sip(start + 0.2, proxy, caller, "SIP/2.0 180 Ringing", 1, "INVITE", "t" + str(index))
        sip(start + 1.0, proxy, caller, "SIP/2.0 200 OK", 1, "INVITE", "t" + str(index), sdp_body(proxy, callee_rtp))
        sip(start + 1.01, caller, proxy, f"ACK sip:2000@{proxy} SIP/2.0", 1, "ACK", "t" + str(index))

        media_start = start + 1.05
        packets = int(seconds * 50)
        loss = 0.03 if index % 10 == 3 else 0.001
        one_way = index % 40 == 17
        for direction in (0, 1):
            if direction == 1 and one_way:
                continue
            src, sport, dst, dport = (
                (caller, caller_rtp, proxy, callee_rtp) if direction == 0
                else (proxy, callee_rtp, caller, caller_rtp)
            )
            ssrc = 0x10000000 + index * 2 + direction
            for seq in range(packets):
                if rng.random() < loss:
                    continue
                at = media_start + seq * 0.02 + rng.uniform(0, 0.004) + direction * 0.001
                frames.append((at, udp_frame(src, sport, dst, dport, rtp_payload(seq, seq * 160, ssrc))))

        end = media_start + seconds + 0.1
        sip(end, caller, proxy, f"BYE sip:2000@{proxy} SIP/2.0", 2, "BYE", "t" + str(index))
        sip(end + 0.02, proxy, caller, "SIP/2.0 200 OK", 2, "BYE", "t" + str(index))

    for index in range(calls * 2):
        client = f"10.2.{index // 250}.{index % 250 + 2}"
        at = base + index * 0.3
        port = 30000 + index
        seq = rng.randrange(1, 2**31)
        frames.append((at, tcp_frame(client, port, "10.0.0.80", 443, 0x02, seq, 0)))
        if index % 15 == 0:
            continue
        frames.append((at + 0.02, tcp_frame("10.0.0.80", 443, client, port, 0x12, 9000, seq + 1)))
        frames.append((at + 0.03, tcp_frame(client, port, "10.0.0.80", 443, 0x10, seq + 1, 9001)))
        for chunk in range(5):
            frames.append((at + 0.04 + chunk * 0.01, tcp_frame(
                client, port, "10.0.0.80", 443, 0x18, seq + 1 + chunk * 100, 9001, b"d" * 100,
            )))
        frames.append((at + 0.2, tcp_frame(client, port, "10.0.0.80", 443, 0x11, seq + 501, 9001)))

    for index in range(calls):
        at = base + index
        frames.append((at, icmp_frame("10.3.0.2", "10.0.0.9", 8, 1, index)))
        if index % 7:
            frames.append((at + 0.01, icmp_frame("10.0.0.9", "10.3.0.2", 0, 1, index)))

    frames.sort(key=lambda item: item[0])
    return frames


def write_pcap(path, frames):
    with open(path, "wb") as output:
        output.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for at, frame in frames:
            seconds = int(at)
            micros = int(round((at - seconds) * 1_000_000))
            if micros >= 1_000_000:
                seconds, micros = seconds + 1, micros - 1_000_000
            output.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            output.write(frame)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--calls", type=int, default=100)
    parser.add_argument("--seconds", type=float, default=30)
    args = parser.parse_args()
    frames = generate(args.calls, args.seconds)
    write_pcap(args.output, frames)
    print(f"{len(frames)} packets written to {args.output}")


if __name__ == "__main__":
    main()
