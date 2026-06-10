"""Stage 1 (Network): raw PCAP -> packet records.

A dependency-free classic-pcap parser written with struct. Parses
Ethernet -> IPv4/IPv6 -> TCP/UDP, extracts DNS queries and TLS ClientHello
SNI directly from payload bytes. (pcapng files: convert first with
`tshark -F pcap -r in.pcapng -w out.pcap` — noted in README.)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1e-6),   # little-endian, microseconds
    0xD4C3B2A1: (">", 1e-6),
    0xA1B23C4D: ("<", 1e-9),   # nanosecond variant
    0x4D3CB2A1: (">", 1e-9),
}
PCAPNG_MAGIC = 0x0A0D0D0A


@dataclass
class Packet:
    ts: float
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "OTHER"        # TCP/UDP/ICMP/ARP/OTHER
    length: int = 0
    payload: bytes = b""
    tcp_flags: int = 0
    dns_queries: list[str] = field(default_factory=list)
    tls_sni: str = ""
    tls_version: str = ""


def parse_pcap(path: str, max_packets: int = 200_000) -> list[Packet]:
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise ValueError("File too small to be a PCAP")

    magic = struct.unpack("<I", data[:4])[0]
    if magic == PCAPNG_MAGIC or struct.unpack(">I", data[:4])[0] == PCAPNG_MAGIC:
        raise ValueError(
            "pcapng format detected. Convert with: tshark -F pcap -r file.pcapng -w file.pcap"
        )
    if magic not in PCAP_MAGICS:
        magic = struct.unpack(">I", data[:4])[0]
        if magic not in PCAP_MAGICS:
            raise ValueError("Not a PCAP file (bad magic number)")
    endian, ts_scale = PCAP_MAGICS[magic]

    packets: list[Packet] = []
    offset = 24  # skip global header
    while offset + 16 <= len(data) and len(packets) < max_packets:
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16
        frame = data[offset:offset + incl_len]
        offset += incl_len
        if len(frame) < incl_len:
            break
        pkt = _parse_ethernet(frame, ts_sec + ts_frac * ts_scale, orig_len)
        if pkt:
            packets.append(pkt)
    return packets


def _parse_ethernet(frame: bytes, ts: float, orig_len: int) -> Packet | None:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    pkt = Packet(ts=ts, length=orig_len)
    if ethertype == 0x0806:
        pkt.protocol = "ARP"
        return pkt
    if ethertype == 0x0800:
        return _parse_ipv4(frame[14:], pkt)
    if ethertype == 0x86DD:
        return _parse_ipv6(frame[14:], pkt)
    return pkt


def _parse_ipv4(buf: bytes, pkt: Packet) -> Packet | None:
    if len(buf) < 20:
        return None
    ihl = (buf[0] & 0x0F) * 4
    proto = buf[9]
    pkt.src_ip = ".".join(str(b) for b in buf[12:16])
    pkt.dst_ip = ".".join(str(b) for b in buf[16:20])
    return _parse_l4(buf[ihl:], proto, pkt)


def _parse_ipv6(buf: bytes, pkt: Packet) -> Packet | None:
    if len(buf) < 40:
        return None
    proto = buf[6]
    pkt.src_ip = _fmt_v6(buf[8:24])
    pkt.dst_ip = _fmt_v6(buf[24:40])
    return _parse_l4(buf[40:], proto, pkt)


def _fmt_v6(raw: bytes) -> str:
    return ":".join(f"{struct.unpack('>H', raw[i:i+2])[0]:x}" for i in range(0, 16, 2))


def _parse_l4(buf: bytes, proto: int, pkt: Packet) -> Packet:
    if proto == 6 and len(buf) >= 20:          # TCP
        pkt.protocol = "TCP"
        pkt.src_port, pkt.dst_port = struct.unpack(">HH", buf[:4])
        data_offset = (buf[12] >> 4) * 4
        pkt.tcp_flags = buf[13]
        pkt.payload = buf[data_offset:]
        _inspect_tls(pkt)
    elif proto == 17 and len(buf) >= 8:        # UDP
        pkt.protocol = "UDP"
        pkt.src_port, pkt.dst_port = struct.unpack(">HH", buf[:4])
        pkt.payload = buf[8:]
        if 53 in (pkt.src_port, pkt.dst_port):
            _inspect_dns(pkt)
    elif proto == 1:
        pkt.protocol = "ICMP"
    return pkt


def _inspect_dns(pkt: Packet) -> None:
    """Extract query names from a DNS message."""
    buf = pkt.payload
    if len(buf) < 12:
        return
    qdcount = struct.unpack(">H", buf[4:6])[0]
    offset = 12
    for _ in range(min(qdcount, 10)):
        labels = []
        while offset < len(buf):
            ln = buf[offset]
            if ln == 0:
                offset += 1
                break
            if ln & 0xC0:  # compression pointer — stop
                offset += 2
                break
            labels.append(buf[offset + 1:offset + 1 + ln].decode("ascii", "replace"))
            offset += 1 + ln
        offset += 4  # qtype + qclass
        if labels:
            pkt.dns_queries.append(".".join(labels))


TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def _inspect_tls(pkt: Packet) -> None:
    """Detect a TLS ClientHello and pull out version + SNI."""
    buf = pkt.payload
    # TLS record: type(1)=22 handshake, version(2), length(2); handshake type(1)=1 ClientHello
    if len(buf) < 44 or buf[0] != 0x16 or buf[5] != 0x01:
        return
    record_version = struct.unpack(">H", buf[1:3])[0]
    pkt.tls_version = TLS_VERSIONS.get(record_version, f"0x{record_version:04x}")
    try:
        off = 9          # record(5) + handshake type(1) + length(3)
        off += 2 + 32    # client_version + random
        sid_len = buf[off]; off += 1 + sid_len
        cs_len = struct.unpack(">H", buf[off:off + 2])[0]; off += 2 + cs_len
        comp_len = buf[off]; off += 1 + comp_len
        ext_total = struct.unpack(">H", buf[off:off + 2])[0]; off += 2
        end = min(off + ext_total, len(buf))
        while off + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", buf[off:off + 4]); off += 4
            if ext_type == 0:  # server_name
                name_len = struct.unpack(">H", buf[off + 3:off + 5])[0]
                pkt.tls_sni = buf[off + 5:off + 5 + name_len].decode("ascii", "replace")
                # Use the supported_versions ext if present for true 1.3 detection
            off += ext_len
    except (struct.error, IndexError):
        pass
