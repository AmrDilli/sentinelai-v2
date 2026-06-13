"""Stage 1 (Network): raw PCAP -> packet records.

A dependency-free classic-pcap parser written with struct. Parses
Ethernet -> IPv4/IPv6 -> TCP/UDP, extracts DNS queries and TLS ClientHello
SNI directly from payload bytes. (pcapng files: convert first with
`tshark -F pcap -r in.pcapng -w out.pcap` — noted in README.)
"""
from __future__ import annotations

import hashlib
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
    ja3: str = ""                  # JA3-style TLS client fingerprint (md5)
    http: dict = field(default_factory=dict)  # {method, host, uri, user_agent}


def iter_pcap(path: str, max_packets: int = 1_000_000):
    """Stream packets one at a time straight off disk — constant memory, so a
    multi-gigabyte capture never gets loaded into RAM. Yields Packet objects."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError("File too small to be a PCAP")
        magic = struct.unpack("<I", header[:4])[0]
        magic_be = struct.unpack(">I", header[:4])[0]
        if PCAPNG_MAGIC in (magic, magic_be):
            raise ValueError(
                "pcapng format detected. Convert with: tshark -F pcap -r file.pcapng -w file.pcap"
            )
        if magic in PCAP_MAGICS:
            endian, ts_scale = PCAP_MAGICS[magic]
        elif magic_be in PCAP_MAGICS:
            endian, ts_scale = PCAP_MAGICS[magic_be]
        else:
            raise ValueError("Not a PCAP file (bad magic number)")

        count = 0
        while count < max_packets:
            rec_header = fh.read(16)
            if len(rec_header) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec_header)
            if incl_len > 262144:  # guard against corrupt length fields
                fh.seek(incl_len, 1)
                continue
            frame = fh.read(incl_len)
            if len(frame) < incl_len:
                break
            pkt = _parse_ethernet(frame, ts_sec + ts_frac * ts_scale, orig_len)
            if pkt:
                count += 1
                yield pkt


def parse_pcap(path: str, max_packets: int = 1_000_000) -> list[Packet]:
    """Convenience wrapper that materializes the stream into a list."""
    return list(iter_pcap(path, max_packets))


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
        _inspect_http(pkt)
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
# GREASE values (RFC 8701) are excluded from JA3 like the reference implementation.
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
_HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC", b"CONN", b"TRAC")


def _inspect_tls(pkt: Packet) -> None:
    """Detect a TLS ClientHello; extract version + SNI and compute a JA3
    fingerprint (md5 of version,ciphers,extensions,curves,point-formats)."""
    buf = pkt.payload
    if len(buf) < 44 or buf[0] != 0x16 or buf[5] != 0x01:
        return
    record_version = struct.unpack(">H", buf[1:3])[0]
    pkt.tls_version = TLS_VERSIONS.get(record_version, f"0x{record_version:04x}")
    try:
        off = 9
        client_version = struct.unpack(">H", buf[off:off + 2])[0]
        off += 2 + 32    # client_version + random
        sid_len = buf[off]; off += 1 + sid_len

        cs_len = struct.unpack(">H", buf[off:off + 2])[0]; off += 2
        ciphers = [struct.unpack(">H", buf[off + i:off + i + 2])[0] for i in range(0, cs_len, 2)]
        off += cs_len

        comp_len = buf[off]; off += 1 + comp_len

        ext_list, curves, ec_formats = [], [], []
        if off + 2 <= len(buf):
            ext_total = struct.unpack(">H", buf[off:off + 2])[0]; off += 2
            end = min(off + ext_total, len(buf))
            while off + 4 <= end:
                ext_type, ext_len = struct.unpack(">HH", buf[off:off + 4]); off += 4
                body = buf[off:off + ext_len]
                ext_list.append(ext_type)
                if ext_type == 0 and len(body) >= 5:  # SNI
                    name_len = struct.unpack(">H", body[3:5])[0]
                    pkt.tls_sni = body[5:5 + name_len].decode("ascii", "replace")
                elif ext_type == 10 and len(body) >= 2:  # supported_groups (curves)
                    n = struct.unpack(">H", body[:2])[0]
                    curves = [struct.unpack(">H", body[2 + i:4 + i])[0] for i in range(0, n, 2)]
                elif ext_type == 11 and len(body) >= 1:  # ec_point_formats
                    ec_formats = list(body[1:1 + body[0]])
                off += ext_len

        def _join(xs):
            return "-".join(str(x) for x in xs if x not in _GREASE)
        ja3_str = "{},{},{},{},{}".format(
            client_version, _join(ciphers), _join(ext_list), _join(curves), _join(ec_formats))
        pkt.ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
    except (struct.error, IndexError):
        pass


def _inspect_http(pkt: Packet) -> None:
    """Parse a cleartext HTTP request line + key headers from the payload."""
    buf = pkt.payload
    if len(buf) < 16 or buf[:4] not in _HTTP_METHODS:
        return
    try:
        head = buf[:2048].split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        request = lines[0].split(" ")
        if len(request) < 2:
            return
        info = {"method": request[0], "uri": request[1], "host": "", "user_agent": ""}
        for line in lines[1:]:
            low = line.lower()
            if low.startswith("host:"):
                info["host"] = line[5:].strip()
            elif low.startswith("user-agent:"):
                info["user_agent"] = line[11:].strip()
        pkt.http = info
    except (UnicodeDecodeError, IndexError):
        pass
