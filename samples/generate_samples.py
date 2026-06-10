"""Generate realistic-but-synthetic sample artifacts for each module so the
pipeline can be demoed end-to-end with no real malware/captures.

  python samples/generate_samples.py
produces samples/generated/{beaconing.pcap, compromise.xml, fake_malware.bin}
"""
import struct
import time
from pathlib import Path

OUT = Path(__file__).parent / "generated"
OUT.mkdir(exist_ok=True)


# ---------------------------------------------------------------- PCAP --------
def _eth_ip_tcp(src_ip, dst_ip, sport, dport, payload=b"", flags=0x18):
    def ip_bytes(ip):
        return bytes(int(o) for o in ip.split("."))
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 1, 0, 64, 6, 0) + ip_bytes(src_ip) + ip_bytes(dst_ip)
    return eth + ip + tcp


def write_pcap():
    path = OUT / "beaconing.pcap"
    records = []
    base = time.time() - 3600
    # Normal-ish web traffic
    for i in range(20):
        records.append((base + i * 2, _eth_ip_tcp("192.168.1.50", "93.184.216.34", 50000 + i, 443, b"\x16\x03\x03" + b"x" * 40)))
    # Regular beaconing to a C2 every 30s (low jitter) -- should be flagged
    for i in range(15):
        records.append((base + i * 30, _eth_ip_tcp("192.168.1.50", "45.133.1.99", 51000, 8443, bytes((i * 37) % 256 for _ in range(600)))))
    # High-entropy exfil burst to one external host
    big = bytes((i * 73 + 11) % 256 for i in range(4000))
    for i in range(10):
        records.append((base + 1800 + i, _eth_ip_tcp("192.168.1.50", "45.133.1.99", 51500 + i, 4444, big)))
    # Port scan: one src hits many ports on a target
    for port in range(20, 60):
        records.append((base + 2000 + port * 0.1, _eth_ip_tcp("192.168.1.77", "192.168.1.10", 60000, port, b"", flags=0x02)))

    records.sort(key=lambda r: r[0])
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in records:
            sec = int(ts); usec = int((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
    print(f"wrote {path} ({len(records)} packets)")


# ---------------------------------------------------------------- EVTX/XML ----
def _evt(eid, ts, **data):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{eid}</EventID>
<TimeCreated SystemTime="{ts}"/><Computer>WORKSTATION-07</Computer></System>
<EventData>{fields}</EventData></Event>"""


def write_eventlog():
    path = OUT / "compromise.xml"
    events = []
    day = "2026-06-09T"
    # Brute force: many 4625 then a 4624 success for 'admin'
    for i in range(8):
        events.append(_evt(4625, f"{day}02:1{i}:00.000Z", TargetUserName="admin", IpAddress="45.133.1.99"))
    events.append(_evt(4624, f"{day}02:19:30.000Z", TargetUserName="admin", IpAddress="45.133.1.99", LogonType="10"))
    # Privilege escalation: create account + add to Administrators
    events.append(_evt(4720, f"{day}02:25:00.000Z", TargetUserName="svc_backup", SubjectUserName="admin"))
    events.append(_evt(4732, f"{day}02:26:00.000Z", TargetUserName="svc_backup", SubjectUserName="admin", GroupName="Administrators"))
    # New service + scheduled task (persistence)
    events.append(_evt(7045, f"{day}02:30:00.000Z", ServiceName="UpdaterSvc", SubjectUserName="svc_backup"))
    events.append(_evt(4698, f"{day}02:31:00.000Z", TaskName="\\Microsoft\\Windows\\Updater", SubjectUserName="svc_backup"))
    # Defender disabled
    events.append(_evt(5001, f"{day}02:33:00.000Z", SubjectUserName="svc_backup"))
    # Cover-up: clear the log
    events.append(_evt(1102, f"{day}02:40:00.000Z", SubjectUserName="svc_backup"))
    path.write_text(f"<Events>{''.join(events)}</Events>", encoding="utf-8")
    print(f"wrote {path} ({len(events)} events)")


# ---------------------------------------------------------------- Malware -----
def write_fake_malware():
    """A harmless file that *looks* suspicious to static analysis: MZ/PE header,
    high-entropy section, suspicious API strings, embedded C2 + wallet. It does
    NOT execute anything — it's just bytes designed to exercise the detector."""
    path = OUT / "fake_malware.bin"
    # Minimal-ish PE so the stdlib parser recognizes it
    mz = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    mz = mz.ljust(0x80, b"\x00")
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 2, int(time.time()), 0, 0, 0xE0, 0x102)
    opt = b"\x0b\x01" + b"\x00" * 222  # PE32 optional header (size 0xE0), unsigned
    def section(name, vsize, rawsize, rawptr):
        return name.ljust(8, b"\x00") + struct.pack("<IIII", vsize, 0x1000, rawsize, rawptr) + b"\x00" * 16
    headers = mz + pe_sig + coff + opt
    sect_table_off = len(headers)
    s1 = section(b".text", 0x1000, 0x400, 0x600)
    s2 = section(b".enc", 0x4000, 0x1000, 0xA00)
    headers = headers + s1 + s2
    # pad to .text
    body = headers.ljust(0x600, b"\x00")
    # .text: suspicious API strings + IOCs (plain ASCII so extractor finds them)
    text = (b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
            b"InternetOpenA\x00HttpSendRequestA\x00CryptEncrypt\x00FindFirstFileA\x00"
            b"DeleteFileA\x00http://45.133.1.99/gate.php\x00185.220.101.5\x00"
            b"evil-c2-domain.xyz\x00bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\x00"
            b"vssadmin delete shadows /all /quiet\x00wevtutil cl Security\x00"
            b"powershell -enc \x00HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00")
    body = body.ljust(0x600, b"\x00") + text
    body = body.ljust(0xA00, b"\x00")
    # .enc: high-entropy "packed" data
    enc = bytes((i * 167 + 13) % 256 for i in range(0x1000))
    body = body + enc
    path.write_bytes(body)
    print(f"wrote {path} ({len(body)} bytes)")


if __name__ == "__main__":
    write_pcap()
    write_eventlog()
    write_fake_malware()
    print("Done. Samples in", OUT)
