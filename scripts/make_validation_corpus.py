"""Generate a LABELED benign+malicious corpus for detection validation.

  python scripts/make_validation_corpus.py

Writes samples to samples/validation/ and a manifest.json mapping each file to
its ground-truth label (malicious | benign) and module. The benign samples are
deliberately ordinary (normal browsing, normal logons, clean files) so the
validator can measure the false-positive rate, which is the meaningful signal.

This is a SYNTHETIC corpus — it demonstrates the methodology and the engine's
behaviour on clean vs. attack inputs. It is not a claim of real-world efficacy;
for that, point scripts/validate.py at a labeled public dataset (see README).
"""
import json
import random
import struct
import time
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "validation"
OUT.mkdir(parents=True, exist_ok=True)
MANIFEST = []


# ---- packet / pcap helpers -------------------------------------------------
def _ipb(ip):
    return bytes(int(o) for o in ip.split("."))


def _tcp(src, dst, sport, dport, payload=b"", flags=0x18):
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) + _ipb(src) + _ipb(dst)
    return eth + ip + tcp


def _udp(src, dst, sport, dport, payload=b""):
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0) + _ipb(src) + _ipb(dst)
    return eth + ip + udp


def _dns(name):
    q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00\x00\x01\x00\x01"


def write_pcap(name, records, label):
    path = OUT / name
    records.sort(key=lambda r: r[0])
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in records:
            sec = int(ts); usec = int((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)
    MANIFEST.append({"file": name, "label": label, "module": "network"})


# ---- event-log helpers -----------------------------------------------------
def _evt(eid, ts, **data):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{ts}"/><Computer>WS-{eid % 90 + 10}</Computer></System>'
            f'<EventData>{fields}</EventData></Event>')


def write_evtx(name, events, label):
    (OUT / name).write_text(f"<Events>{''.join(events)}</Events>", encoding="utf-8")
    MANIFEST.append({"file": name, "label": label, "module": "forensics"})


# ---- PE / file helpers -----------------------------------------------------
def _pe(text_bytes, enc_bytes):
    mz = (b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)).ljust(0x80, b"\x00")
    coff = struct.pack("<HHIIIHH", 0x14C, 2, int(time.time()), 0, 0, 0xE0, 0x102)
    opt = b"\x0b\x01" + b"\x00" * 222
    def section(n, rawsize, rawptr):
        return n.ljust(8, b"\x00") + struct.pack("<IIII", 0x1000, 0x1000, rawsize, rawptr) + b"\x00" * 16
    headers = mz + b"PE\x00\x00" + coff + opt
    headers += section(b".text", 0x400, 0x600) + section(b".data", 0x1000, 0xA00)
    body = headers.ljust(0x600, b"\x00") + text_bytes
    body = body.ljust(0xA00, b"\x00") + enc_bytes
    return body


def write_file(name, data, label):
    (OUT / name).write_bytes(data)
    MANIFEST.append({"file": name, "label": label, "module": "malware"})


# ===========================================================================
#  MALICIOUS samples
# ===========================================================================
def malicious():
    base = time.time() - 3600
    # 3 beaconing variants (different intervals) + exfil + scan + tunneling
    for n, (iv, dst) in enumerate([(30, "203.0.113.10"), (60, "198.51.100.7"), (120, "203.0.113.44")]):
        recs = []
        for i in range(12):
            recs.append((base + i * iv, _tcp("192.168.1.50", dst, 51000, 8443,
                         bytes((i * 37) % 256 for _ in range(600)))))
        big = bytes((i * 73 + 11) % 256 for i in range(4000))
        for i in range(8):
            recs.append((base + 1500 + i, _tcp("192.168.1.50", dst, 51500 + i, 4444, big)))
        write_pcap(f"mal_beacon_{n}.pcap", recs, "malicious")
    # port scan
    recs = [(base + p * 0.1, _tcp("192.168.1.77", "192.168.1.10", 60000, p, b"", flags=0x02))
            for p in range(20, 70)]
    write_pcap("mal_portscan.pcap", recs, "malicious")
    # dns tunneling
    r = random.Random(7); recs = []
    for i in range(40):
        sub = "".join(r.choice("abcdef0123456789") for _ in range(28))
        recs.append((base + i, _udp("192.168.1.50", "8.8.8.8", 40000 + i, 53, _dns(f"{sub}.data-x.net"))))
    write_pcap("mal_dnstunnel.pcap", recs, "malicious")

    # forensics: brute-force+escalation+clear, password spray, rdp lateral
    d = "2026-06-09T"
    e = [_evt(4625, f"{d}02:1{i}:00.000Z", TargetUserName="admin", IpAddress="45.133.1.99") for i in range(8)]
    e += [_evt(4624, f"{d}02:19:30.000Z", TargetUserName="admin", IpAddress="45.133.1.99", LogonType="10"),
          _evt(4720, f"{d}02:25:00.000Z", TargetUserName="svc_bk", SubjectUserName="admin"),
          _evt(4732, f"{d}02:26:00.000Z", TargetUserName="svc_bk", GroupName="Administrators"),
          _evt(1102, f"{d}02:40:00.000Z", SubjectUserName="svc_bk")]
    write_evtx("mal_bruteforce.xml", e, "malicious")
    spray = [_evt(4625, f"{d}03:0{i}:00.000Z", TargetUserName=f"user{i}", IpAddress="45.133.1.99") for i in range(9)]
    write_evtx("mal_spray.xml", spray, "malicious")
    # External RDP access (the pattern this detector targets) + explicit creds
    rdp = ([_evt(4624, f"{d}04:0{i}:00.000Z", TargetUserName="admin", IpAddress=f"45.133.1.{99 - i}", LogonType="10") for i in range(6)]
           + [_evt(4648, f"{d}04:10:00.000Z", TargetUserName="admin", SubjectUserName="admin")])
    write_evtx("mal_rdp_external.xml", rdp, "malicious")

    # malware: packed PE w/ suspicious APIs + IOCs (3 capability variants)
    ioc = (b"http://45.133.1.99/gate.php\x00185.220.101.5\x00evil-c2-domain.xyz\x00"
           b"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\x00")
    hi = bytes((i * 167 + 13) % 256 for i in range(0x1000))
    write_file("mal_injector.bin", _pe(b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
               b"InternetOpenA\x00HttpSendRequestA\x00" + ioc, hi), "malicious")
    write_file("mal_ransom.bin", _pe(b"CryptEncrypt\x00FindFirstFileA\x00DeleteFileA\x00"
               b"vssadmin delete shadows /all /quiet\x00wevtutil cl Security\x00" + ioc, hi), "malicious")
    write_file("mal_keylogger.bin", _pe(b"SetWindowsHookExA\x00GetAsyncKeyState\x00GetForegroundWindow\x00"
               b"InternetOpenA\x00HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00" + ioc, hi), "malicious")


# ===========================================================================
#  BENIGN samples (ordinary activity — should NOT alarm)
# ===========================================================================
def benign():
    base = time.time() - 3600
    cdns = ["142.250.190.78", "13.107.42.14", "151.101.0.81", "140.82.121.4"]
    doms = ["google.com", "microsoft.com", "github.com", "cloudflare.com"]
    for n in range(4):
        rr = random.Random(100 + n); recs = []
        for i in range(28):
            dst = rr.choice(cdns)
            recs.append((base + i * rr.uniform(2, 40),  # irregular timing = high jitter
                         _tcp("192.168.1.50", dst, 50000 + i, 443, b"\x16\x03\x03" + bytes(rr.randrange(256) for _ in range(40)))))
        for i in range(6):
            recs.append((base + i * 5, _udp("192.168.1.50", "8.8.8.8", 40000 + i, 53, _dns(rr.choice(doms)))))
        write_pcap(f"ben_browse_{n}.pcap", recs, "benign")

    d = "2026-06-09T"
    for n in range(3):
        e = [_evt(4624, f"{d}09:0{i}:00.000Z", TargetUserName=f"alice", IpAddress="192.168.1.20", LogonType="2") for i in range(5)]
        if n == 1:
            e.append(_evt(4625, f"{d}09:30:00.000Z", TargetUserName="alice", IpAddress="192.168.1.20"))  # one typo
        e.append(_evt(4634, f"{d}17:00:00.000Z", TargetUserName="alice"))  # logoff
        write_evtx(f"ben_logons_{n}.xml", e, "benign")

    # clean PE: ordinary APIs, no IOCs, low-entropy (repetitive) sections
    clean_text = b"GetProcAddress\x00LoadLibraryA\x00MessageBoxA\x00CreateFileA\x00GetVersionExA\x00CloseHandle\x00"
    low = bytes([0x00, 0x01, 0x02, 0x03] * 0x400)  # very low entropy
    write_file("ben_app_0.bin", _pe(clean_text, low), "benign")
    write_file("ben_app_1.bin", _pe(b"RegOpenKeyExA\x00GetSystemMetrics\x00wsprintfA\x00" + clean_text, low), "benign")
    # plain data files (non-PE)
    write_file("ben_readme.bin", b"Quarterly report. Revenue up 12%. See attached spreadsheet.\n" * 40, "benign")
    write_file("ben_config.bin", b"[settings]\nlog_level=info\ntimeout=30\nretries=3\n" * 30, "benign")


if __name__ == "__main__":
    malicious()
    benign()
    (OUT / "manifest.json").write_text(json.dumps(MANIFEST, indent=2))
    n_mal = sum(1 for m in MANIFEST if m["label"] == "malicious")
    n_ben = len(MANIFEST) - n_mal
    print(f"Wrote {len(MANIFEST)} samples to {OUT}  ({n_mal} malicious, {n_ben} benign)")
