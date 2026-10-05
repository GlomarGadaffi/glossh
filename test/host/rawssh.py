#!/usr/bin/env python3
"""Raw-socket probes of littlessh's plaintext (pre-NEWKEYS) transport.

usage: rawssh.py ignore-flood|strict-ignore PORT
Prints one summary line; exit 0 = expected server behaviour.
"""
import socket
import struct
import sys
import time

MSG_DISCONNECT, MSG_IGNORE, MSG_KEXINIT = 1, 2, 20


def string(b):
    return struct.pack(">I", len(b)) + b


def pkt(payload):
    """binary packet, no MAC: >= 4 bytes padding, total a multiple of 8"""
    pad = 8 - (5 + len(payload)) % 8
    if pad < 4:
        pad += 8
    return struct.pack(">IB", 1 + len(payload) + pad, pad) + payload + bytes(pad)


IGNORE = pkt(bytes([MSG_IGNORE]) + string(b""))


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


def recv_pkt(s):
    n, pad = struct.unpack(">IB", recv_exact(s, 5))
    return recv_exact(s, n - 1)[:n - 1 - pad]


def until_close(s):
    """every packet the server sends before it closes (EOF or reset)"""
    out = []
    try:
        while True:
            out.append(recv_pkt(s))
    except (EOFError, ConnectionResetError):
        return out


def connect(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"SSH-2.0-rawssh_probe\r\n")
    line = b""
    while not line.endswith(b"\n"):
        line += recv_exact(s, 1)
    if not line.startswith(b"SSH-2.0-"):
        raise SystemExit("no server version line: %r" % line)
    return s


def summary(pkts):
    """(message types, (reason, description) of the first DISCONNECT)"""
    types = [p[0] for p in pkts]
    for p in pkts:
        if p[0] == MSG_DISCONNECT and len(p) >= 9:
            dl = struct.unpack(">I", p[5:9])[0]
            return types, (struct.unpack(">I", p[1:5])[0],
                           p[9:9 + dl].decode(errors="replace"))
    return types, None


def ignore_flood(port):
    """100 IGNOREs before our KEXINIT: closed within 1 s, protocol error"""
    t0 = time.monotonic()
    s = connect(port)
    s.sendall(IGNORE * 100)
    types, disc = summary(until_close(s))
    el = time.monotonic() - t0
    print("elapsed=%.3fs types=%s disconnect=%s" % (el, types, disc))
    return el < 1.0 and types[:1] == [MSG_KEXINIT] and disc is not None and disc[0] == 2


def strict_ignore(port):
    """strict KEX (kex-strict-c-v00) with an IGNORE before our KEXINIT:
    the server's KEXINIT, then a DISCONNECT naming strict KEX"""
    lists = [b"curve25519-sha256,kex-strict-c-v00@openssh.com",
             b"ecdsa-sha2-nistp256",
             b"aes256-gcm@openssh.com", b"aes256-gcm@openssh.com",
             b"hmac-sha2-256", b"hmac-sha2-256",
             b"none", b"none", b"", b""]
    kexinit = (bytes([MSG_KEXINIT]) + bytes(16) + b"".join(string(x) for x in lists)
               + b"\x00" + bytes(4))
    s = connect(port)
    s.sendall(IGNORE + pkt(kexinit))
    types, disc = summary(until_close(s))
    print("types=%s disconnect=%s" % (types, disc))
    return (types[:2] == [MSG_KEXINIT, MSG_DISCONNECT] and disc is not None
            and "strict KEX" in disc[1])


def main():
    probes = {"ignore-flood": ignore_flood, "strict-ignore": strict_ignore}
    if len(sys.argv) != 3 or sys.argv[1] not in probes:
        raise SystemExit(__doc__)
    try:
        ok = probes[sys.argv[1]](int(sys.argv[2]))
    except OSError as e:
        print("socket error: %r" % e)
        ok = False
    sys.exit(0 if ok else 1)


main()
