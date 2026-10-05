#!/usr/bin/env python3
"""Raw-socket probes of littlessh, below what an OpenSSH client will send.

usage: rawssh.py PROBE PORT     (probes: see PROBES at the bottom)
Prints one summary line; exit 0 = expected server behaviour.

The plaintext probes speak the pre-NEWKEYS transport by hand. The rest use
Ssh, a minimal client (curve25519-sha256, aes256-gcm@openssh.com, password
auth; python3-cryptography) that does NOT verify the host key signature:
it is a probe, not a client to trust.
"""
import hashlib
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MSG_DISCONNECT, MSG_IGNORE, MSG_UNIMPLEMENTED = 1, 2, 3
MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT = 5, 6
MSG_KEXINIT, MSG_NEWKEYS, MSG_ECDH_INIT, MSG_ECDH_REPLY = 20, 21, 30, 31
MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE, MSG_USERAUTH_SUCCESS = 50, 51, 52
MSG_USERAUTH_BANNER = 53
MSG_GLOBAL_REQUEST, MSG_REQUEST_FAILURE = 80, 82
MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION = 90, 91
MSG_CHANNEL_DATA, MSG_CHANNEL_REQUEST = 94, 98
MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE = 99, 100
DISCONNECT_PROTOCOL_ERROR, DISCONNECT_NO_MORE_AUTH = 2, 14

V_C = b"SSH-2.0-rawssh_probe"


def string(b):
    return struct.pack(">I", len(b)) + b


def u32(v):
    return struct.pack(">I", v)


def mpint(b):
    b = b.lstrip(b"\x00")
    return string(b"\x00" + b if b and b[0] & 0x80 else b)


def pkt(payload):
    """binary packet, no MAC: >= 4 bytes padding, total a multiple of 8"""
    pad = 8 - (5 + len(payload)) % 8
    if pad < 4:
        pad += 8
    return struct.pack(">IB", 1 + len(payload) + pad, pad) + payload + bytes(pad)


IGNORE = pkt(bytes([MSG_IGNORE]) + string(b""))
UNIMPLEMENTED = bytes([MSG_UNIMPLEMENTED]) + u32(0)
DISCONNECT = bytes([MSG_DISCONNECT]) + u32(11) + string(b"bye") + string(b"")


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


def until_close(recv):
    """every packet the server sends before it closes (EOF or reset)"""
    out = []
    try:
        while True:
            out.append(recv())
    except (EOFError, ConnectionResetError):
        return out


def connect(port):
    """socket and the server's version line (no CRLF)"""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(V_C + b"\r\n")
    line = b""
    while not line.endswith(b"\n"):
        line += recv_exact(s, 1)
    if not line.startswith(b"SSH-2.0-"):
        raise SystemExit("no server version line: %r" % line)
    return s, line.rstrip(b"\r\n")


def summary(pkts):
    """(message types, (reason, description) of the first DISCONNECT)"""
    types = [p[0] for p in pkts]
    for p in pkts:
        if p[0] == MSG_DISCONNECT and len(p) >= 9:
            dl = struct.unpack(">I", p[5:9])[0]
            return types, (struct.unpack(">I", p[1:5])[0],
                           p[9:9 + dl].decode(errors="replace"))
    return types, None


def kexinit(strict=False):
    kex = b"curve25519-sha256" + (b",kex-strict-c-v00@openssh.com" if strict else b"")
    lists = [kex, b"ecdsa-sha2-nistp256",
             b"aes256-gcm@openssh.com", b"aes256-gcm@openssh.com",
             b"hmac-sha2-256", b"hmac-sha2-256",
             b"none", b"none", b"", b""]
    return (bytes([MSG_KEXINIT]) + bytes(16) + b"".join(string(x) for x in lists)
            + b"\x00" + bytes(4))


class Ssh:
    """Encrypted session. `extra` maps a KEX wait ("kexinit", "ecdh",
    "newkeys") to payloads sent in plaintext just before that message.
    seq is the sequence number of the next packet we send (non-strict KEX:
    it counts from our first packet and never resets)."""

    def __init__(self, port, extra=None):
        extra = extra or {}
        self.s, v_s = connect(port)
        self.seq = 0
        self.enc = False
        i_s = recv_pkt(self.s)
        i_c = kexinit()
        for p in extra.get("kexinit", []) + [i_c]:
            self.send(p)
        eph = X25519PrivateKey.generate()
        q_c = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        for p in extra.get("ecdh", []) + [bytes([MSG_ECDH_INIT]) + string(q_c)]:
            self.send(p)
        rep = recv_pkt(self.s)
        if rep[0] != MSG_ECDH_REPLY:
            raise EOFError("no ECDH_REPLY: %r" % summary([rep])[1])
        k_s, off = self.field(rep, 1)
        q_s, off = self.field(rep, off)
        k = mpint(eph.exchange(X25519PublicKey.from_public_bytes(q_s)))
        h = hashlib.sha256(string(V_C) + string(v_s) + string(i_c) + string(i_s)
                           + string(k_s) + string(q_c) + string(q_s) + k).digest()
        for p in extra.get("newkeys", []) + [bytes([MSG_NEWKEYS])]:
            self.send(p)
        if recv_pkt(self.s)[:1] != bytes([MSG_NEWKEYS]):
            raise EOFError("no NEWKEYS")

        def kdf(letter, n):   # RFC 4253 7.2, session id = H
            out = hashlib.sha256(k + h + letter + h).digest()
            while len(out) < n:
                out += hashlib.sha256(k + h + out).digest()
            return out[:n]
        self.iv_out, self.iv_in = kdf(b"A", 12), kdf(b"B", 12)
        self.k_out, self.k_in = AESGCM(kdf(b"C", 32)), AESGCM(kdf(b"D", 32))
        self.enc = True

    @staticmethod
    def field(b, off):
        n = struct.unpack(">I", b[off:off + 4])[0]
        return b[off + 4:off + 4 + n], off + 4 + n

    @staticmethod
    def next_iv(iv):   # RFC 5647: bump the 8-byte invocation counter
        return iv[:4] + ((int.from_bytes(iv[4:], "big") + 1) % 2**64).to_bytes(8, "big")

    def send(self, payload):
        if not self.enc:
            self.s.sendall(pkt(payload))
        else:
            pad = 16 - (1 + len(payload)) % 16
            if pad < 4:
                pad += 16
            body = bytes([pad]) + payload + os.urandom(pad)
            hdr = u32(len(body))
            self.s.sendall(hdr + self.k_out.encrypt(self.iv_out, body, hdr))
            self.iv_out = self.next_iv(self.iv_out)
        self.seq += 1
        return self.seq - 1

    def recv(self):
        """next packet, USERAUTH_BANNER skipped; EOFError when closed"""
        while True:
            hdr = recv_exact(self.s, 4)
            n = struct.unpack(">I", hdr)[0]
            body = self.k_in.decrypt(self.iv_in, recv_exact(self.s, n + 16), hdr)
            self.iv_in = self.next_iv(self.iv_in)
            p = body[1:n - body[0]]
            if p[0] != MSG_USERAUTH_BANNER:
                return p

    def rest(self):
        return summary(until_close(self.recv))

    def service(self):
        self.send(bytes([MSG_SERVICE_REQUEST]) + string(b"ssh-userauth"))
        return self.recv()[0] == MSG_SERVICE_ACCEPT

    def password(self, pw=b"hunter2", change=False, user=b"admin"):
        m = (bytes([MSG_USERAUTH_REQUEST]) + string(user) + string(b"ssh-connection")
             + string(b"password") + bytes([change]) + string(pw))
        self.send(m + (string(b"newpass") if change else b""))
        return self.recv()[0]

    def session(self):
        """service + auth + an open session channel; True if all succeeded"""
        if not self.service() or self.password() != MSG_USERAUTH_SUCCESS:
            return False
        self.send(bytes([MSG_CHANNEL_OPEN]) + string(b"session") + u32(7)
                  + u32(1 << 20) + u32(32768))
        return self.recv()[0] == MSG_CHANNEL_OPEN_CONFIRMATION

    def request(self, name, want, data=b""):
        self.send(bytes([MSG_CHANNEL_REQUEST]) + u32(0) + string(name)
                  + bytes([want]) + data)
        return self.recv()[0] if want else None


# ------------------------------------------------------- plaintext probes

def ignore_flood(port):
    """100 IGNOREs before our KEXINIT: closed within 1 s, protocol error"""
    t0 = time.monotonic()
    s, _ = connect(port)
    s.sendall(IGNORE * 100)
    types, disc = summary(until_close(lambda: recv_pkt(s)))
    el = time.monotonic() - t0
    print("elapsed=%.3fs types=%s disconnect=%s" % (el, types, disc))
    return el < 1.0 and types[:1] == [MSG_KEXINIT] and disc is not None and disc[0] == 2


def strict_ignore(port):
    """strict KEX (kex-strict-c-v00) with an IGNORE before our KEXINIT:
    the server's KEXINIT, then a DISCONNECT naming strict KEX"""
    s, _ = connect(port)
    s.sendall(IGNORE + pkt(kexinit(strict=True)))
    types, disc = summary(until_close(lambda: recv_pkt(s)))
    print("types=%s disconnect=%s" % (types, disc))
    return (types[:2] == [MSG_KEXINIT, MSG_DISCONNECT] and disc is not None
            and "strict KEX" in disc[1])


def kex_disconnect(port):
    """RFC 4253 11.1: the client's DISCONNECT instead of KEXINIT, or instead
    of ECDH_INIT, ends the connection with no DISCONNECT back"""
    out = []
    for first in ([], [kexinit()]):
        s, _ = connect(port)
        s.sendall(b"".join(pkt(p) for p in first + [DISCONNECT]))
        out.append(summary(until_close(lambda: recv_pkt(s)))[0])
    print("types=%s" % out)
    return out == [[MSG_KEXINIT], [MSG_KEXINIT]]


# ------------------------------------------------------- encrypted probes

def kex_unimplemented(port):
    """non-strict KEX: an UNIMPLEMENTED before KEXINIT, ECDH_INIT and
    NEWKEYS is skipped like IGNORE, and the login then succeeds"""
    c = Ssh(port, {"kexinit": [UNIMPLEMENTED], "ecdh": [UNIMPLEMENTED],
                   "newkeys": [UNIMPLEMENTED]})
    ok = c.service() and c.password() == MSG_USERAUTH_SUCCESS
    print("kex and auth ok=%s" % ok)
    return ok


def unimplemented(port):
    """RFC 4253 11.4 before auth: message 200 gets UNIMPLEMENTED naming its
    sequence number and the connection goes on; a connection-protocol
    message (90) before auth is still a protocol error"""
    c = Ssh(port)
    seq = c.send(bytes([200]) + b"junk")
    r = c.recv()
    if r[0] != MSG_UNIMPLEMENTED:
        print("reply=%s" % (summary([r]),))
        return False
    got = struct.unpack(">I", r[1:5])[0]
    svc = c.service()
    c.send(bytes([MSG_CHANNEL_OPEN]) + string(b"session") + u32(0) + u32(0) + u32(0))
    types, disc = c.rest()
    print("reply=%d seq=%s want=%d service=%s then types=%s disconnect=%s"
          % (r[0], got, seq, svc, types, disc))
    return (got == seq and svc and disc is not None
            and disc[0] == DISCONNECT_PROTOCOL_ERROR)


def auth_twice(port):
    """RFC 4252 5.1: USERAUTH_REQUEST after SUCCESS is ignored: the next
    packet we see answers our GLOBAL_REQUEST"""
    c = Ssh(port)
    first = c.service() and c.password() == MSG_USERAUTH_SUCCESS
    c.send(bytes([MSG_USERAUTH_REQUEST]) + string(b"admin") + string(b"ssh-connection")
           + string(b"password") + b"\x00" + string(b"hunter2"))
    c.send(bytes([MSG_GLOBAL_REQUEST]) + string(b"probe@rawssh") + b"\x01")
    nxt = c.recv()[0]
    print("first auth=%s next reply=%d" % (first, nxt))
    return first and nxt == MSG_REQUEST_FAILURE


def password_change(port):
    """RFC 4252 8: change=TRUE gets USERAUTH_FAILURE, counted as an
    attempt: four failures, then the fifth hits auth_max_tries (5)"""
    c = Ssh(port)
    svc = c.service()
    replies = []
    for _ in range(4):
        replies.append(c.password(change=True))
        if replies[-1] != MSG_USERAUTH_FAILURE:
            print("service=%s replies=%s" % (svc, replies))
            return False
    c.send(bytes([MSG_USERAUTH_REQUEST]) + string(b"admin") + string(b"ssh-connection")
           + string(b"password") + b"\x01" + string(b"hunter2") + string(b"x"))
    types, disc = c.rest()
    print("service=%s replies=%s then types=%s disconnect=%s" % (svc, replies, types, disc))
    return (svc and replies == [MSG_USERAUTH_FAILURE] * 4 and disc is not None
            and disc[0] == DISCONNECT_NO_MORE_AUTH)


def auth_no_service(port):
    """USERAUTH_REQUEST with no SERVICE_REQUEST("ssh-userauth") before it:
    a protocol error, even with the right password"""
    c = Ssh(port)
    c.send(bytes([MSG_USERAUTH_REQUEST]) + string(b"admin") + string(b"ssh-connection")
           + string(b"password") + b"\x00" + string(b"hunter2"))
    types, disc = summary([c.recv()])
    print("reply=%s disconnect=%s" % (types, disc))
    return disc is not None and disc[0] == DISCONNECT_PROTOCOL_ERROR


def env_request(port):
    """RFC 4254 6.4: we set no environment, so "env" fails; "signal" is
    still acknowledged"""
    c = Ssh(port)
    up = c.session()
    env = c.request(b"env", True, string(b"LANG") + string(b"C"))
    sig = c.request(b"signal", True, string(b"INT"))
    print("session=%s env=%s signal=%s" % (up, env, sig))
    return up and env == MSG_CHANNEL_FAILURE and sig == MSG_CHANNEL_SUCCESS


def pty_clamp(port):
    """pty-req cols 70000 and window-change rows 65537: the harness logs
    on_pty (run_tests.sh greps it for 65535). Done at the shell prompt."""
    c = Ssh(port)
    up = c.session()
    pty = c.request(b"pty-req", True, string(b"xterm") + u32(70000) + u32(24)
                    + u32(0) + u32(0) + string(b"\x00"))
    c.request(b"window-change", False, u32(80) + u32(65537) + u32(0) + u32(0))
    sh = c.request(b"shell", True)
    while c.recv()[0] != MSG_CHANNEL_DATA:
        pass
    print("session=%s pty=%s shell=%s" % (up, pty, sh))
    return up and pty == MSG_CHANNEL_SUCCESS and sh == MSG_CHANNEL_SUCCESS


PROBES = {"ignore-flood": ignore_flood, "strict-ignore": strict_ignore,
          "kex-disconnect": kex_disconnect, "kex-unimplemented": kex_unimplemented,
          "unimplemented": unimplemented, "auth-twice": auth_twice,
          "password-change": password_change, "auth-no-service": auth_no_service,
          "env": env_request, "pty-clamp": pty_clamp}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in PROBES:
        raise SystemExit(__doc__)
    try:
        ok = PROBES[sys.argv[1]](int(sys.argv[2]))
    except (OSError, EOFError) as e:
        print("connection error: %r" % e)
        ok = False
    sys.exit(0 if ok else 1)


main()
