#!/usr/bin/env python3
"""
Minimaler TeamSpeak-3-Client in Python.

Implementiert den echten TS3-UDP-Handshake bis einschließlich:
  Init0/Init2/Init4, RSA-Puzzle, initivexpand2, clientek, verschlüsseltem
  clientinit und Empfang von initserver.

Kein Audio.
"""

import argparse
import base64
import hashlib
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


PTYPE_COMMAND = 2
PTYPE_PING = 4
PTYPE_PONG = 5
PTYPE_ACK = 6
PTYPE_INIT1 = 8

FLAG_UNENCRYPTED = 0x80
FLAG_COMPRESSED = 0x40
FLAG_NEWPROTOCOL = 0x20
FLAG_FRAGMENTED = 0x10

FAKE_KEY = b"c:\\windows\\syste"
FAKE_NONCE = b"m\\firewall32.cpl"

ROOT_KEY = bytes([
    0xcd, 0x0d, 0xe2, 0xae, 0xd4, 0x63, 0x45, 0x50,
    0x9a, 0x7e, 0x3c, 0xfd, 0x8f, 0x68, 0xb3, 0xdc,
    0x75, 0x55, 0xb2, 0x9d, 0xcc, 0xec, 0x73, 0xcd,
    0x18, 0x75, 0x0f, 0x99, 0x38, 0x12, 0x40, 0x8a,
])

CLIENT_VERSION = "3.?.? [Build: 5680278000]"
CLIENT_PLATFORM = "Windows"
CLIENT_VERSION_SIGN = (
    "DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg=="
)
HWID = "923f136fb1e22ae6ce95e60255529c00,d13231b1bc33edfecfb9169cc7a63bcc"
DEFAULT_IDENTITY_TS = (
    "MG0DAgeAAgEgAiAIXJBlj1hQbaH0Eq0DuLlCmH8bl+veTAO2+"
    "k9EQjEYSgIgNnImcmKo7ls5mExb6skfK2Tw+u54aeDr0OP1ITs"
    "C/50CIA8M5nmDBnmDM/gZ//4AAAAAAAAAAAAAAAAAAAAZRzOI"
)
DEFAULT_IDENTITY_PUBLIC_TS = (
    "MEsDAgcAAgEgAiAIXJBlj1hQbaH0Eq0DuLlCmH8bl+veTAO2+"
    "k9EQjEYSgIgNnImcmKo7ls5mExb6skfK2Tw+u54aeDr0OP1ITsC/50="
)


# ---------------------------------------------------------------------------
# Edwards25519, kompatibel zu curve25519-dalek EdwardsPoint-Kompression
# ---------------------------------------------------------------------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
P256_N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
BY = (4 * pow(5, P - 2, P)) % P
BX = (pow((BY * BY - 1) * pow(D * BY * BY + 1, P - 2, P), (P + 3) // 8, P))
if (BX * BX - (BY * BY - 1) * pow(D * BY * BY + 1, P - 2, P)) % P != 0:
    BX = (BX * I) % P
if BX & 1:
    BX = P - BX
B = (BX, BY)
IDENTITY = (0, 1)


def ed_decompress(data: bytes):
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    x2 = ((y * y - 1) * pow(D * y * y + 1, P - 2, P)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = (x * I) % P
    if x & 1 != sign:
        x = P - x
    if (x * x - x2) % P:
        raise ValueError("invalid ed25519 point")
    return (x, y)


def ed_compress(point) -> bytes:
    x, y = point
    data = bytearray(y.to_bytes(32, "little"))
    data[31] |= (x & 1) << 7
    return bytes(data)


def ed_add(p, q):
    x1, y1 = p
    x2, y2 = q
    den = pow(1 + D * x1 * x2 * y1 * y2, P - 2, P)
    x3 = ((x1 * y2 + x2 * y1) * den) % P
    den = pow(1 - D * x1 * x2 * y1 * y2, P - 2, P)
    y3 = ((y1 * y2 + x1 * x2) * den) % P
    return (x3, y3)


def ed_mul(point, scalar: int):
    scalar %= L
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = ed_add(result, addend)
        addend = ed_add(addend, addend)
        scalar >>= 1
    return result


def ed_scalar_from_hash_key(block: bytes) -> int:
    h = bytearray(hashlib.sha512(block[1:]).digest())
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h[:32], "little") % L


# ---------------------------------------------------------------------------
# TS3 Packet / Crypto
# ---------------------------------------------------------------------------


@dataclass
class Packet:
    mac: bytes
    packet_id: int
    client_id: int
    flags: int
    ptype: int
    payload: bytes


def build_header(mac: bytes, packet_id: int, client_id: int, flags: int, ptype: int) -> bytes:
    return mac + struct.pack(">HHB", packet_id & 0xFFFF, client_id & 0xFFFF, (flags & 0xF0) | ptype)


def parse_s2c(raw: bytes) -> Packet:
    if len(raw) < 11:
        raise ValueError("packet too short")
    mac = raw[:8]
    packet_id = struct.unpack(">H", raw[8:10])[0]
    type_byte = raw[10]
    return Packet(mac, packet_id, 0, type_byte & 0xF0, type_byte & 0x0F, raw[11:])


def parse_c2s(raw: bytes) -> Packet:
    if len(raw) < 13:
        raise ValueError("packet too short")
    mac = raw[:8]
    packet_id, client_id, type_byte = struct.unpack(">HHB", raw[8:13])
    return Packet(mac, packet_id, client_id, type_byte & 0xF0, type_byte & 0x0F, raw[13:])


def key_nonce(ptype: int, has_client_id: bool, packet_id: int, generation_id: int, iv: bytes):
    temp = bytearray(70)
    temp[0] = 0x31 if has_client_id else 0x30
    temp[1] = ptype
    temp[2:6] = struct.pack(">I", generation_id)
    temp[6:] = iv
    digest = hashlib.sha256(temp).digest()
    key = bytearray(digest[:16])
    key[0] ^= packet_id >> 8
    key[1] ^= packet_id & 0xFF
    return bytes(key), digest[16:32]


def eax_encrypt(payload: bytes, header_meta: bytes, key: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=8)
    cipher.update(header_meta)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return tag, ciphertext


def eax_decrypt(packet: Packet, raw: bytes, server_to_client: bool, key: bytes, nonce: bytes):
    header_len = 11 if server_to_client else 13
    meta = raw[8:header_len]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=8)
    cipher.update(meta)
    return cipher.decrypt_and_verify(packet.payload, packet.mac)


def decrypt_fake(packet: Packet, raw: bytes):
    return eax_decrypt(packet, raw, True, FAKE_KEY, FAKE_NONCE)


def decrypt_shared(packet: Packet, raw: bytes, iv: bytes):
    key, nonce = key_nonce(packet.ptype, False, packet.packet_id, 0, iv)
    return eax_decrypt(packet, raw, True, key, nonce)


def encrypt_shared(payload: bytes, packet_id: int, client_id: int, ptype: int, iv: bytes, flags: int = 0):
    header = build_header(b"\x00" * 8, packet_id, client_id, flags, ptype)
    key, nonce = key_nonce(ptype, True, packet_id, 0, iv)
    tag, ciphertext = eax_encrypt(payload, header[8:13], key, nonce)
    return build_header(tag, packet_id, client_id, flags, ptype) + ciphertext


def encrypt_fake_c2s(payload: bytes, packet_id: int, client_id: int, ptype: int, flags: int = 0):
    header = build_header(b"\x00" * 8, packet_id, client_id, flags, ptype)
    tag, ciphertext = eax_encrypt(payload, header[8:13], FAKE_KEY, FAKE_NONCE)
    return build_header(tag, packet_id, client_id, flags, ptype) + ciphertext


def ts_escape(s: str) -> str:
    return (s.replace("\\", "\\\\").replace("/", "\\/").replace(" ", "\\s")
             .replace("|", "\\p").replace("\n", "\\n").replace("\r", "\\r")
             .replace("\t", "\\t"))


def ts_unescape(s: str) -> str:
    return (s.replace("\\s", " ").replace("\\/", "/").replace("\\p", "|")
             .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
             .replace("\\\\", "\\"))


def parse_command_args(command: bytes):
    text = command.decode("utf-8", errors="replace")
    parts = text.split()
    name = parts[0] if parts else ""
    args = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            args[k] = ts_unescape(v)
        else:
            args[part] = ""
    return name, args, text


def quicklz_decompress(source: bytes) -> bytes:
    if len(source) < 3:
        raise ValueError("QuickLZ packet too short")

    flags = source[0]
    level = (flags >> 2) & 0x03
    if level not in (1, 3):
        raise ValueError(f"QuickLZ unsupported level {level}")

    header_len = 9 if flags & 2 else 3
    if len(source) < header_len:
        raise ValueError("QuickLZ header truncated")

    if header_len == 9:
        comp_size = int.from_bytes(source[1:5], "little")
        dec_size = int.from_bytes(source[5:9], "little")
    else:
        comp_size = source[1]
        dec_size = source[2]

    if comp_size < header_len or comp_size > len(source):
        raise ValueError("QuickLZ invalid compressed size")

    payload_end = comp_size
    if not flags & 1:
        if comp_size - header_len != dec_size:
            raise ValueError("QuickLZ invalid uncompressed size")
        return source[header_len:payload_end]

    def read_u8(pos: int) -> tuple[int, int]:
        if pos >= payload_end:
            raise ValueError("QuickLZ stream truncated")
        return source[pos], pos + 1

    def read_u32(pos: int) -> tuple[int, int]:
        if pos + 4 > payload_end:
            raise ValueError("QuickLZ control word truncated")
        return int.from_bytes(source[pos:pos + 4], "little"), pos + 4

    def qlz_hash(val: int) -> int:
        return ((val >> 12) ^ val) & 0x0fff

    def read_u24_from_dest(pos: int) -> int:
        return dst[pos] | (dst[pos + 1] << 8) | (dst[pos + 2] << 16)

    def update_hashtable(start: int, end: int) -> None:
        nonlocal hashtable
        for i in range(start, end):
            hashtable[qlz_hash(read_u24_from_dest(i))] = i

    def copy_from(start: int, length: int) -> None:
        if start < 0 or start > len(dst):
            raise ValueError("QuickLZ invalid back reference")
        end = start + length
        i = start
        while i < end:
            if i >= len(dst):
                raise ValueError("QuickLZ invalid back reference")
            dst.append(dst[i])
            i += 1

    src = header_len
    dst = bytearray()
    control = 1
    hashtable = [0] * 4096
    next_hashed = 0

    while True:
        if control == 1:
            control, src = read_u32(src)

        if control & 1:
            control >>= 1
            nxt, src = read_u8(src)
            if level == 1:
                match_len = nxt & 0x0f
                hash_value_next, src = read_u8(src)
                hash_value = (nxt >> 4) | (hash_value_next << 4)
                if match_len:
                    match_len += 2
                else:
                    match_len, src = read_u8(src)
                if match_len < 3:
                    raise ValueError("QuickLZ reference length too small")
                offset = hashtable[hash_value]
                if len(dst) + match_len > dec_size:
                    raise ValueError("QuickLZ decompressed size exceeded")
                copy_from(offset, match_len)
                end = len(dst) + 1 - match_len
                update_hashtable(next_hashed, end)
                next_hashed = len(dst)
            else:
                if nxt & 0b11 == 0:
                    match_len = 3
                    offset = nxt >> 2
                elif nxt & 0b11 == 0b01:
                    b2, src = read_u8(src)
                    match_len = 3
                    offset = (nxt >> 2) | (b2 << 6)
                elif nxt & 0b11 == 0b10:
                    b2, src = read_u8(src)
                    match_len = 3 + ((nxt >> 2) & 0x0f)
                    offset = (nxt >> 6) | (b2 << 2)
                elif nxt & 0x7f == 0b11:
                    b2, src = read_u8(src)
                    b3, src = read_u8(src)
                    b4, src = read_u8(src)
                    match_len = 3 + ((nxt >> 7) | ((b2 & 0x7f) << 1))
                    offset = (b2 >> 7) | (b3 << 1) | (b4 << 9)
                else:
                    b2, src = read_u8(src)
                    b3, src = read_u8(src)
                    match_len = 2 + ((nxt >> 2) & 0x1f)
                    offset = (nxt >> 7) | (b2 << 1) | (b3 << 9)
                if len(dst) < offset or len(dst) + match_len > dec_size:
                    raise ValueError("QuickLZ invalid offset")
                copy_from(len(dst) - offset, match_len)
        elif len(dst) >= max(dec_size, 10) - 10:
            while len(dst) < dec_size:
                if control == 1:
                    _, src = read_u32(src)
                control >>= 1
                literal, src = read_u8(src)
                dst.append(literal)
            break
        else:
            literal, src = read_u8(src)
            dst.append(literal)
            control >>= 1
            if level == 1:
                end = max(len(dst) - 2, 0)
                update_hashtable(next_hashed, end)
                next_hashed = max(next_hashed, end)

        if len(dst) == dec_size:
            break
        if len(dst) > dec_size:
            raise ValueError("QuickLZ decompressed size exceeded")

    return bytes(dst)


def make_command(name: str, args: list[tuple[str, str]]) -> bytes:
    parts = [name]
    for k, v in args:
        if v == "":
            parts.append(k)
        else:
            parts.append(f"{k}={ts_escape(v)}")
    return " ".join(parts).encode("utf-8")


def hashcash_level(omega: str, offset: int) -> int:
    digest = hashlib.sha1(f"{omega}{offset}".encode("ascii")).digest()
    level = 0
    for b in digest:
        if b == 0:
            level += 8
        else:
            while b & 1 == 0:
                level += 1
                b >>= 1
            break
    return level


def solve_hashcash(omega: str, target=8) -> int:
    offset = 0
    while hashcash_level(omega, offset) < target:
        offset += 1
    return offset


def der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    data = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(data)]) + data


def der_int(value: int) -> bytes:
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if data[0] & 0x80:
        data = b"\x00" + data
    return b"\x02" + der_len(len(data)) + data


def der_bit_string(data: bytes, unused_bits: int = 7) -> bytes:
    payload = bytes([unused_bits]) + data
    return b"\x03" + der_len(len(payload)) + payload


def der_sequence(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    return b"\x30" + der_len(len(payload)) + payload


def der_read_len(data: bytes, offset: int):
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def der_decode_ecdsa(sig: bytes):
    if sig[0] != 0x30:
        raise ValueError("not a DER sequence")
    _, off = der_read_len(sig, 1)
    if sig[off] != 0x02:
        raise ValueError("missing r")
    r_len, off = der_read_len(sig, off + 1)
    r = int.from_bytes(sig[off:off + r_len], "big")
    off += r_len
    if sig[off] != 0x02:
        raise ValueError("missing s")
    s_len, off = der_read_len(sig, off + 1)
    s = int.from_bytes(sig[off:off + s_len], "big")
    return r, s


def der_encode_ecdsa(r: int, s: int):
    return der_sequence([der_int(r), der_int(s)])


def p256_public_tomcrypt(key: ECC.EccKey) -> bytes:
    pub = key.public_key()
    return der_sequence([
        der_bit_string(b"\x00", 7),
        der_int(32),
        der_int(int(pub.pointQ.x)),
        der_int(int(pub.pointQ.y)),
    ])


def create_identity() -> ECC.EccKey:
    while True:
        key = ECC.generate(curve="P-256")
        pub = key.public_key()
        if int(pub.pointQ.x).bit_length() > 248 and int(pub.pointQ.y).bit_length() > 248:
            return key


def parse_tomcrypt_private(data: bytes) -> ECC.EccKey:
    if data[0] != 0x30:
        raise ValueError("identity is not a DER sequence")
    seq_len, off = der_read_len(data, 1)
    end = off + seq_len
    values = []
    while off < end:
        tag = data[off]
        ln, value_off = der_read_len(data, off + 1)
        value = data[value_off:value_off + ln]
        if tag == 0x02:
            values.append(int.from_bytes(value, "big"))
        off = value_off + ln
    if len(values) < 4 or values[0] != 32:
        raise ValueError("unsupported TS identity format")
    x, y, d = values[1], values[2], values[3]
    return ECC.construct(curve="P-256", d=d, point_x=x, point_y=y)


def p256_sign(key: ECC.EccKey, data: bytes) -> bytes:
    h = SHA256.new(data)
    sig = DSS.new(key, "fips-186-3", encoding="der").sign(h)
    r, s = der_decode_ecdsa(sig)
    if s > P256_N // 2:
        s = P256_N - s
    return der_encode_ecdsa(r, s)


def derive_server_ephemeral_key(license_data: bytes, root_key: bytes = ROOT_KEY):
    if not license_data or license_data[0] not in (0, 1):
        raise ValueError("unsupported license data")
    parent = ed_decompress(root_key)
    off = 1
    while off < len(license_data):
        block = license_data[off:]
        if len(block) < 42:
            raise ValueError("license block too short")
        typ = block[33]
        extra = 0
        rest = block[42:]
        if typ == 0:
            pos = rest[4:].index(0)
            extra = 5 + pos
        elif typ == 2:
            pos = rest[5:].index(0)
            extra = 6 + pos
        elif typ == 8:
            count = rest[1]
            pos = 2
            for _ in range(count):
                ln = rest[pos]
                pos += 1 + ln
            extra = pos
        elif typ == 32:
            extra = 0
        else:
            raise ValueError(f"unsupported license block type {typ}")
        block_len = 42 + extra
        block = license_data[off:off + block_len]
        pub = ed_decompress(block[1:33])
        parent = ed_add(ed_mul(pub, ed_scalar_from_hash_key(block)), parent)
        off += block_len
    return parent


class TS3Client:
    def __init__(self, host, port, nickname, password="", verbose=0):
        self.host = host
        self.port = port
        self.nickname = nickname
        self.password = password
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET6 if ":" in socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][4][0] else socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(10)
        self.addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][4]
        self.client_id = 0
        self.command_id = 0
        self.iv = None
        self.shared_mac = None
        self.identity = create_identity()
        self.identity_tomcrypt_pub = p256_public_tomcrypt(self.identity)
        self._fragment_payload = None
        self._fragment_flags = 0

    def send(self, data: bytes):
        if self.verbose >= 3:
            print(f"--> {len(data)} {data[:32].hex()}")
        self.sock.sendto(data, self.addr)

    def recv_raw(self, timeout=10):
        self.sock.settimeout(timeout)
        data, _ = self.sock.recvfrom(65535)
        if self.verbose >= 3:
            print(f"<-- {len(data)} {data[:32].hex()}")
        return data

    def init_packet(self, payload: bytes) -> bytes:
        return build_header(b"TS3INIT1", 0x65, 0, FLAG_UNENCRYPTED, PTYPE_INIT1) + payload

    def send_ack(self, packet_id: int):
        payload = struct.pack(">H", packet_id)
        if self.iv is None:
            self.send(encrypt_fake_c2s(payload, packet_id, self.client_id, PTYPE_ACK))
        else:
            self.send(encrypt_shared(payload, packet_id, self.client_id, PTYPE_ACK, self.iv))

    def send_command(self, payload: bytes, packet_id=None):
        if packet_id is None:
            packet_id = self.command_id
            self.command_id += 1
        self.send(encrypt_shared(payload, packet_id, self.client_id, PTYPE_COMMAND, self.iv))
        return packet_id

    def command_packet(self, payload: bytes, packet_id: int):
        return encrypt_shared(payload, packet_id, self.client_id, PTYPE_COMMAND, self.iv, FLAG_NEWPROTOCOL)

    def command_packets(self, payload: bytes, first_packet_id: int):
        max_payload = 500 - 13
        if len(payload) <= max_payload:
            return [self.command_packet(payload, first_packet_id)]

        packets = []
        chunks = [payload[i:i + max_payload] for i in range(0, len(payload), max_payload)]
        for i, chunk in enumerate(chunks):
            flags = FLAG_COMPRESSED if False else 0
            flags |= FLAG_NEWPROTOCOL
            if i == 0 or i == len(chunks) - 1:
                flags |= FLAG_FRAGMENTED
            packets.append(encrypt_shared(
                chunk,
                first_packet_id + i,
                self.client_id,
                PTYPE_COMMAND,
                self.iv,
                flags,
            ))
        return packets

    def recv_command(self, timeout=10, allow_fake=False):
        while True:
            raw = self.recv_raw(timeout)
            packet = parse_s2c(raw)
            if packet.ptype == PTYPE_ACK:
                continue
            if packet.ptype == PTYPE_PING:
                self.send(build_header(b"\x00" * 8, packet.packet_id, self.client_id, FLAG_UNENCRYPTED, PTYPE_PONG) + struct.pack(">H", packet.packet_id))
                continue
            if packet.ptype != PTYPE_COMMAND:
                continue
            result = self.decode_command_packet(raw, packet, allow_fake)
            if result is None:
                continue
            return result

    def decode_command_packet(self, raw: bytes, packet: Packet, allow_fake=False):
        payload = decrypt_fake(packet, raw) if allow_fake else decrypt_shared(packet, raw, self.iv)
        self.send_ack(packet.packet_id)

        if packet.flags & FLAG_FRAGMENTED or self._fragment_payload is not None:
            if self._fragment_payload is None:
                self._fragment_payload = bytearray(payload)
                self._fragment_flags = packet.flags
                return None

            self._fragment_payload.extend(payload)
            if packet.flags & FLAG_FRAGMENTED:
                payload = bytes(self._fragment_payload)
                flags = self._fragment_flags
                self._fragment_payload = None
                self._fragment_flags = 0
            else:
                return None
        else:
            flags = packet.flags

        if flags & FLAG_COMPRESSED:
            payload = quicklz_decompress(payload)

        name, args, text = parse_command_args(payload)
        if self.verbose:
            print(f"<< {text[:180]}")
        return packet, name, args, text

    def connect(self):
        timestamp = int(time.time())
        version = timestamp - 1356998400
        random0 = os.urandom(4)

        print("[1/7] Init Step 0")
        self.send(self.init_packet(struct.pack(">IBI", version, 0, timestamp) + random0 + b"\x00" * 8))

        raw = self.recv_raw()
        p = parse_s2c(raw)
        if p.ptype != PTYPE_INIT1 or p.payload[:1] != b"\x01":
            raise RuntimeError("unexpected init step 1")
        random1 = p.payload[1:17]
        random0_r = p.payload[17:21]

        print("[2/7] Init Step 2")
        self.send(self.init_packet(struct.pack(">IB", version, 2) + random1 + random0_r))

        raw = self.recv_raw()
        p = parse_s2c(raw)
        if p.ptype != PTYPE_INIT1 or p.payload[:1] != b"\x03":
            raise RuntimeError("unexpected init step 3")
        x = p.payload[1:65]
        n = p.payload[65:129]
        level = struct.unpack(">I", p.payload[129:133])[0]
        random2 = p.payload[133:233]

        print(f"[3/7] RSA-Puzzle level={level}")
        y = pow(int.from_bytes(x, "big"), 1 << level, int.from_bytes(n, "big")).to_bytes(64, "big")

        alpha = os.urandom(10)
        omega_der = self.identity_tomcrypt_pub
        initiv = (
            "clientinitiv "
            f"alpha={base64.b64encode(alpha).decode('ascii')} "
            f"omega={base64.b64encode(omega_der).decode('ascii')} "
            "ot=1 ip"
        ).encode("ascii")
        print("[4/7] Init Step 4")
        self.send(self.init_packet(struct.pack(">IB", version, 4) + x + n + struct.pack(">I", level) + random2 + y + initiv))

        print("[5/7] initivexpand2")
        _, name, args, _ = self.recv_command(allow_fake=True)
        if name != "initivexpand2":
            raise RuntimeError(f"expected initivexpand2, got {name}")
        beta = base64.b64decode(args["beta"])
        license_data = base64.b64decode(args["l"])
        root_key = base64.b64decode(args["root"]) if "root" in args else ROOT_KEY
        if self.verbose:
            print(f"    initivexpand2 args: {', '.join(sorted(args))}")
        if len(beta) != 54:
            raise RuntimeError("invalid beta length")

        server_ek = derive_server_ephemeral_key(license_data, root_key)
        ek_scalar = int.from_bytes(os.urandom(64), "little") % L
        ek_pub = ed_mul(B, ek_scalar)
        ek_pub_b = ed_compress(ek_pub)
        shared_secret = ed_compress(ed_mul(server_ek, ek_scalar))
        shared_iv = bytearray(hashlib.sha512(shared_secret).digest())
        for i in range(10):
            shared_iv[i] ^= alpha[i]
        for i in range(54):
            shared_iv[i + 10] ^= beta[i]
        self.iv = bytes(shared_iv)
        self.shared_mac = hashlib.sha1(self.iv).digest()[:8]

        print("[6/7] clientek")
        proof = p256_sign(self.identity, ek_pub_b + beta)
        clientek = make_command("clientek", [
            ("ek", base64.b64encode(ek_pub_b).decode("ascii")),
            ("proof", base64.b64encode(proof).decode("ascii")),
        ])
        clientek_packet = encrypt_fake_c2s(clientek, 1, self.client_id, PTYPE_COMMAND, FLAG_NEWPROTOCOL)
        self.send(clientek_packet)

        try:
            raw = self.recv_raw(2)
            ack = parse_s2c(raw)
            if ack.ptype == PTYPE_ACK:
                if self.verbose:
                    print(f"    clientek ACK packet_id={ack.packet_id}")
            elif ack.ptype == PTYPE_COMMAND:
                _, name, args, text = self.decode_command_packet(raw, ack)
                if name == "error":
                    raise RuntimeError(text)
            elif self.verbose:
                print(f"    unexpected packet after clientek: type={ack.ptype} id={ack.packet_id}")
        except socket.timeout:
            if self.verbose:
                print("    no ACK after clientek")

        omega_ts = base64.b64encode(self.identity_tomcrypt_pub).decode("ascii")
        offset = solve_hashcash(omega_ts, 8)
        clientinit = make_command("clientinit", [
            ("client_nickname", self.nickname),
            ("client_version", CLIENT_VERSION),
            ("client_platform", CLIENT_PLATFORM),
            ("client_input_hardware", "1"),
            ("client_output_hardware", "1"),
            ("client_default_channel", ""),
            ("client_default_channel_password", ""),
            ("client_server_password", self.password),
            ("client_meta_data", ""),
            ("client_version_sign", CLIENT_VERSION_SIGN),
            ("client_nickname_phonetic", ""),
            ("client_key_offset", str(offset)),
            ("client_default_token", ""),
        ])
        print("[7/7] clientinit")
        clientinit_packets = self.command_packets(clientinit, 2)
        for packet in clientinit_packets:
            self.send(packet)

        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                _, name, args, text = self.recv_command(timeout=1)
            except socket.timeout:
                continue
            if name == "initserver":
                if "aclid" in args:
                    self.client_id = int(args["aclid"])
                print("[+] Connected")
                return True
            if name == "error":
                raise RuntimeError(text)
        raise RuntimeError("timeout waiting for initserver")

    def listen(self):
        print("[*] Verbunden. Ctrl+C zum Trennen.")
        while True:
            self.recv_command(timeout=30)

    def disconnect(self):
        try:
            if self.iv is not None:
                cmd = make_command("clientdisconnect", [
                    ("reasonid", "8"),
                    ("reasonmsg", "Auf Wiedersehen"),
                ])
                self.send_command(cmd)
        except Exception:
            pass
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="TeamSpeak 3 Client in Python")
    parser.add_argument("host", nargs="?", default="localhost")
    parser.add_argument("-p", "--port", type=int, default=9987)
    parser.add_argument("-n", "--nickname", default="PythonClient")
    parser.add_argument("--password", default="")
    parser.add_argument("--stay-seconds", type=int, default=0)
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args()

    print("=" * 60)
    print(f"  Python TS3 Client  |  {args.host}:{args.port}")
    print(f"  Nickname: {args.nickname}")
    print("=" * 60)

    client = TS3Client(args.host, args.port, args.nickname, args.password, args.verbose)
    try:
        client.connect()
        if args.stay_seconds:
            time.sleep(args.stay_seconds)
        else:
            client.listen()
    except KeyboardInterrupt:
        print("\n[*] Unterbrochen.")
    except Exception as e:
        print(f"[-] {e}")
        return 1
    finally:
        client.disconnect()
        print("[*] Getrennt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
