"""protocol.py — simple length-prefixed JSON packet framing utilities.

Packets are JSON objects; binary fields (`iv`, `ciphertext`, `tag`) are
base64-encoded for transport. Each message is prefixed by a 4-byte big-endian length.
"""

import json
import struct
import base64
from typing import Dict, Any, Optional

# Number of bytes used for the length prefix (4-byte unsigned int)
HEADER_SIZE = 4


def _b64e(data: bytes) -> str:
    # Base64-encode bytes and return UTF-8 string
    return base64.b64encode(data).decode("utf-8")


def _b64d(data_str: str) -> bytes:
    # Decode base64 string back into bytes
    return base64.b64decode(data_str.encode("utf-8"))


def encode_packet(packet: Dict[str, Any]) -> bytes:
    """Convert a packet dict into length-prefixed bytes suitable for sendall().

    Any binary fields in `packet` (iv, ciphertext, tag) are converted to base64
    strings so the whole payload can be serialized as JSON.
    """
    payload = packet.copy()  # shallow copy to avoid mutating caller
    # Encode binary fields to base64 strings for JSON transport
    if "iv" in payload and isinstance(payload["iv"], (bytes, bytearray)):
        payload["iv"] = _b64e(payload["iv"])
    if "ciphertext" in payload and isinstance(payload["ciphertext"], (bytes, bytearray)):
        payload["ciphertext"] = _b64e(payload["ciphertext"])
    if "tag" in payload and isinstance(payload["tag"], (bytes, bytearray)):
        payload["tag"] = _b64e(payload["tag"])

    # Serialize to JSON bytes and prepend 4-byte big-endian length
    raw = json.dumps(payload).encode("utf-8")
    length = struct.pack(">I", len(raw))
    return length + raw


def decode_packet(data: bytes) -> Dict[str, Any]:
    """Convert JSON bytes into a packet dict and decode base64 fields back to bytes."""
    payload = json.loads(data.decode("utf-8"))

    # Decode base64-encoded binary fields back to bytes
    if "iv" in payload and isinstance(payload["iv"], str):
        payload["iv"] = _b64d(payload["iv"])
    if "ciphertext" in payload and isinstance(payload["ciphertext"], str):
        payload["ciphertext"] = _b64d(payload["ciphertext"])
    if "tag" in payload and isinstance(payload["tag"], str):
        payload["tag"] = _b64d(payload["tag"])

    return payload


def send_packet(sock, packet: Dict[str, Any]) -> None:
    # Encode and send the full framed packet using socket.sendall
    data = encode_packet(packet)
    sock.sendall(data)


def _recv_exact(sock, n: int) -> Optional[bytes]:
    # Read exactly n bytes from socket, returning None if the socket closed
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_packet(sock) -> Optional[Dict[str, Any]]:
    # Read the 4-byte header to obtain payload length
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    # Read the JSON body of the specified length
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return decode_packet(body)