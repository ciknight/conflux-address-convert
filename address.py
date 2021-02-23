#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 ci_knight<ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
import struct
from base64 import b16decode, b16encode

import base32

HEX_PREFIX = "0X"
HEX_PREFIX_LEN = 2
HEX_BUFFER_LEN = 20

CFX_ADDRESS_CHAR_LENGTH = 42
CHECKSUM_LEN = 8

NETWORK_ID_MAINNET = 1029
NETWORK_MAIN = "cfx"
NETWORK_ID_TESTNET = 1
NETWORK_TEST = "cfxtest"
NETWORK_LOCAL_PREFIX = "net"

VERSION_BYTE = struct.pack("b", 0)  # 0x00

DELIMITER = ":"

CHECKSUM_TEMPLATE = bytes(8)


def _encode_netid(netid: int) -> str:
    if netid <= 0:
        raise Exception("chainId should be passed as in range [1, 0xFFFFFFFF]")

    if netid == NETWORK_ID_MAINNET:
        return NETWORK_MAIN
    if netid == NETWORK_ID_TESTNET:
        return NETWORK_TEST

    return NETWORK_LOCAL_PREFIX + str(netid)


def _encode_payload(hex_buf: bytes) -> bytes:
    return VERSION_BYTE + hex_buf


def _address_buffer_from_hex(hex_addr: str) -> bytes:
    hex_addr = hex_addr.upper()
    if hex_addr.startswith(HEX_PREFIX):
        hex_addr = hex_addr[HEX_PREFIX_LEN:]

    buf = b16decode(hex_addr)
    if len(buf) != HEX_BUFFER_LEN:
        raise Exception("hex buffer length should be 20")

    return buf


def _prefix_to_word(chain_prefix: str) -> bytes:
    buf = bytearray(chain_prefix.encode())
    for i, d in enumerate(buf):
        buf[i] = d & 0x1F

    return bytes(buf)


def _poly_mod(buf: bytes) -> int:
    c = 1
    for b in buf:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ b
        if (c0 & 0x01) != 0:
            c ^= 0x98F2BC8E61
        if (c0 & 0x02) != 0:
            c ^= 0x79B76D99E2
        if (c0 & 0x04) != 0:
            c ^= 0xF33E5FB3C4
        if (c0 & 0x08) != 0:
            c ^= 0xAE2EABE2A8
        if (c0 & 0x010) != 0:
            c ^= 0x1E4F43E470

    return c ^ 1


def _checksum_bytes(n: int) -> bytes:
    buf = [
        (n >> 32) & 0xFF,
        (n >> 24) & 0xFF,
        (n >> 16) & 0xFF,
        (n >> 8) & 0xFF,
        n & 0xFF,
    ]
    return bytes(buf)


def _create_checksum(chain_prefix: str, payload: str) -> str:
    prefix_buf = _prefix_to_word(chain_prefix)
    delimiter_buf = struct.pack("b", 0)
    payload_buf = base32.decode_words(payload)
    n = _poly_mod(prefix_buf + delimiter_buf + payload_buf + CHECKSUM_TEMPLATE)
    return base32.encode(_checksum_bytes(n))


def encode(hex_addr: str, netid: int) -> str:
    if not hex_addr:
        raise Exception("Invalid argument")

    buf = _address_buffer_from_hex(hex_addr)
    chain_prefix = _encode_netid(netid)
    payload = base32.encode(_encode_payload(buf))
    checksum = _create_checksum(chain_prefix, payload)
    return chain_prefix + DELIMITER + payload + checksum


assert (
    encode("0x106d49f8505410eb4e671d51f7d96d2c87807b09", 1029)
    == "cfx:aajg4wt2mbmbb44sp6szd783ry0jtad5bea80xdy7p"
)


def _have_chain_prefix(cfx_addr) -> bool:
    chain_prefix = cfx_addr.lower().spite(DELIMITER)[0]
    return chain_prefix in (NETWORK_MAIN, NETWORK_TEST, NETWORK_LOCAL_PREFIX)


def decode(cfx_addr: str) -> str:
    if not cfx_addr and not _have_chain_prefix(cfx_addr):
        raise Exception("Invalid argument")

    cfx_addr = cfx_addr.lower()
    parts = cfx_addr.split(DELIMITER)
    if len(parts) < 2:
        raise Exception("Address should have at least two part")

    chain_prefix = parts[0]
    payload_with_checksum = parts[-1]
    if not base32.is_valid(payload_with_checksum):
        raise Exception("Input contain invalid base32 chars")

    if len(payload_with_checksum) != CFX_ADDRESS_CHAR_LENGTH:
        raise Exception("Address payload should have 42 chars")

    payload, checksum = (
        payload_with_checksum[:-CHECKSUM_LEN],
        payload_with_checksum[CFX_ADDRESS_CHAR_LENGTH - CHECKSUM_LEN :],
    )
    if checksum != _create_checksum(chain_prefix, payload):
        raise Exception("Invalid checksum")

    raw = base32.decode(payload)
    hex_addr = HEX_PREFIX + b16encode(raw).decode()[HEX_PREFIX_LEN:]
    return hex_addr.lower()


assert (
    decode("cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg")
    == "0x1a2f80341409639ea6a35bbcab8299066109aa55"
)
