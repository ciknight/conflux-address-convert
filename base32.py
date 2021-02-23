#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 ci_knight<ci_knight@msn.cn>
#
# Distributed under terms of the MIT license.
from base64 import b32encode
import struct

CONFLUX_CHARSET = "abcdefghjkmnprstuvwxyz0123456789"
STANDARD_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
PADDING_CHAR = "="


def _is_valid(s: str) -> bool:
    if not s:
        return False

    for tmp in s:
        if tmp not in CONFLUX_CHARSET:
            return False

    return True


def _from_standard(data: str) -> str:
    result = ""
    for buf in data:
        if buf == PADDING_CHAR:
            break

        index = STANDARD_CHARSET.index(buf)
        result += CONFLUX_CHARSET[index]

    return result


def encode(buf: bytes) -> str:
    if not buf:
        raise Exception("buffer is null or empty")

    return _from_standard(b32encode(buf).decode())


def decode_words(words: str) -> bytes:
    if not _is_valid(words):
        raise Exception("include invalid char")

    buf = b""
    for w in words:
        num = CONFLUX_CHARSET.index(w)
        buf += struct.pack("b", num)

    return buf
