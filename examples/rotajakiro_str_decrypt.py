#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Example: decrypting RotaJakiro strings with unicall.

The sample's str_decrypt(data, blob_len, kept_len, key, keylen) @ 0x402B80
performs AES-256 decryption plus a per-byte rotation. Two representative
call sites are shown:

  1. Site 0x409542 -- ciphertext lives in .rodata at 0x4187E0 (0xE0 bytes),
     key at .data 0x61F300 (8 bytes).
  2. Site 0x406F5A (sub_406E30) -- ciphertext is six qword immediates built
     on the stack (little-endian in memory), key pointer 0x61F2F0.

The path to the sample can be overridden with the UNICALL_SAMPLE
environment variable.
"""
import os
import struct

from unicall import Emu

SAMPLE = os.environ.get(
    "UNICALL_SAMPLE",
    r"D:\data\security\pentest\temp_extract_dir\RotaJakiro.malware")

emu = Emu(SAMPLE)
raw = open(SAMPLE, "rb").read()

# ---- case 1: .rodata blob -------------------------------------------------
blob = raw[0x4187E0 - 0x400000:0x4187E0 - 0x400000 + 0xE0]
plain = emu.call(0x402B80, [blob, len(blob), 0xDE, 0x61F300, 8], ret="str")
print("case 1 (rodata blob @0x4187E0):")
print(plain)

# ---- case 2: stack-built ciphertext (qword immediates, little-endian) -----
blob2 = struct.pack("<6Q",
                    0xF749A7CADD299C76, 0x11DF18E2058F0AFD,
                    0xCD8E4E37DDD8F707, 0x0C6E9C5005E1A46E,
                    0xBAA9BCA78BA1353A, 0xC59F3C76339D733C)
plain2 = emu.call(0x402B80, [blob2, len(blob2), 35, 0x61F2F0, 8], ret="str")
print("\ncase 2 (stack immediates, key passed as image address 0x61F2F0):")
print(repr(plain2))

# Passing the key as raw bytes is equivalent:
plain3 = emu.call(0x402B80, [blob2, len(blob2), 35,
                             bytes.fromhex("14baee238f721aa6"), 8], ret="str")
assert plain2 == plain3
