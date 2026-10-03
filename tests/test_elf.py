# -*- coding: utf-8 -*-
"""Full-chain ELF test against the real RotaJakiro Linux backdoor sample.

Default sample path: D:\\data\\security\\pentest\\temp_extract_dir\\RotaJakiro.malware,
overridable via the UNICALL_SAMPLE environment variable; skipped when the
sample is not available.
"""
import os
import struct

import pytest

from unicall import Emu

SAMPLE = os.environ.get(
    "UNICALL_SAMPLE",
    r"D:\data\security\pentest\temp_extract_dir\RotaJakiro.malware")

pytestmark = pytest.mark.skipif(
    not os.path.exists(SAMPLE), reason="RotaJakiro sample not available")

STR_DECRYPT = 0x402B80


@pytest.fixture(scope="module")
def emu():
    e = Emu(SAMPLE)
    assert e.PLATFORM == "elf"
    return e


@pytest.fixture(scope="module")
def sample():
    return open(SAMPLE, "rb").read()


def test_elf_str_decrypt_rodata_blob(emu, sample):
    """Call site 0x409542: ciphertext in .rodata @0x4187E0 (0xE0 bytes),
    key in .data @0x61F300 (8 bytes); yields the systemd daemon config."""
    blob = sample[0x4187E0 - 0x400000:0x4187E0 - 0x400000 + 0xE0]
    key = sample[0x1F300:0x1F308]           # VA 0x61F300 -> file offset 0x1F300
    out = emu.call(STR_DECRYPT, [blob, 0xE0, 0xDE, key, 8], ret="str")
    assert "system-daemon" in out
    assert "exec %s" in out and "respawn" in out


def test_elf_str_decrypt_stack_immediates(emu):
    """Call site 0x406F5A (sub_406E30): ciphertext is six little-endian
    qword immediates; the key pointer is passed as an image address."""
    blob = struct.pack("<6Q",
                       0xF749A7CADD299C76, 0x11DF18E2058F0AFD,
                       0xCD8E4E37DDD8F707, 0x0C6E9C5005E1A46E,
                       0xBAA9BCA78BA1353A, 0xC59F3C76339D733C)
    out = emu.call(STR_DECRYPT, [blob, 48, 35, 0x61F2F0, 8], ret="str")
    assert out == ".dbus/sessions/session-dbus"


def test_elf_key_bytes_equivalent_to_address(emu, sample):
    """Passing the key as an image address equals passing the raw bytes."""
    blob = sample[0x4187E0 - 0x400000:0x4187E0 - 0x400000 + 0xE0]
    r1 = emu.call(STR_DECRYPT, [blob, 0xE0, 0xDE, 0x61F300, 8], ret="str")
    r2 = emu.call(STR_DECRYPT, [blob, 0xE0, 0xDE,
                                bytes.fromhex("14baee238f721aa6"), 8], ret="str")
    assert r1 == r2


def test_elf_auto_detect_factory():
    e = Emu(SAMPLE)
    assert type(e).__name__ == "ELFEmu"
