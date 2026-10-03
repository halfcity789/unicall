# -*- coding: utf-8 -*-
"""Full-chain PE test: loading / IAT hooks / Win64 argument passing / stack
arguments / strict imports / hook_skip.

The test sample is a minimal PE32+ built by tests/pe_builder.py; no external
file is required.
"""
import pytest

from unicall import Emu, StopEmulation
from pe_builder import build_test_pe


@pytest.fixture(scope="module")
def pe(tmp_path_factory):
    p = str(tmp_path_factory.mktemp("pe") / "test.pe")
    addrs = build_test_pe(p)
    return p, addrs


def test_pe_full_chain(pe):
    path, A = pe
    emu = Emu(path)
    assert emu.imagebase == 0x400000

    seen = {}
    emu.hook_import("fake.dll!magic_number", lambda e: 0x1337)
    emu.hook_import("fake.dll!lstrlenA",
                    lambda e, p: seen.update(p=p) or len(e.read_cstring(p)))

    # Win x64 four register arguments
    assert emu.call(A["add4"], [1, 2, 3, 4]) == 10
    # IAT hook return value participates in the caller's computation
    assert emu.call(A["call_imp"]) == 0x1338
    # bytes argument -> placed in memory automatically, pointer passed
    assert emu.call(A["echo"], [b"hello world"]) == 11
    assert seen["p"] != 0
    # 5th argument passed on the stack (after the shadow space)
    assert emu.call(A["add5"], [1, 2, 3, 4, 5]) == 15
    # extra arguments are ignored
    assert emu.call(A["add4"], [1, 2, 3, 4, 5, 6]) == 10


def test_pe_strict_import(pe):
    path, A = pe
    emu = Emu(path)                     # no hooks registered
    with pytest.raises(StopEmulation) as ei:
        emu.call(A["call_imp"])
    assert "magic_number" in str(ei.value)


def test_pe_hook_skip(pe):
    path, A = pe
    emu = Emu(path)
    emu.hook_skip(A["call_imp"], 0x55)           # constant return value
    assert emu.call(A["call_imp"]) == 0x55
    emu.hook_skip(A["echo"], lambda e, p: 0x66)  # callable shim
    assert emu.call(A["echo"], [b"x"]) == 0x66


def test_pe_memory_layout(pe):
    path, A = pe
    emu = Emu(path)
    # mapped image code is readable (first two bytes of add4: mov eax, ecx)
    assert emu.read_mem(A["add4"], 2) == b"\x8b\xc1"
    # malloc + write_mem + read_cstring round trip
    p = emu.malloc(16)
    emu.write_mem(p, b"abc\x00")
    assert emu.read_cstring(p) == "abc"
