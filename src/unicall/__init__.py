#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall -- function-level Unicorn emulation framework (PE / ELF, x86 / x64).

Maps a binary into Unicorn, redirects external symbols (GOT/IAT) to Python
implementable trampolines, and calls arbitrary functions with a single
call() statement. Intended for malware string decryption, algorithm
extraction, deobfuscation and CTF work, without reimplementing crypto or
building a full runtime environment.

Quick start:
    from unicall import Emu
    emu = Emu("sample.bin")                    # ELF / PE detected by magic
    out = emu.call(0x402B80, [blob, 48, 35, key, 8], ret="str")

Platform selection is also available explicitly:
    from unicall import ELFEmu, PEEmu
"""
from ._core import EmuBase, StopEmulation
from ._elf import ELFEmu
from ._pe import PEEmu

__version__ = "0.1.0"
__all__ = ["Emu", "ELFEmu", "PEEmu", "EmuBase", "StopEmulation", "__version__"]


def Emu(path, **kwargs):
    """Select the ELF / PE loader automatically by file magic.
    kwargs are forwarded to ELFEmu / PEEmu."""
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic[:2] == b"MZ":
        return PEEmu(path, **kwargs)
    if magic == b"\x7fELF":
        return ELFEmu(path, **kwargs)
    raise ValueError(f"unsupported file format (magic={magic!r}): {path}")
