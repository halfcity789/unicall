#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall._elf -- ELF loader (static/dynamic, PIE/non-PIE, x86/x64).

External symbol discovery: JUMP_SLOT / GLOB_DAT relocations with undefined
symbols in .rela.plt / .rela.dyn (and the 32-bit counterparts) get their GOT
slots redirected to the trampoline page.
"""
import struct

from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *

from ._core import EmuBase
from .shims import LIBC_SHIMS


class ELFEmu(EmuBase):
    PLATFORM = "elf"

    def _load(self, path, base):
        uc = Uc(self.cfg["arch"], self.cfg["mode"])
        self.uc = uc
        with open(path, "rb") as f:
            elf = ELFFile(f)
            etype = elf.header.e_type
            pref = next(elf.iter_segments())["p_vaddr"] & ~0xFFF
            # ET_EXEC: p_vaddr is absolute, bias = 0; ET_DYN: needs load bias
            self.bias = (base if base is not None else 0x400000) \
                if etype == "ET_DYN" else 0
            self.base = self.bias + pref
            self.is_pie = etype == "ET_DYN"
            self.entry = self.bias + elf.header.e_entry

            # 1) PT_LOAD segments
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                va = self.bias + seg["p_vaddr"]
                start = va & ~0xFFF
                end = (va + seg["p_memsz"] + 0xFFF) & ~0xFFF
                try:
                    uc.mem_map(start, end - start, UC_PROT_ALL)
                except UcError:
                    pass                          # same page as previous segment
                uc.mem_write(va, seg.data())

            # 2) Undefined symbols -> record GOT slots (redirected later,
            #    in one pass, by _install_trampoline)
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym is not None:
                for secname in (".rela.plt", ".rel.plt",
                                ".rela.dyn", ".rel.dyn"):
                    sec = elf.get_section_by_name(secname)
                    if sec is None:
                        continue
                    for r in sec.iter_relocations():
                        # GLOB_DAT/JMP_SLOT (x64) and GLOB_DAT/JMP_SLOT (x86)
                        if r["r_info_type"] not in (1, 5, 6, 7):
                            continue
                        sym = dynsym.get_symbol(r["r_info_sym"])
                        if not sym.name or sym["st_value"]:
                            continue              # defined inside the binary
                        self._imports[self.bias + r["r_offset"]] = sym.name

            # 3) PIE relative relocations
            if self.is_pie and self.bias:
                for secname in (".rela.dyn", ".rel.dyn"):
                    sec = elf.get_section_by_name(secname)
                    if sec is None:
                        continue
                    fmt = "<Q" if self.ptr == 8 else "<I"
                    for r in sec.iter_relocations():
                        if r["r_info_type"] in (3, 8):  # RELATIVE
                            got = self.bias + r["r_offset"]
                            (v,) = struct.unpack(fmt, uc.mem_read(got, self.ptr))
                            uc.mem_write(got, struct.pack(fmt, v + self.bias))
        self.image_end = self.base + 0x1000000

    def _setup_tls(self):
        """glibc TLS: fs:0x28 holds the stack canary (same offset on x86/x64)."""
        uc, cfg = self.uc, self.cfg
        uc.mem_map(cfg["tls"], 0x1000, UC_PROT_ALL)
        uc.mem_write(cfg["tls"] + 0x28, struct.pack("<Q", 0xDEADBEEFC0DEBAAD))
        uc.reg_write(UC_X86_REG_FS_BASE, cfg["tls"])

    def _install_default_shims(self):
        for imp in self._names:
            short = imp.split("!")[-1].split("@")[-1].lower()
            if short in LIBC_SHIMS and imp not in self.import_hooks:
                self.import_hooks[imp] = LIBC_SHIMS[short]

    def _default_conv(self):
        return "sysv" if self.mode64 else "cdecl"
