#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall._pe -- PE loader (PE32+ / PE32, x64/x86).

Parses DOS/NT headers, maps sections, applies .reloc base relocations
(DIR64/HIGHLOW), parses the import directory (INT/IAT) and redirects IAT
slots to the trampoline page. Delay-load imports are not supported yet
(internal thunks can be neutralized with hook_skip).
"""
import struct

from unicorn import *
from unicorn.x86_const import *

from ._core import EmuBase
from .shims import LIBC_SHIMS, WINAPI_SHIMS


class PEEmu(EmuBase):
    PLATFORM = "pe"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._dispatch_conv = "win"   # read IAT trampoline args per Win x64

    def _load(self, path, base):
        data = open(path, "rb").read()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        assert data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00", "not a PE file"
        coff = e_lfanew + 4
        machine, nsec = struct.unpack_from("<HH", data, coff)
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        pe32p = magic == 0x20B
        if pe32p != self.mode64:        # trust the actual file format
            self.mode64 = pe32p
            self.cfg = dict(CFG_X64 if pe32p else CFG_X86)
            self.ptr = self.cfg["ptr"]
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        if pe32p:
            imagebase = struct.unpack_from("<Q", data, opt + 24)[0]
            off_dd, off_nrva = opt + 112, opt + 108
        else:
            imagebase = struct.unpack_from("<I", data, opt + 28)[0]
            off_dd, off_nrva = opt + 96, opt + 92
        # Offsets are identical across both formats from SectionAlignment on
        sec_align = struct.unpack_from("<I", data, opt + 32)[0]
        size_image = struct.unpack_from("<I", data, opt + 56)[0]
        self.imagebase = imagebase
        self.load_base = base if base is not None else imagebase
        self.entry = self.load_base + entry
        self._sizeof_headers = struct.unpack_from("<I", data, opt + 60)[0]
        dd_count = struct.unpack_from("<I", data, off_nrva)[0]
        dds = [struct.unpack_from("<II", data, off_dd + i * 8)
               for i in range(min(dd_count, 16))]

        uc = Uc(self.cfg["arch"], self.cfg["mode"])
        self.uc = uc

        # Map the whole image (headers included), then fill in the sections
        img_size = (size_image + 0xFFF) & ~0xFFF
        uc.mem_map(self.load_base, img_size, UC_PROT_ALL)
        uc.mem_write(self.load_base, data[:self._sizeof_headers])

        self._sections = []
        sec_tbl = opt + size_opt
        for i in range(nsec):
            o = sec_tbl + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode(errors="replace")
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, o + 8)
            self._sections.append(dict(name=name, va=va, vsize=vsize,
                                       rawsize=rawsize, raw=raw))
            uc.mem_write(self.load_base + va, data[raw:raw + rawsize])

        # Base relocations
        delta = self.load_base - imagebase
        if delta and len(dds) > 5 and dds[5][0]:
            rva, rsize = dds[5]
            off = self._rva2off(rva)
            end = off + rsize
            while off < end:
                page, blk = struct.unpack_from("<II", data, off)
                if blk == 0:
                    break
                for i in range((blk - 8) // 2):
                    e = struct.unpack_from("<H", data, off + 8 + i * 2)[0]
                    typ, o2 = e >> 12, e & 0xFFF
                    if typ == 0:
                        continue
                    tgt = self.load_base + page + o2
                    if typ == 10 and self.ptr == 8:            # DIR64
                        (v,) = struct.unpack("<Q", uc.mem_read(tgt, 8))
                        uc.mem_write(tgt, struct.pack("<Q", (v + delta) & (2**64 - 1)))
                    elif typ == 3 and self.ptr == 4:           # HIGHLOW
                        (v,) = struct.unpack("<I", uc.mem_read(tgt, 4))
                        uc.mem_write(tgt, struct.pack("<I", (v + delta) & 0xFFFFFFFF))
                off += blk

        # Import directory -> {IAT slot: "dll!function"}
        if len(dds) > 1 and dds[1][0]:
            off = self._rva2off(dds[1][0])
            while True:
                oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, off)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                dll = data[self._rva2off(name_rva):].split(b"\x00")[0].decode(errors="replace")
                thunk = self._rva2off(oft or ft)
                slot_rva = ft
                hi = 1 << (63 if self.ptr == 8 else 31)
                while True:
                    fmt = "<Q" if self.ptr == 8 else "<I"
                    (t,) = struct.unpack_from(fmt, data, thunk)
                    if t == 0:
                        break
                    if not (t & hi):
                        noff = self._rva2off(t & (hi - 1))
                        fname = data[noff + 2:].split(b"\x00")[0].decode(errors="replace")
                        self._imports[self.load_base + slot_rva] = f"{dll}!{fname}"
                    thunk += self.ptr
                    slot_rva += self.ptr
                off += 20

    def _rva2off(self, rva):
        for sec in self._sections:
            if sec["va"] <= rva < sec["va"] + max(sec["vsize"], sec["rawsize"]):
                return sec["raw"] + (rva - sec["va"])
        if rva < self._sizeof_headers:
            return rva
        return None

    def _setup_tls(self):
        """Windows TEB/PEB: x64 uses gs (0x30 TEB self / 0x60 PEB),
        x86 uses fs (0x18 / 0x30)."""
        uc, cfg = self.uc, self.cfg
        uc.mem_map(cfg["tls"], 0x3000, UC_PROT_ALL)
        teb, peb = cfg["tls"], cfg["tls"] + 0x1000
        if self.mode64:
            uc.mem_write(teb + 0x30, struct.pack("<Q", teb))
            uc.mem_write(teb + 0x60, struct.pack("<Q", peb))
            uc.reg_write(UC_X86_REG_GS_BASE, teb)
        else:
            uc.mem_write(teb + 0x18, struct.pack("<I", teb))
            uc.mem_write(teb + 0x30, struct.pack("<I", peb))
            uc.reg_write(UC_X86_REG_FS_BASE, teb)

    def _install_default_shims(self):
        for imp in self._names:
            d, _, f = imp.partition("!")
            key = (d.lower(), f.lower())
            impl = WINAPI_SHIMS.get(key) or (
                LIBC_SHIMS.get(f.lower())
                if d.lower() in ("msvcrt.dll", "ucrtbase.dll", "ntdll.dll")
                else None)
            if impl and imp not in self.import_hooks:
                self.import_hooks[imp] = impl

    def _default_conv(self):
        return "win" if self.mode64 else "cdecl"
