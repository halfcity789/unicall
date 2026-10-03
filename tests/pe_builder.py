# -*- coding: utf-8 -*-
"""Test helper: build a minimal PE32+ in memory (IAT with two imports)."""
import struct


def build_test_pe(path):
    FILE_ALIGN, SEC_ALIGN = 0x200, 0x1000
    BASE = 0x400000
    RVA_CODE = 0x1000
    RVA_IAT, RVA_IMP, RVA_INT, RVA_NAMES, RVA_DLL = \
        0x2000, 0x2020, 0x2050, 0x2070, 0x20A0

    # add4 @0x00; call_imp @0x10 (call @0x14 -> IAT[0]); echo @0x24
    # (call @0x28 -> IAT[1]); add5 @0x40 (5th arg on stack at [rsp+0x28])
    code = bytearray(bytes.fromhex(
        "8bc1"          # mov eax, ecx
        "03c2"          # add eax, edx
        "4103c0"        # add eax, r8d
        "4103c1"        # add eax, r9d
        "c3"            # ret
        + "90" * 5
        + "4883ec28"    # sub rsp, 0x28
        + "ff15" + "00000000"
        + "4883c428"    # add rsp, 0x28
        + "ffc0"        # inc eax
        + "c3"
        + "90" * 3
        + "4883ec28"    # sub rsp, 0x28
        + "ff15" + "00000000"
        + "4883c428"
        + "c3"
        + "90" * (0x40 - 0x33)
        + "8bc1" "03c2" "4103c0" "4103c1"
        + "03442428"    # add eax, [rsp+0x28]
        + "c3"
    ))

    def fix_call(code_off, iat):
        rip = RVA_CODE + code_off + 6
        struct.pack_into("<i", code, code_off + 2, iat - rip)

    fix_call(0x14, RVA_IAT)
    fix_call(0x28, RVA_IAT + 8)

    raw_size = 0x1200
    raw = bytearray(raw_size)
    off = lambda rva: rva - RVA_CODE
    raw[0:len(code)] = code
    struct.pack_into("<IIIII", raw, off(RVA_IMP), RVA_INT, 0, 0, RVA_DLL, RVA_IAT)
    struct.pack_into("<IIIII", raw, off(RVA_IMP) + 20, 0, 0, 0, 0, 0)
    n1, n2 = RVA_NAMES, RVA_NAMES + 2 + len(b"magic_number\x00")
    struct.pack_into("<QQQ", raw, off(RVA_INT), n1, n2, 0)
    raw[off(RVA_NAMES):off(RVA_NAMES) + 15] = struct.pack("<H", 0) + b"magic_number\x00"
    raw[off(n2):off(n2) + 11] = struct.pack("<H", 0) + b"lstrlenA\x00"
    raw[off(RVA_DLL):off(RVA_DLL) + 9] = b"fake.dll\x00"

    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"                                   # DOS magic
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    pe = 0x80
    hdr[pe:pe + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", hdr, pe + 4, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = pe + 24
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<I", hdr, opt + 16, RVA_CODE)
    struct.pack_into("<Q", hdr, opt + 24, BASE)
    struct.pack_into("<I", hdr, opt + 32, SEC_ALIGN)
    struct.pack_into("<I", hdr, opt + 36, FILE_ALIGN)
    struct.pack_into("<I", hdr, opt + 56, 0x3000)
    struct.pack_into("<I", hdr, opt + 60, 0x400)
    struct.pack_into("<H", hdr, opt + 68, 3)
    struct.pack_into("<I", hdr, opt + 108, 2)
    struct.pack_into("<II", hdr, opt + 112 + 8, RVA_IMP, RVA_NAMES + 26 + 9 - RVA_IMP)
    sec = opt + 0xF0
    hdr[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", hdr, sec + 8, 0x2100, RVA_CODE, raw_size, 0x400)
    struct.pack_into("<I", hdr, sec + 36, 0x60000020)

    with open(path, "wb") as f:
        f.write(bytes(hdr) + bytes(raw))

    return dict(base=BASE, add4=BASE + 0x1000, call_imp=BASE + 0x1010,
                echo=BASE + 0x1024, add5=BASE + 0x1040)
