#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Benchmark: measure unicall cold start (image mapping) and per-call overhead.

    uv run python bench/bench_speed.py [sample path]

Reference numbers (2026-10, Windows 11, Python 3.14, unicorn 2.1.4):
  ELF mapping (RotaJakiro, 2.2MB image)    ~25 ms, one-time
  ELF single str_decrypt (48B, AES-256)    ~3 ms
  PE single add4 (register-only function)  ~15 us (lower bound of call())
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from pe_builder import build_test_pe          # noqa: E402
from unicall import Emu                      # noqa: E402

SAMPLE = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    "UNICALL_SAMPLE",
    r"RotaJakiro.malware")


def bench(fn, n, label):
    fn()                                      # warm up
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    dt = time.perf_counter() - t0
    print(f"  {label:<52} {dt / n * 1e3:9.3f} ms/call  (x{n})")
    return dt / n


def main():
    import unicorn
    import capstone
    print(f"unicorn {unicorn.__version__} / capstone {capstone.__version__}")
    print("unicall benchmark\n" + "-" * 78)

    # ---- PE: minimal image, measures the lower bound of call() overhead ----
    pe_path = os.path.join(os.path.dirname(__file__), "_bench_test.pe")
    A = build_test_pe(pe_path)
    emu = Emu(pe_path)
    print("[PE] add4 (four register arguments, pure addition)")
    bench(lambda: emu.call(A["add4"], [1, 2, 3, 4]), 2000,
          "call() total overhead")

    # ---- ELF: real sample, cold start and decryption throughput ----
    try:
        raw = open(SAMPLE, "rb").read()
    except OSError:
        print(f"[ELF] skipped: sample not found at {SAMPLE}")
        os.remove(pe_path)
        return

    t0 = time.perf_counter()
    emu = Emu(SAMPLE)
    t_load = (time.perf_counter() - t0) * 1e3
    print("[ELF] RotaJakiro (130KB file / 2.2MB mapped image)")
    print(f"  {'Emu() cold start (load + env + hooks)':<52} {t_load:9.1f} ms      (x1)")

    blob = raw[0x4187E0 - 0x400000:0x4187E0 - 0x400000 + 0xE0]
    key = raw[0x1F300:0x1F308]

    def decrypt():
        return emu.call(0x402B80, [blob, 0xE0, 0xDE, key, 8], ret="str")

    assert "system-daemon" in decrypt()
    per = bench(decrypt, 100, "single str_decrypt (AES-256, 3 blocks)")
    print(f"\n  -> decrypting all 60 call sites takes ~{per * 60 * 1e3:.0f} ms "
          f"(excluding cold start)")
    os.remove(pe_path)


if __name__ == "__main__":
    main()
