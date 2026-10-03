#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unicall.shims -- built-in default implementations for external symbols."""

from ._core import StopEmulation


# ---- generic memory/string shims (ELF short names; also used by PE) --------
def sh_malloc(e, n): return e.malloc(n)
def sh_calloc(e, n, sz): return e.malloc(n * sz, zero=True)
def sh_realloc(e, p, n):
    if not p:
        return e.malloc(n)
    old = e.heap_sizes.get(p, n)
    q = e.malloc(n)
    e.write_mem(q, e.read_mem(p, min(old, n)))
    return q
def sh_free(e, p): pass
def sh_memcpy(e, d, s, n):
    if n:
        e.write_mem(d, e.read_mem(s, n))
    return d
def sh_memset(e, d, c, n):
    if n:
        e.write_mem(d, bytes([c & 0xFF]) * n)
    return d
def sh_strlen(e, p): return len(e.read_cstring(p))
def sh_rand(e):
    e.rand_state = (e.rand_state * 1103515245 + 12345) & 0x7FFFFFFF
    return e.rand_state
def sh_srand(e, s): e.rand_state = s & 0x7FFFFFFF
def sh_puts(e, p):
    s = e.read_cstring(p)
    print(f"[unicall] puts: {s!r}")
    return len(s) + 1
def sh_printf(e, fmt, *a):
    print(f"[unicall] printf: {e.read_cstring(fmt)!r} {a}")
    return 0
def sh_chkfail(e): raise StopEmulation("__stack_chk_fail: canary mismatch")
def sh_exit(e, c): raise StopEmulation(f"exit({c})")

LIBC_SHIMS = {
    "malloc": sh_malloc, "calloc": sh_calloc, "realloc": sh_realloc,
    "free": sh_free, "memcpy": sh_memcpy, "memset": sh_memset,
    "memmove": sh_memcpy, "strlen": sh_strlen, "rand": sh_rand,
    "srand": sh_srand, "puts": sh_puts, "printf": sh_printf,
    "__stack_chk_fail": sh_chkfail, "exit": sh_exit,
}


# ---- Windows API shims (matched by lowercased "dll!function") --------------
def sh_getlasterror(e): return 0
def sh_getcurrentprocess(e): return 0xFFFF0001
def sh_sleep(e, ms): return 0                       # no real sleeping
def sh_exitprocess(e, code): raise StopEmulation(f"ExitProcess({code})")
def sh_lstrlen(e, p): return len(e.read_cstring(p).split("\x00")[0])
def sh_lstrlenw(e, p):                              # UTF-16LE
    raw = e.read_mem(p, 4096)
    s = raw.split(b"\x00\x00")[0].decode("utf-16-le", errors="replace")
    return len(s)

WINAPI_SHIMS = {
    ("kernel32.dll", "getlasterror"): sh_getlasterror,
    ("kernel32.dll", "getcurrentprocess"): sh_getcurrentprocess,
    ("kernel32.dll", "sleep"): sh_sleep,
    ("kernel32.dll", "exitprocess"): sh_exitprocess,
    ("kernel32.dll", "lstrlena"): sh_lstrlen,
    ("kernel32.dll", "lstrlen"): sh_lstrlen,
    ("kernel32.dll", "lstrlenw"): sh_lstrlenw,
}
