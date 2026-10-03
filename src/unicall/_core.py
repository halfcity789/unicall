#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicall._core -- platform-independent core machinery.

Contents: memory layout configuration, emulation environment (stack / heap /
scratch / TLS), import trampoline dispatch, calling conventions (SysV x64 /
Win x64 / cdecl x86), argument placement, safe exception channel, and debug
tracing. Platform differences (loader, TLS layout, default shim matching)
are implemented by subclasses through the following methods:

    _load(path, base)          # map the image, fill self._imports
    _setup_tls()               # TLS / TEB environment
    _install_default_shims()   # platform-specific default shim matching
    _default_conv()            # default calling convention
"""
import inspect
import struct

from unicorn import *
from unicorn.x86_const import *

try:
    import capstone as _cs
except ImportError:          # pragma: no cover
    _cs = None


class StopEmulation(Exception):
    """Raised inside a shim/hook to abort the current emu.call() cleanly."""


# ---------------------------------------------------------------------------
# Memory layout (x64 / x86). Individual regions can be overridden via
# constructor arguments in case of address-space conflicts.
# ---------------------------------------------------------------------------
CFG_X64 = dict(
    arch=UC_ARCH_X86, mode=UC_MODE_64, ptr=8,
    stack=0x7FF000000000, stack_size=0x200000,
    heap=0x10000000, heap_size=0x1000000,
    hook_page=0x70000000, ret_magic=0x5F000000,
    scratch=0x30000000, scratch_size=0x200000,
    tls=0x7FE000000000,
)
CFG_X86 = dict(
    arch=UC_ARCH_X86, mode=UC_MODE_32, ptr=4,
    stack=0x7F000000, stack_size=0x100000,
    heap=0x10000000, heap_size=0x1000000,
    hook_page=0x70000000, ret_magic=0x5F000000,
    scratch=0x30000000, scratch_size=0x200000,
    tls=0x7E000000,
)

ARGREGS = {
    "sysv": [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
             UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9],
    "win": [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9],
}


class EmuBase:
    PLATFORM = "?"

    def __init__(self, path, base=None, arch=UC_MODE_64,
                 hook_page=None, heap=None, stack=None, scratch=None,
                 strict_imports=True):
        """base: load base (only meaningful for PIE / relocated images;
        defaults keep addresses identical to what IDA displays).
        arch: UC_MODE_64 or UC_MODE_32.
        strict_imports: raise when an unhooked import is called (False means
        log a warning and return 0)."""
        self.strict = strict_imports
        self.cfg = dict(CFG_X64 if arch == UC_MODE_64 else CFG_X86)
        for k, v in (("hook_page", hook_page), ("heap", heap),
                     ("stack", stack), ("scratch", scratch)):
            if v is not None:
                self.cfg[k] = v
        self.path = path
        self.mode64 = arch == UC_MODE_64
        self.ptr = self.cfg["ptr"]
        self.import_hooks = {}      # import name -> callable / constant
        self.heap_sizes = {}        # heap pointer -> allocation size (realloc)
        self.rand_state = 0x5EED
        self.last_insn = None
        self._pending = None
        self._dispatch_conv = "sysv"

        self._imports = {}          # slot address -> symbol name
        self._load(path, base)
        self._setup_env()
        self._install_trampoline()
        self._install_default_shims()

    # ------------------------------------------------------------ platform API
    def _load(self, path, base):                       # pragma: no cover
        raise NotImplementedError

    def _setup_tls(self):                              # pragma: no cover
        raise NotImplementedError

    def _install_default_shims(self):                  # pragma: no cover
        raise NotImplementedError

    def _default_conv(self):                           # pragma: no cover
        raise NotImplementedError

    # ------------------------------------------------------------ environment
    def _setup_env(self):
        uc, cfg = self.uc, self.cfg
        uc.mem_map(cfg["stack"], cfg["stack_size"], UC_PROT_ALL)
        uc.mem_map(cfg["heap"], cfg["heap_size"], UC_PROT_ALL)
        uc.mem_map(cfg["scratch"], cfg["scratch_size"], UC_PROT_ALL)
        uc.mem_map(cfg["hook_page"], 0x10000, UC_PROT_ALL)
        uc.mem_map(cfg["ret_magic"] & ~0xFFF, 0x1000, UC_PROT_ALL)
        uc.mem_write(cfg["ret_magic"], b"\xC3")
        self._setup_tls()
        self.heap_ptr = cfg["heap"] + 0x1000
        self.scratch_ptr = cfg["scratch"] + 0x1000

    def _install_trampoline(self):
        """Redirect every external symbol slot to a single dispatch page."""
        cfg = self.cfg
        names = sorted({n for n in self._imports.values()})
        self._by_name = {n: cfg["hook_page"] + i * 16 for i, n in enumerate(names)}
        self._names = names
        for slot in self._by_name.values():
            self.uc.mem_write(slot, b"\xC3")
        for slot, name in self._imports.items():
            self.uc.mem_write(slot, struct.pack(
                "<Q" if self.ptr == 8 else "<I", self._by_name[name]))
        self.uc.hook_add(UC_HOOK_CODE, self._dispatch,
                         begin=cfg["hook_page"], end=cfg["hook_page"] + 0x10000)

    # ------------------------------------------------------------ public API
    def hook_import(self, name, fn):
        """Register an import hook. `name` accepts a short symbol name such
        as 'malloc' (case-insensitive). `fn` receives `emu` as its first
        argument followed by the call arguments; its return value is written
        to RAX (return None to leave RAX untouched). Raise StopEmulation
        inside fn to abort emulation."""
        key = next((n for n in self._names
                    if self._match_name(n, name)), None)
        if key is None:
            raise KeyError(f"binary has no import matching {name!r}; "
                           f"known: {self._names}")
        self.import_hooks[key] = fn

    def _match_name(self, import_name, query):
        return import_name.lower() == query.lower()

    def hook_skip(self, addr, fn):
        """Intercept an internal function by address: return immediately when
        execution reaches `addr`. `fn` is either callable(emu, *args) or a
        constant return value."""
        def cb(mu, a, size, ud):
            args = self._read_args(self._nparams(fn), self._default_conv())
            r = self._run_shim(fn, args)
            if r is not None:
                mu.reg_write(UC_X86_REG_RAX if self.mode64 else UC_X86_REG_EAX,
                             r & ((1 << (self.ptr * 8)) - 1))
            self._pop_return(mu)
        self.uc.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    def call(self, addr, args=(), convention=None, ret="int",
             timeout=None, max_instr=200_000_000):
        """Call a function. Argument elements: int (value, or an address
        inside the mapped image) / bytes / bytearray / str (the latter are
        placed into scratch memory automatically and passed as pointers).
        convention: 'sysv' | 'win' | 'cdecl' (default chosen per platform
        and bitness). ret: 'int' returns RAX; 'str' reads the C string
        pointed to by RAX.

        timeout: wall-clock limit in seconds. Keep it None (no timer) for
        short calls: arming a nonzero timeout costs ~15 ms per call on
        Windows due to the system timer resolution. max_instr always guards
        against runaway code regardless of timeout."""
        conv = convention or self._default_conv()
        self._pending = None
        vals = [self._place_arg(a) for a in args]
        uc = self.uc
        rsp = (self.cfg["stack"] + self.cfg["stack_size"] - 0x10000) & ~0xF

        if self.mode64:
            if conv == "win":
                regs = ARGREGS["win"]
                stack_args = vals[4:]
                frame = 0x20 + 8 * len(stack_args)          # shadow space
            elif conv == "sysv":
                regs = ARGREGS["sysv"]
                stack_args = vals[6:]
                frame = 8 * len(stack_args)
            else:
                raise ValueError(f"x64 unsupported convention {conv!r}")
            for r, v in zip(regs, vals):
                uc.reg_write(r, v & ((1 << 64) - 1))
            rsp = rsp - 8 - ((frame + 15) & ~0xF)
            uc.mem_write(rsp, struct.pack("<Q", self.cfg["ret_magic"]))
            if conv == "win":
                uc.mem_write(rsp + 8, b"\x00" * 0x20)       # zero shadow space
                for i, v in enumerate(stack_args):
                    uc.mem_write(rsp + 8 + 0x20 + i * 8, struct.pack("<Q", v))
            elif stack_args:
                uc.mem_write(rsp + 8,
                             b"".join(struct.pack("<Q", v) for v in stack_args))
        else:   # x86: arguments pushed right to left
            if conv not in ("cdecl", "win"):
                raise ValueError(f"x86 unsupported convention {conv!r}")
            for v in reversed(vals):
                rsp -= self.ptr
                uc.mem_write(rsp, struct.pack("<I", v & 0xFFFFFFFF))
            rsp -= self.ptr
            uc.mem_write(rsp, struct.pack("<I", self.cfg["ret_magic"]))

        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.emu_start(addr, self.cfg["ret_magic"],
                     timeout=0 if timeout is None else int(timeout * 1_000_000),
                     count=max_instr)
        if self._pending is not None:
            raise self._pending
        rip = uc.reg_read(UC_X86_REG_RIP)
        if rip != self.cfg["ret_magic"]:
            raise RuntimeError(
                f"function @ {addr:#x} did not return (RIP={rip:#x}, "
                f"last insn {self.last_insn}); increase max_instr, check "
                f"hooks, or use enable_trace() to locate the issue")
        rax = uc.reg_read(UC_X86_REG_RAX if self.mode64 else UC_X86_REG_EAX)
        if ret == "str":
            return self.read_cstring(rax)
        return rax

    # ------------------------------------------------------------ memory helpers
    def malloc(self, n, zero=False):
        """Allocate n bytes on the emulated heap (Python-side bump
        allocator) and return the pointer."""
        p = self.heap_ptr
        self.heap_ptr = (p + n + 15) & ~15
        self.heap_sizes[p] = n
        if zero:
            self.uc.mem_write(p, b"\x00" * n)
        return p

    def read_mem(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def write_mem(self, addr, data):
        self.uc.mem_write(addr, data)

    def read_cstring(self, ptr, maxlen=4096):
        out = bytearray()
        while len(out) < maxlen:
            chunk = self.uc.mem_read(ptr + len(out), 64)
            if b"\x00" in chunk:
                out += chunk[:chunk.index(b"\x00")]
                break
            out += chunk
        return bytes(out).decode("utf-8", errors="replace")

    # ------------------------------------------------------------ internals
    def _place_arg(self, a):
        if isinstance(a, str):
            a = a.encode("utf-8") + b"\x00"
        if isinstance(a, (bytes, bytearray)):
            p = self.scratch_ptr
            self.uc.mem_write(p, bytes(a))
            self.scratch_ptr = (p + len(a) + 15) & ~15
            return p
        return int(a)

    def _nparams(self, fn):
        """Number of user arguments of a shim (excluding the leading emu)."""
        if not callable(fn) or inspect.isbuiltin(fn):
            return 0
        try:
            n = fn.__code__.co_argcount
        except AttributeError:
            return 0
        if inspect.ismethod(fn):
            n -= 1                      # bound self already supplied
        return max(0, n - 1)            # first formal parameter is emu

    def _read_args(self, n, conv):
        """Read n arguments per convention from the current context (used by
        both the import trampoline and hook_skip; rsp points at the return
        address at this point)."""
        uc = self.uc
        rsp = uc.reg_read(UC_X86_REG_RSP)
        vals = []
        if self.mode64:
            regs = ARGREGS["win" if conv == "win" else "sysv"]
            for i in range(n):
                if i < len(regs):
                    vals.append(uc.reg_read(regs[i]))
                elif conv == "win":
                    (v,) = struct.unpack(
                        "<Q", uc.mem_read(rsp + 8 + 0x20 + (i - 4) * 8, 8))
                    vals.append(v)
                else:
                    (v,) = struct.unpack("<Q", uc.mem_read(rsp + 8 + i * 8, 8))
                    vals.append(v)
        else:
            for i in range(n):
                (v,) = struct.unpack("<I", uc.mem_read(rsp + 4 + i * 4, 4))
                vals.append(v)
        return vals

    def _run_shim(self, fn, args):
        n = self._nparams(fn)
        if inspect.ismethod(fn):
            return fn(*args[:n])
        if callable(fn):
            return fn(self, *args[:n])
        return fn

    def _pop_return(self, mu):
        rsp = mu.reg_read(UC_X86_REG_RSP)
        (ret,) = struct.unpack("<Q" if self.ptr == 8 else "<I",
                               mu.mem_read(rsp, self.ptr))
        mu.reg_write(UC_X86_REG_RSP, rsp + self.ptr)
        mu.reg_write(UC_X86_REG_RIP, ret)

    def _dispatch(self, mu, address, size, ud):
        """Unified trampoline dispatch: every external symbol call lands here."""
        try:
            idx = (address - self.cfg["hook_page"]) // 16
            if idx >= len(self._names):
                return
            name = self._names[idx]
            fn = self.import_hooks.get(name)
            if fn is None:
                msg = (f"unhooked import called: {name} "
                       f"(register with emu.hook_import({name!r}, ...))")
                if self.strict:
                    raise StopEmulation(msg)
                print(f"[unicall] WARNING: {msg} -> returning 0")
                mu.reg_write(UC_X86_REG_RAX, 0)
                self._pop_return(mu)
                return
            args = self._read_args(self._nparams(fn), self._dispatch_conv)
            r = self._run_shim(fn, args)
            if r is not None:
                mu.reg_write(UC_X86_REG_RAX if self.mode64 else UC_X86_REG_EAX,
                             r & ((1 << (self.ptr * 8)) - 1))
            self._pop_return(mu)
        except Exception as ex:     # unified safe exit: jump to RET_MAGIC
            self._pending = ex
            mu.reg_write(UC_X86_REG_RIP, self.cfg["ret_magic"])

    # ------------------------------------------------------------ debugging
    def enable_trace(self, on=True, limit=500):
        """Print every instruction (disassembled with capstone) to locate
        where emulation goes off the rails."""
        if not on or _cs is None:
            return
        md = _cs(_cs.CS_ARCH_X86,
                 _cs.CS_MODE_64 if self.mode64 else _cs.CS_MODE_32)
        state = {"n": 0}

        def cb(mu, addr, size, ud):
            if state["n"] >= limit:
                raise StopEmulation(f"trace limit reached at {addr:#x}")
            try:
                ins = next(md.disasm(self.read_mem(addr, size), addr))
                print(f"[trace] {addr:#x}  {ins.mnemonic} {ins.op_str}")
            except StopIteration:
                print(f"[trace] {addr:#x}  <bad>")
            state["n"] += 1
            self.last_insn = f"{addr:#x}"
        self.uc.hook_add(UC_HOOK_CODE, cb)
