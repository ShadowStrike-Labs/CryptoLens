"""Compute and reverse common API-name hash schemes.

The reverse index covers frequently resolved Windows API and DLL names. The
module uses only the Python standard library.
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Dict, List, Tuple

from . import util

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def _mask(width: int) -> int:
    return M32 if width == 32 else M64


def _ror_add_width(data: bytes, rot: int, width: int) -> int:
    h = 0
    m = _mask(width)
    for b in data:
        h = (util.ror(h, rot, width) + b) & m
    return h


def _ror13_add(data: bytes) -> int:
    return _ror_add_width(data, 13, 32)


def _ror_add(rot: int, width: int = 32) -> Callable[[bytes], int]:
    return lambda data: _ror_add_width(data, rot, width)


def _multiply_add(data: bytes, multiplier: int, width: int,
                  seed: int = 0, use_xor: bool = False) -> int:
    h = seed
    m = _mask(width)
    for b in data:
        h = ((h * multiplier) ^ b if use_xor
             else (h * multiplier) + b) & m
    return h


def _djb2(data: bytes) -> int:
    return _multiply_add(data, 33, 32, seed=5381)


def _djb2_xor(data: bytes) -> int:
    return _multiply_add(data, 33, 32, seed=5381, use_xor=True)


def _sdbm(data: bytes) -> int:
    h = 0
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & M32
    return h


def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & M32
    return h


def _fnv1_32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h * 0x01000193) ^ b) & M32
    return h


def _sdbm64(data: bytes) -> int:
    h = 0
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & M64
    return h


def _fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & M64
    return h


def _fnv1_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h * 0x100000001B3) ^ b) & M64
    return h


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & M32


@dataclass(frozen=True)
class Scheme:
    name: str
    func: Callable[[bytes], int]
    note: str = ""
    width: int = 32


SCHEMES: Tuple[Scheme, ...] = (
    Scheme("ror13_add", _ror13_add, "classic shellcode block_api hash"),
    Scheme("ror7_add", _ror_add(7)),
    Scheme("ror11_add", _ror_add(11)),
    Scheme("ror9_add", _ror_add(9)),
    Scheme("djb2", _djb2),
    Scheme("djb2_xor", _djb2_xor),
    Scheme("sdbm", _sdbm),
    Scheme("bkdr131_32", lambda d: _multiply_add(d, 131, 32),
           "base-131 polynomial hash"),
    Scheme("fnv1a32", _fnv1a32),
    Scheme("fnv1_32", _fnv1_32),
    Scheme("crc32", _crc32),
    Scheme("ror13_add64", _ror_add(13, 64), width=64),
    Scheme("ror7_add64", _ror_add(7, 64), width=64),
    Scheme("ror11_add64", _ror_add(11, 64), width=64),
    Scheme("ror9_add64", _ror_add(9, 64), width=64),
    Scheme("djb2_64", lambda d: _multiply_add(d, 33, 64, seed=5381), width=64),
    Scheme("djb2_xor64", lambda d: _multiply_add(d, 33, 64, seed=5381,
                                                  use_xor=True), width=64),
    Scheme("sdbm64", _sdbm64, width=64),
    Scheme("bkdr131_64", lambda d: _multiply_add(d, 131, 64),
           "base-131 polynomial hash", 64),
    Scheme("fnv1a64", _fnv1a64, width=64),
    Scheme("fnv1_64", _fnv1_64, width=64),
)


WORDLIST: Tuple[str, ...] = (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
    "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "VirtualFree", "WinExec", "CreateProcessA", "CreateProcessW",
    "CreateThread", "CreateRemoteThread", "ExitProcess", "ExitThread",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
    "TerminateProcess", "GetCurrentProcess", "GetCurrentThread",
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
    "CreateFileMappingA", "MapViewOfFile",
 "GetProcessHeap",
    "HeapAlloc", "HeapFree", "RtlMoveMemory", "RtlZeroMemory",
    "GetTickCount", "Sleep", "GetLastError", "SetLastError",
    "LoadResource", "FindResourceA", "SizeofResource",
    "RegOpenKeyExA", "RegSetValueExA", "RegQueryValueExA", "RegCloseKey",
    "GetTempPathA", "ShellExecuteA", "URLDownloadToFileA",
    "InternetOpenA", "InternetOpenUrlA", "InternetReadFile",
    "HttpOpenRequestA", "HttpSendRequestA", "InternetConnectA",
    "WSAStartup", "WSASocketA", "socket", "connect", "send", "recv",
    "bind", "listen", "accept", "closesocket",
    "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt",
    "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
    "kernel32.dll", "ntdll.dll", "user32.dll", "ws2_32.dll",
    "advapi32.dll", "wininet.dll", "urlmon.dll", "shell32.dll",
)


def _variants(name: str) -> List[Tuple[str, bytes]]:
    """Return common case, terminator, and UTF-16LE representations."""
    narrow = name.encode("latin-1", "ignore")
    upper = name.upper().encode("latin-1", "ignore")
    wide = name.encode("utf-16-le", "ignore")
    upper_wide = name.upper().encode("utf-16-le", "ignore")
    candidates = (
        ("", narrow), ("+NUL", narrow + b"\x00"),
        ("upper", upper), ("upper+NUL", upper + b"\x00"),
        ("wide", wide), ("wide+NUL", wide + b"\x00\x00"),
        ("upper-wide", upper_wide),
        ("upper-wide+NUL", upper_wide + b"\x00\x00"),
    )
    out = []
    seen = set()
    for label, data in candidates:
        if data in seen:
            continue
        seen.add(data)
        out.append((label, data))
    return out


@dataclass(frozen=True)
class ApiHashHit:
    value: int
    scheme: str
    name: str
    variant: str
    note: str = ""
    width: int = 32


@lru_cache(maxsize=1)
def _reverse() -> Dict[Tuple[int, int], List[ApiHashHit]]:
    rev: Dict[Tuple[int, int], List[ApiHashHit]] = {}
    for scheme in SCHEMES:
        mask = _mask(scheme.width)
        for name in WORDLIST + EXTRA_WORDLIST:
            for vlabel, data in _variants(name):
                h = scheme.func(data) & mask
                rev.setdefault((scheme.width, h), []).append(
                    ApiHashHit(h, scheme.name, name, vlabel, scheme.note,
                               scheme.width))
    return rev


def identify(value: int, width: int = None) -> List[ApiHashHit]:
    """Return API-hash matches, optionally restricted to a bit width."""
    if width:
        widths = (width,)
    elif value < 0 or (M32 < value <= M64 and value >> 32 == M32):
        widths = (32, 64)  # signed or sign-extended 32-bit representation
    elif value > M32:
        widths = (64,)
    else:
        widths = (32, 64)
    out = []
    for candidate_width in widths:
        out.extend(_reverse().get(
            (candidate_width, value & _mask(candidate_width)), ()))
    return out


def hash_name(name: str, scheme: str = "ror13_add", variant: str = "") -> int:
    """Compute the hash of ``name`` under a named scheme/variant."""
    sm = {s.name: s for s in SCHEMES}[scheme]
    data = dict(_variants(name))[variant]
    return sm.func(data) & _mask(sm.width)


def list_schemes() -> List[str]:
    return [s.name for s in SCHEMES]


# Additional frequently hashed Win32 APIs / DLLs (loader & C2 behavior).
EXTRA_WORDLIST: Tuple[str, ...] = (
    "GetModuleHandleExA", "GetModuleFileNameW", "LoadLibraryExW",
    "FreeLibrary", "GetModuleHandleExW", "GetProcessImageFileNameA",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
    "NtReadVirtualMemory", "NtCreateThreadEx", "NtQueueApcThread",
    "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
    "NtResumeThread", "NtQuerySystemInformation", "NtOpenProcess",
    "RtlCreateUserThread", "RtlDecompressBuffer", "LdrLoadDll",
    "LdrGetProcedureAddress", "ZwClose", "VirtualQuery", "FlushInstructionCache",
    "GetThreadContext", "SetThreadContext", "SuspendThread", "ResumeThread",
    "QueueUserAPC", "WaitForSingleObject", "WaitForMultipleObjects",
    "CreateMutexA", "OpenMutexA", "CreateEventA", "GetComputerNameA",
    "GetUserNameA", "GetVersionExA", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "GetAdaptersInfo", "RegCreateKeyExA",
    "RegDeleteValueA", "RegEnumKeyExA", "CryptGenRandom", "CryptDestroyKey",
    "CryptImportKey", "CryptExportKey", "CryptAcquireContextW",
    "CoCreateInstance", "CoInitializeEx", "OleInitialize", "SHGetFolderPathA",
    "WNetAddConnection2A", "GetProcAddressForCaller", "WinHttpOpen",
    "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WinHttpReceiveResponse", "WinHttpReadData", "GetNativeSystemInfo",
    "VirtualAllocExNuma", "CreateToolhelp32Snapshot", "Process32First",
    "Process32Next", "Thread32First", "Module32First", "OpenThread",
    "advapi32", "kernel32", "ntdll", "user32", "ws2_32", "wininet",
    "kernelbase.dll", "shlwapi.dll", "crypt32.dll", "winhttp.dll",
)


def resolve(values, schemes=None):
    """Resolve integer or ``(value, width)`` candidates to API-hash hits."""
    rev = _reverse()
    scheme_map = {s.name: s for s in SCHEMES}
    want = set(schemes) if schemes else None
    allowed_widths = ({scheme_map[s].width for s in want if s in scheme_map}
                      if want else {32, 64})
    out: List[ApiHashHit] = []
    for item in values:
        if isinstance(item, tuple) and len(item) == 2:
            value, explicit_width = item
            widths = {explicit_width} & allowed_widths
        else:
            value = item
            if want:
                widths = allowed_widths
            elif value < 0 or (M32 < value <= M64 and value >> 32 == M32):
                widths = {32, 64}
            elif value <= M32:
                widths = {32}
            else:
                widths = {64}
        for width in widths:
            normalized = value & _mask(width)
            for hit in rev.get((width, normalized), ()):
                if want and hit.scheme not in want:
                    continue
                out.append(hit)
    return out
