"""API-name hashing schemes used by shellcode / PIC loaders.

Runtime values are often hashes of API names (classic kernel32!GetProcAddress
resolved by hash). This builds a reverse map over common API/DLL names so the
lookup panel can answer "0x7C0DFCAA -> ror13_add('GetProcAddress')".
Pure Python (zlib from stdlib for CRC-32).
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Dict, List, Tuple

from . import util

M32 = 0xFFFFFFFF


def _ror13_add(data: bytes) -> int:
    h = 0
    for b in data:
        h = (util.ror(h, 13, 32) + b) & M32
    return h


def _ror_add(rot: int) -> Callable[[bytes], int]:
    def f(data: bytes) -> int:
        h = 0
        for b in data:
            h = (util.ror(h, rot, 32) + b) & M32
        return h
    return f


def _djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = ((h * 33) + b) & M32
    return h


def _djb2_xor(data: bytes) -> int:
    h = 5381
    for b in data:
        h = ((h * 33) ^ b) & M32
    return h


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


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & M32


@dataclass(frozen=True)
class Scheme:
    name: str
    func: Callable[[bytes], int]
    note: str = ""


SCHEMES: Tuple[Scheme, ...] = (
    Scheme("ror13_add", _ror13_add, "classic shellcode block_api hash"),
    Scheme("ror7_add", _ror_add(7)),
    Scheme("ror11_add", _ror_add(11)),
    Scheme("ror9_add", _ror_add(9)),
    Scheme("djb2", _djb2),
    Scheme("djb2_xor", _djb2_xor),
    Scheme("sdbm", _sdbm),
    Scheme("fnv1a32", _fnv1a32),
    Scheme("fnv1_32", _fnv1_32),
    Scheme("crc32", _crc32),
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
    """Byte encodings a loader might hash: as-is, +NUL, uppercase, wide."""
    out = [
        ("", name.encode("latin-1", "ignore")),
        ("+NUL", name.encode("latin-1", "ignore") + b"\x00"),
        ("upper", name.upper().encode("latin-1", "ignore")),
        ("wide", name.encode("utf-16-le", "ignore")),
    ]
    return out


@dataclass(frozen=True)
class ApiHashHit:
    value: int
    scheme: str
    name: str
    variant: str
    note: str = ""


@lru_cache(maxsize=1)
def _reverse() -> Dict[int, List[ApiHashHit]]:
    rev: Dict[int, List[ApiHashHit]] = {}
    for scheme in SCHEMES:
        for name in WORDLIST + EXTRA_WORDLIST:
            for vlabel, data in _variants(name):
                h = scheme.func(data) & M32
                rev.setdefault(h, []).append(
                    ApiHashHit(h, scheme.name, name, vlabel, scheme.note))
    return rev


def identify(value: int, width: int = 32) -> List[ApiHashHit]:
    """Return API-hash matches for a value (checked as 32-bit)."""
    return list(_reverse().get(value & M32, []))


def hash_name(name: str, scheme: str = "ror13_add", variant: str = "") -> int:
    """Compute the hash of ``name`` under a named scheme/variant."""
    sm = {s.name: s for s in SCHEMES}[scheme]
    data = dict(_variants(name))[variant]
    return sm.func(data) & M32


def list_schemes() -> List[str]:
    return [s.name for s in SCHEMES]


# Additional frequently hashed Win32 APIs / DLLs (loader & C2 behaviour).
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
    """Resolve integer values to API-hash hits, optionally filtered by scheme.

    ``values``  - iterable of candidate hash integers (e.g. function immediates)
    ``schemes`` - optional iterable of scheme ids (from
                  ``structure.detect_hash_schemes``) to avoid force-fitting a
                  value to an unrelated scheme.
    """
    rev = _reverse()
    want = set(schemes) if schemes else None
    out: List[ApiHashHit] = []
    for v in values:
        for hit in rev.get(v & M32, []):
            if want and hit.scheme not in want:
                continue
            out.append(hit)
    return out
