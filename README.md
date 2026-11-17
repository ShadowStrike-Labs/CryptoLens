# CryptoLens

CryptoLens is an IDA Pro plugin and standalone Python package for locating
cryptographic and hash-related code in x86 and x64 Windows binaries. It scans
constants, constant tables, instruction patterns, function structure, API-name
hashes, and debugger memory.

Current version: **0.3.0**

## Requirements

- IDA Pro 9.x
- Python 3.8 or later through IDAPython
- x86 or x64 Windows input
- Hex-Rays is optional for static scans and required for decompiler-derived
  function features

The plugin has no third-party Python dependencies. Its UI uses IDA APIs rather
than importing PyQt or PySide directly.

## Installation

Copy the repository directory to the per-user IDA plugin directory:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\CryptoLens\
```

The installed directory must contain both `ida-plugin.json` and
`cryptolens_plugin.py`. Restart IDA after installing or updating the plugin.
A successful load writes a `[CryptoLens] loaded` line to the Output window.

An installation under the IDA program directory also works, but writing to
`C:\Program Files\...` normally requires administrator privileges.

## IDA actions

| Action | Hotkey | Purpose |
| --- | --- | --- |
| Analyze current function | `Ctrl-Shift-A` | Classify the function at the cursor from disassembly and Hex-Rays features |
| Scan all functions for crypto | | List functions with matching structural signatures |
| Resolve API hashes in function | `Ctrl-Shift-H` | Resolve immediate values to API names and create an IDA enum |
| Resolve API hashes (whole binary) | | Resolve candidate API hashes across all functions |
| Scan process memory (debugger) | | Search live writable memory for keys, state, tables, and constants |
| Fingerprint libraries / keys / entropy | | Find library strings, key material, OIDs, CryptoAPI IDs, and high-entropy regions |
| Scan binary (high confidence) | `Ctrl-Shift-Y` | Run the default static scan |
| Scan binary (include variants) | | Include medium-confidence results |
| Lookup a number | `Ctrl-Shift-L` | Interpret a typed number, byte string, or quoted string |
| Lookup value under cursor | | Read a selected token, instruction immediate, or data item |
| Annotate findings in IDB | | Add comments and colors for the latest result set |
| Export findings | | Save results as JSON or HTML |

Binary-wide scan results appear in an IDA chooser. Selecting a row navigates
to its address. Function analysis, value lookup, and per-function API-hash
resolution use text views.

## Constant detection

The catalog contains:

- 30 multi-value families with 415 members
- 486 individual value signatures
- 14 lookup-table signatures
- 16 ASN.1 DER algorithm identifiers
- 25 function-structure classifiers

Covered families include SHA-1, all SHA-2 variants, MD5, BLAKE2, Keccak/SHA-3,
SipHash, MurmurHash2/3, SM3, RIPEMD-160, Camellia, SM4, Blowfish, ChaCha,
Salsa20, AES, RC5/6, TEA/XTEA, FNV, xxHash, CityHash, SplitMix64, Tiger, CRC
variants, and several PRNG families.

Mathematical constants are derived from their formulas where possible. Examples
include SHA-2 square-root and cube-root values, MD5's sine table, Blowfish's pi
words, and golden-ratio constants. Fixed values from standards or reference
implementations are stored as named families.

### Attribution rules

An exact numeric match does not always identify one algorithm. For example,
`0x9E3779B9` occurs in TEA/XTEA, RC5/6, Serpent, and non-cryptographic hash
mixers. The lookup output lists each candidate use.

The automatic scanner requires one of the following before it reports a
constant family:

- several family members within a sliding 4-KiB region;
- several family members in one IDA function; or
- an ordered fragment of a known constant table.

The sliding-window path does not require valid function boundaries. It can
therefore inspect decoded code islands and data in packed or damaged binaries.
Operand widths are retained so 64-bit SHA and xxHash values are not
misclassified as related 32-bit families.

Generic rotate, NOT, nearest-prime, and multiply transformations are not used as
scan signatures. Supported transformed relationships are limited to byte order,
CRC reflection, documented golden-ratio negation, and named algorithm-specific
derivations.

### Golden-ratio variants

The constrained near-match rule remains available for modified golden-ratio
values. For example:

```text
> 0x9E3779F9
[medium] variant of golden-ratio reciprocal (1/phi)
  differs in 1 bit vs 0x9E3779B9
  candidates: TEA/XTEA/XXTEA, RC5/RC6, Serpent, hash mixing
```

A near match is not promoted to a high-confidence algorithm result without
additional context.

## Function classification

The function analyzer combines instruction features, constants, table
references, loops, byte-memory access, and Hex-Rays ctree expressions. Current
structural checks include:

- ChaCha20 and Salsa20 rotation schedules
- BLAKE2s and BLAKE2b right-rotation schedules
- SHA-1, SHA-256, SHA-512, MD5, SM3, and Keccak/SHA-3
- SipHash, MurmurHash2/3, FNV, xxHash, djb2, sdbm, and SplitMix64
- TEA/XTEA shift directions and delta values
- RC4 byte-state access and swap activity
- CRC bit loops and table-driven implementations
- AES-NI, SHA-NI, PCLMULQDQ, SSE4.2 CRC32, RDRAND, and RDSEED
- Camellia and SM4 key-schedule families

Unmatched ARX-style functions receive a summary of their rotation and operation
profile instead of a named classification.

## Value lookup

`Ctrl-Shift-L` accepts hexadecimal, decimal, binary, byte strings, and quoted
text. The report can include:

- exact constants and candidate algorithms;
- constrained constant variants;
- API-name hash matches;
- little- and big-endian ASCII;
- embedded constant families and tables;
- signed and unsigned forms;
- IEEE-754 float and double interpretations;
- Unix, millisecond, and Windows FILETIME timestamps;
- compiler division reciprocals;
- parity, primality, and pointer-shaped value notes.

`Lookup value under cursor` provides the same report without requiring a valid
function. It checks the selected text first, then an instruction immediate, then
a typed data item.

## API-name hashes

CryptoLens implements 21 common 32- and 64-bit API-name hash schemes over a
list of 160 Windows API and DLL names. Scheme detection examines the selected
function and its direct internal callees, which covers wrappers that compare a
hash produced by a separate helper. A 32-bit scheme requires structural support
or two resolved values; a single exact 64-bit match is accepted because its
collision probability against the built-in name set is substantially lower.
When a consistent mapping is found, the plugin can create or extend the
`CryptoLens_apihash` enum, apply it to operands, and add comments. For example,
`0xB1F0FE0EF080D006` resolves to `bkdr131_64("kernel32.dll")`.

## Debugger memory scan

During an active debug session, the memory scanner can locate:

- AES-128, AES-192, and AES-256 expanded key schedules and recover the source
  key bytes;
- 256-byte RC4 state permutations;
- ChaCha/Salsa state markers;
- constant families and lookup tables built at runtime.

The default scan covers writable regions. Calling
`cryptolens_ida.memscan.scan_memory(only_writable=False)` includes all mapped
regions.

## Fingerprints and entropy

The fingerprint scan recognizes OpenSSL, mbedTLS/PolarSSL, Crypto++, libsodium,
Windows CNG/BCrypt, PEM and OpenSSH markers, X.509 material, CryptoAPI `CALG_*`
values, and DER OIDs for RSA, EC curves, Ed25519, X25519, SHA, and AES modes.

Entropy results identify adjacent blocks above the configured threshold. High
entropy may indicate encryption, compression, or packing; it is not treated as
an algorithm identification.

## Command-line use

Run the core without IDA from the repository root:

```powershell
python -m cryptolens explain 0x9E3779B9
python -m cryptolens explain 2654435769 --width 32
python -m cryptolens apihash GetProcAddress
python -m cryptolens apihash --resolve 0x7C0DFCAA
python -m cryptolens selftest
```

## Repository layout

```text
cryptolens/              IDA-independent analysis modules
  constants.py           formula-derived anchors
  families.py            multi-value family catalog
  familyscan.py          ordered and sliding-window family matching
  signatures.py          individual value catalog
  engine.py              exact and constrained near-match lookup
  structure.py           function feature classifiers
  tables.py              generated and fixed lookup tables
  memfind.py             AES, RC4, and ChaCha memory recovery
  apihash.py             API-name hash implementations and reverse index
  fingerprints.py        strings, CryptoAPI IDs, and DER OIDs
cryptolens_ida/          IDA readers, actions, views, annotations, and export
cryptolens_plugin.py     IDA entry point
ida-plugin.json          IDA plugin manifest
tests/                   core and adapter regression tests
CHANGELOG.md             release history
```

The `cryptolens` package does not import IDA. IDA access is isolated in
`cryptolens_ida`, which allows the core scanners and classifiers to run in unit
tests and from the command line.

## Testing

Run the dependency-free self-test:

```powershell
python -m cryptolens selftest
```

Run the full test suite when pytest is installed:

```powershell
python -m pytest -q
```

The current suite contains 59 tests covering formula derivation, catalog
invariants, family matching, false-positive regressions, structural classifiers,
API hashes, memory recovery, fingerprints, and IDA adapter data models.

## Extending the catalog

- Add multi-value algorithms to `cryptolens/families.py` as `FamilySpec`
  entries.
- Add values that are meaningful in isolation to `_RAW` in
  `cryptolens/signatures.py`.
- Add formula-derived anchors to `_canon_generators()` in
  `cryptolens/constants.py`.
- Add lookup tables to `_table_sigs()` in `cryptolens/tables.py`.
- Add API-name hash implementations to `cryptolens/apihash.py`.

Each new detector should include a positive test and at least one nearby
non-matching case.

## Planned work

- Decompiler-assisted parameter recovery, including round counts and custom
  S-boxes
- User-defined signature files
- Headless batch reports
- Compiled positive and negative fixtures from MSVC, Clang, and GCC

Completed release work is recorded in [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
