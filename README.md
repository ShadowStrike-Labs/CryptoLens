# CryptoLens

An IDA Pro (9.x) plugin that scans a binary for crypto and hashing algorithm
patterns and produces a report. Its distinguishing feature is a **generative
constant engine**: instead of matching a fixed list of magic numbers, it knows
the *formula* behind each constant, so it can explain an arbitrary value and
flag near misses as "variant of X" (for example a golden-ratio-like delta that
a packer uses instead of the textbook `0x9E3779B9`).

Target: IDA Pro 9.x, Python 3, x86/x64 (Intel/AMD), Windows. The analysis core
has no IDA dependency and runs as a standalone CLI.

## What it detects

- **Known constants** from the major algorithms: TEA/XTEA/XXTEA, RC5/RC6,
  Serpent, MD5, SHA-1, SHA-2 (IV + round constants), Blowfish (pi digits),
  ChaCha20/Salsa20 sigma words, AES T-tables, FNV-1/1a, xxHash, CRC-16/32/32C/64,
  SM4, Mersenne Twister and common LCG PRNGs, Tiger, Adler-32.
- **Variants** of those constants: negated, bitwise-NOT, byte-swapped,
  bit-reversed, rotated, rounded to odd/prime, multiplied, or differing by a few
  bits. This is how it catches author/packer constants that are "golden-ratio-like"
  without being the exact value.
- **Known tables**: AES S-box / inverse S-box (computed, not hard-coded),
  CRC-32 and CRC-32C tables, Base64/Base32 alphabets, and *custom* Base64
  alphabets (64 distinct printable bytes in a row).
- **Hardware crypto instructions**: AES-NI, SHA-NI, PCLMULQDQ, SSE4.2 CRC32,
  RDRAND/RDSEED (including VEX-prefixed forms).
- **API-name hashes** (shellcode/loader style): resolves a value back to names
  like `ror13_add("GetProcAddress")` across ten common schemes.

## The variant engine (the novel part)

Every base constant is produced from a recipe in `cryptolens/hpmath.py`
(`floor(2^32 / phi)`, `frac(sqrt 2) * 2^32`, `frac(cbrt p) * 2^32`,
`floor(|sin i| * 2^32)`, ...), so the engine knows *why* a number has its value.
Given any integer it:

1. applies cheap, invertible transforms (negate / NOT / byte-swap / bit-reverse
   / rotate / 64->32 halves),
2. looks each result up in the generated anchor table and the algorithm
   database, and
3. if nothing matches exactly, runs a fuzzy pass against canonical anchors and
   reports near misses as "variant of X" with a confidence score.

Example (`python -m cryptolens explain 0x9E3779F9`):

```
0x9E3779F9  as 32-bit
  [medium] variant of TEA/XTEA/XXTEA
      origin : floor(2^32 / phi)  (golden-ratio reciprocal 1/phi)
      detail : differs in 1 bit(s) vs 0x9E3779B9
      usedby : TEA/XTEA/XXTEA - delta; RC5/RC6 - magic Q; Serpent; boost::hash_combine
```

Exact matches read their algorithm attribution directly; `0x61C88647` is
identified as the Linux/Java negated golden ratio *and* noted as `neg(1/phi)`;
`0xEDB88320` as the reflected CRC-32 polynomial *and* `bitrev` of the normal one.

## Number lookup panel

For values you see in memory at runtime, the lookup panel (`Ctrl-Shift-L` in
IDA, or `cryptolens explain` on the CLI) accepts a hex/decimal number, a byte
blob, or a `'quoted string'`, and reports constants, variants, API-hash
matches, ASCII/endian interpretations and embedded tables. Byte input is scanned
word-by-word, so pasting `expand 32-byte k` identifies all four ChaCha sigma
words.

When a value is not a known crypto constant, the panel still reports **general
interpretations** so it is useful on obfuscated binaries: signed/unsigned
decimal, bytes + ASCII, IEEE-754 float/double, Unix / millisecond / Windows
FILETIME timestamps, compiler division-magic reciprocals, prime/parity, and a
masked-pointer hint. For code where IDA could not form functions, use **Lookup
value under cursor** (right-click, or the CryptoLens menu): it reads the
highlighted token, the instruction immediate, or the data item at the cursor and
explains it with no typing.

## Install

The analysis core is pure standard library; no third-party packages are
required for either the core or the IDA plugin.

**As an IDA plugin.** IDA 9.x discovers a folder plugin via its
`ida-plugin.json` manifest (included in this repo), so install the whole folder:

- Recommended (no admin): copy the `CryptoLens` folder into your **user**
  plugins directory -
  `%APPDATA%\Hex-Rays\IDA Pro\plugins\CryptoLens\` on Windows
  (`~/.idapro/plugins/CryptoLens/` on Linux/macOS).
- Or copy it into the install-wide `plugins` directory
  (`C:\Program Files\IDA Professional 9.x\plugins\CryptoLens\`), which needs
  administrator rights.

The folder must contain `ida-plugin.json` next to `cryptolens_plugin.py` (both
are at the repo root). A bare `.py` dropped into a *subfolder* without the
manifest is not loaded. Restart IDA; you should see `[CryptoLens] loaded` in the
Output window and a **CryptoLens** submenu under Edit > Plugins, plus hotkeys
(`Ctrl-Shift-Y` scan, `Ctrl-Shift-L` lookup). Qt is not used directly: the UI is
built on IDA's own `Choose` and `simplecustviewer_t`, so it works across the
Qt5->Qt6/PySide6 change introduced in IDA 9.2.

**As a standalone CLI:**

```
python -m cryptolens explain 0x9E3779B9
python -m cryptolens explain 2654435769 --width 32
python -m cryptolens apihash GetProcAddress
python -m cryptolens apihash --resolve 0x7C0DFCAA
python -m cryptolens selftest
```

## Identify the algorithm in a function

Put the cursor in a function (disassembly or pseudocode) and press
`Ctrl-Shift-A`. CryptoLens extracts structural features from both the
disassembly and the Hex-Rays decompilation, then classifies them. It does not
rely on constants alone, so it recognises algorithms whose tables are built at
runtime or that use no magic numbers.

The decisive feature is the **set of rotation amounts**. Right-rotations are
normalised to their left-equivalent, so detection is robust to how the
compiler/decompiler expressed them:

- ChaCha20 `16/12/8/7`, Salsa20 `7/9/13/18`
- SHA-256 Sigma rotations `2/13/22` and `6/11/25` (+ message-schedule shifts
  `>>3`, `>>10`)
- SHA-1 `1/5/30`, MD5's 16-entry per-round table
- TEA/XTEA golden-ratio delta with `<<4` / `>>5`
- RC4 by its 256-entry byte state with `&0xFF` indexing and swaps (no rotations)
- CRC by its shift-and-XOR loop or table plus the polynomial
- AES by AES-NI instructions or S-box/T-table references

Each match comes with a score, the evidence behind it, the function's rotation
set, and any notable constants explained through the phase-1 engine. When
nothing named matches, it still reports the ARX structure (rotation amounts and
op histogram) so an unknown cipher is at least characterised. "Scan all
functions for crypto" runs the same classifier across the whole binary for
triage.

## Resolve hashed API imports

Malware and loaders often call `kernel32!GetProcAddress` and friends by a hash
instead of a name. Put the cursor in the resolver function and press
`Ctrl-Shift-H`: CryptoLens guesses the hashing scheme from the function's
structure (rotate-by-13, FNV prime, djb2, sdbm, CRC, ...), resolves the compared
constants to API names across all ten built-in schemes (filtered by the guessed
one, or inferred from a majority vote), builds an IDA enum, and switches the
operands to it so the pseudocode becomes readable. The name list is extensible
in `cryptolens/apihash.py`.

## Debugger memory scan

With a live debug session, **Scan process memory** walks the process memory map
and recovers what only exists at runtime. The recovery math is in the testable
core (`cryptolens/memfind.py`):

- **AES keys** - for each candidate offset it re-derives the key schedule and
  checks it against the following bytes, recovering the actual AES-128/192/256
  key (the aeskeyfind approach).
- **RC4 states** - 256-byte windows that are a permutation of 0..255.
- **ChaCha/Salsa states** - the `expand 32-byte k` block.
- **runtime tables and constants** - S-boxes, CRC tables and known values that
  were built in memory.

It scans writable regions by default (where keys and states live), which is both
correct and fast.

## Library fingerprints and entropy

**Fingerprint libraries / keys / entropy** detects:

- crypto-library strings (OpenSSL, mbedTLS/PolarSSL, Crypto++, libsodium, Windows
  CNG/BCrypt), searched in both ASCII and UTF-16LE,
- embedded key material (PEM private/public keys, X.509 certificates, OpenSSH
  keys),
- CryptoAPI `CALG_*` algorithm ids used as instruction immediates, and
- high-entropy regions (>=7.2 bits/byte sustained) that mark encrypted,
  compressed or packed blobs.

## Using it in IDA

The **CryptoLens** menu provides:

- **Analyze current function** (`Ctrl-Shift-A`, also on the right-click menu in
  both the disassembly and pseudocode views) - identify the algorithm in the
  function under the cursor. This is the fastest way to answer "what is this
  `sub_XXX`?".
- **Scan all functions for crypto** - classify every function and list the
  crypto-like ones in the results table.
- **Resolve API hashes in function** (`Ctrl-Shift-H`, also on the right-click
  menu) - name the hashed imports in the current function, build an enum, and
  relabel the operands so magic numbers read as `GetProcAddress`, `WinExec`, ...
- **Resolve API hashes (whole binary)** - do the same across every function.
- **Scan process memory (debugger)** - during a live debug session, recover AES
  keys (from the key schedule), RC4 states, ChaCha states, and runtime tables.
- **Fingerprint libraries / keys / entropy** - detect crypto-library strings,
  PEM/OpenSSH keys, certificates, CryptoAPI `CALG_*` ids, and high-entropy blobs.
- **Scan binary (high confidence)** - exact constants, tables and crypto
  instructions, plus high-confidence immediate matches. Results open in a table;
  double-click a row to jump to the address.
- **Scan binary (include variants)** - also reports medium-confidence
  "variant of X" immediates.
- **Lookup a number...** - the panel described above.
- **Lookup value under cursor** - explain the highlighted constant, or the
  instruction immediate / data item at the cursor, with no typing (also on the
  right-click menu in the disassembly, pseudocode and hex views).
- **Annotate findings in IDB** - adds `CryptoLens:` comments and background
  colors at each finding.
- **Export findings (JSON/HTML)** - saves the last scan.

Scan strategy: bulk *data* is matched against exact values at aligned 32/64-bit
offsets (fast, essentially no false positives). The expensive variant/fuzzy
analysis is reserved for *instruction immediates*, which is exactly where
golden-ratio-like deltas and custom magic numbers appear in code.

## Project layout

```
cryptolens/              core analysis library (no IDA imports, unit-tested)
  hpmath.py              high-precision constants from formulas
  util.py                bit / number-theory helpers
  constants.py           base-constant registry + anchor table
  signatures.py          algorithm attribution database
  engine.py              transforms, matching, fuzzy variant detection, scoring
  structure.py           function structural classifier + hash-scheme fingerprints
  memfind.py             AES key-schedule / RC4 / ChaCha recovery from memory
  fingerprints.py        crypto-library / key-material / CALG fingerprints
  entropy.py             Shannon entropy + high-entropy region detection
  apihash.py             API-name hashing schemes + reverse lookup
  tables.py              AES S-box / CRC / Base64 table detection
  fastscan.py            fast exact-value buffer scan
  parse.py, report.py    input parsing and report formatting
  cli.py, selftest.py    CLI and verification suite
cryptolens_ida/          IDA integration (thin I/O layer)
  ida_shim.py            isolated IDA SDK imports
  scanners.py            data / table / immediate / instruction scanners
  funcscan.py            per-function feature extraction (Hex-Rays + asm)
  apihashscan.py         API-hash resolution + enum creation
  memscan.py             debugger memory scan
  fpscan.py              library/key fingerprints + entropy map
  annotate.py            comments + colors in the IDB
  results.py             Choose-based results table
  lookup.py              simplecustviewer_t lookup panel
  plugin.py              actions, menu, hotkeys, export
cryptolens_plugin.py     IDA plugin entry point (PLUGIN_ENTRY)
tests/                   pytest-discoverable tests (core + structure + phase2)
```

The split is deliberate: all detection logic lives in the testable core, and
the IDA layer only reads bytes/instructions and writes comments. That is why the
engine can be verified without launching IDA.

## Extending

- **Add an algorithm constant**: append a row to `_RAW` in
  `cryptolens/signatures.py` as `(value, width, algorithm, role, note)`. It is
  automatically matched through all transforms.
- **Add a base constant / recipe**: add a generator in
  `_canon_generators()` in `cryptolens/constants.py`; variant detection follows
  for free.
- **Add an API-hash scheme**: add a function and a `Scheme(...)` entry in
  `cryptolens/apihash.py`.
- **Add a table**: add a `TableSig` in `cryptolens/tables.py`.

## Verifying

```
python -m cryptolens selftest     # derives SHA/MD5/Blowfish/golden-ratio
                                  # constants from formulas and checks the engine
```

The self-test confirms that computed constants equal their published values
(e.g. SHA-256 `H0 = 0x6A09E667`, MD5 `T[1] = 0xD76AA478`) and that the engine
classifies the headline cases correctly.

## Roadmap

Phase 1 (complete): the variant engine, constant/table/instruction/immediate
scanners, the lookup panel, IDB annotation, export and the standalone CLI.

Phase 2 - step 1 (complete): decompiler + disassembly **function structural
analysis** ("what algorithm is this function?"), driven from the cursor, with a
whole-binary triage scan. ChaCha/Salsa rotation sets, SHA-1/2 rotations, MD5
rotation table, RC4 state+swap, CRC loops, TEA deltas, AES-NI/tables, plus a
generic ARX characterisation for unknown ciphers.

Phase 2 - step 2 (complete): **API-hash loop detection + enum creation** -
scheme fingerprinting, constant-to-name resolution, IDA enum, operand relabelling.

Phase 3 - step 3 (complete): **debugger memory scan** - AES key-schedule
recovery, RC4/ChaCha state detection, runtime tables and constants.

Phase 3 - step 4 (complete): **library/key fingerprints + entropy map** -
crypto-library and key-material strings, CryptoAPI `CALG_*` ids, high-entropy
regions.

Ideas for later:

- decompiler-assisted recovery of per-algorithm parameters (round counts, S-box
  variants), signature files users can edit, and headless batch reporting.

## License

MIT (see `pyproject.toml`).
