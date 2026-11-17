# Changelog

## 0.3.0 (precision catalog)

### Added

- 30 corroborated constant families (415 family members), including complete
  SHA-2 tables/IV variants, BLAKE2, Keccak/SHA-3, SipHash, MurmurHash2/3, SM3,
  RIPEMD-160, Camellia, SM4, Blowfish, SplitMix64 and CityHash.
- Ordered sequence detection at unaligned offsets and sliding 4-KiB
  co-occurrence matching, including code islands without IDA functions.
- BLAKE2 sigma, AES Rcon, CRC-32K/Q, RC4 identity and Base58 table signatures.
- ASN.1 DER OID fingerprints for RSA, EC curves, Ed25519/X25519, SHA and AES.
- 64-bit API-name hash schemes, including base-131/BKDR, FNV, djb2, sdbm, and
  rotate-add variants; wrapper analysis also checks direct hash-helper callees.
- 23 catalog and precision tests in `test_catalog_precision.py`.

### Corrected

- Correct xxHash64 PRIME64_4 and PRIME64_5 values/roles.
- Complete SHA-512 round constants K[0..79].
- Correct SHA-512 high-half wording and SM4 CK terminology.
- Table-result adapter crash (`TableHit.name` versus nonexistent `.title`).
- Shared constants now report all candidate families instead of claiming the
  first listed algorithm.
- Width-aware data-reference extraction prevents SHA-512/SHA-256,
  SHA-384/SHA-224 and xxHash64/xxHash32 aliases.

### Precision changes

- Removed universal rotate/NOT/nearest-prime/multiply derivation cross-products.
- Automatic scans require family co-occurrence or ordered sequences; manual
  lookup still explains individual values.
- Tightened golden-ratio fuzzy matching and removed broad prime-prefix matches.
- Added mandatory structural gates for RC4, CRC, TEA, Base64, FNV, API hashes,
  Keccak and related classifiers.
- Custom Base64 detection now requires the 62-alphanumeric-plus-2-symbol shape
  and is medium confidence until code context corroborates it.
- Bulk scanning no longer treats executable opcodes as aligned data constants.
- Main binary scan reads segments once and decodes code once for all passes.

## 0.2.0

- Function-level Hex-Rays/disassembly classifier.
- API-hash resolver and IDA enum creation.
- Debugger memory recovery for AES schedules, RC4 and ChaCha states.
- Library/key fingerprints and entropy map.

## 0.1.0

- Formula-derived mathematical constants, manual lookup, static table/value
  scanner, IDA results UI, annotation and JSON/HTML export.
