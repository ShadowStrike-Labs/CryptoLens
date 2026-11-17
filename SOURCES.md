# Constant catalogue sources

CryptoLens derives constants where the specification gives a formula and keeps
curated literal families where the standard/reference defines fixed values.
Algorithm attribution in automatic scans requires co-occurrence or an ordered
sequence; an individual lookup only states exact numeric membership.

Primary and reference sources used for the v0.3 catalogue:

- [NIST FIPS 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — SHA-1, SHA-224/256, SHA-384/512, SHA-512/224 and SHA-512/256 IVs, round constants and structure.
- [NIST FIPS 202: SHA-3 Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and the [Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf) — Keccak-f[1600] round constants and permutation structure.
- [NIST FIPS 197-upd1: AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) — S-box and key-schedule Rcon values.
- [RFC 1321: MD5](https://www.rfc-editor.org/rfc/rfc1321) — sine-derived T table and rotation schedule.
- [RFC 7693: BLAKE2](https://www.rfc-editor.org/rfc/rfc7693) — BLAKE2s/BLAKE2b IVs, sigma permutation and rotations.
- [RFC 8439: ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439) — ChaCha state words and quarter-round structure.
- [RFC 3713: Camellia](https://www.rfc-editor.org/rfc/rfc3713) — six SIGMA key-schedule constants.
- [CFRG SM3 draft](https://www.ietf.org/archive/id/draft-sca-cfrg-sm3-02.txt) — SM3 IV, T constants and permutation rotations.
- [SipHash reference implementation](https://github.com/veorq/SipHash/blob/master/siphash.c) — four ASCII initialization constants and SipRound rotations.
- [SMHasher MurmurHash3 reference](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) — x86-32 and x64-128 body/finalizer constants.
- [xxHash reference header](https://github.com/Cyan4973/xxHash/blob/dev/xxhash.h) — xxHash32/64 prime families. This source was also used to correct the old PRIME64_4/PRIME64_5 labels.
- [Google CityHash reference](https://github.com/google/cityhash/blob/master/src/city.cc) and [city.h](https://github.com/google/cityhash/blob/master/src/city.h) — k0/k1/k2 and kMul.
- [FNV draft](https://www.ietf.org/archive/id/draft-eastlake-fnv-25.txt) — FNV prime/offset basis and FNV-1 versus FNV-1a operation order.
- [RIPEMD-160 specification page](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html) — dual-line round constants.

ASN.1 algorithm-identifier fingerprints follow the relevant standards:
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) (RSA),
[RFC 5480](https://www.rfc-editor.org/rfc/rfc5480) (EC/P-256), and
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) (X25519/Ed25519).

Source material is summarized and values are represented as facts/formulas;
content has been rephrased for licensing compliance.
