# Constant catalog sources

This list records primary references for the main formula-derived values,
constant families, and DER identifiers. Additional family labels are recorded
in `cryptolens/families.py`.

- [NIST FIPS 180-4, Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf):
  SHA-1 and SHA-2 initial values, round constants, and structure.
- [NIST FIPS 202, SHA-3 Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
  and the [Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf):
  Keccak-f[1600] round constants and permutation structure.
- [NIST FIPS 197-upd1, AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf):
  the S-box and key-schedule Rcon values.
- [RFC 1321, MD5](https://www.rfc-editor.org/rfc/rfc1321): the sine-derived T
  table and rotation schedule.
- [RFC 7693, BLAKE2](https://www.rfc-editor.org/rfc/rfc7693): BLAKE2s and
  BLAKE2b initial values, message permutation, and rotations.
- [RFC 8439, ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439):
  ChaCha state words and quarter-round structure.
- [RFC 3713, Camellia](https://www.rfc-editor.org/rfc/rfc3713): key-schedule
  SIGMA constants.
- [CFRG SM3 draft](https://www.ietf.org/archive/id/draft-sca-cfrg-sm3-02.txt):
  SM3 initial values, round constants, and rotations.
- [SipHash reference implementation](https://github.com/veorq/SipHash/blob/master/siphash.c):
  initialization constants and SipRound rotations.
- [SMHasher MurmurHash3 reference](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp):
  x86-32 and x64-128 body and finalizer constants.
- [xxHash reference header](https://github.com/Cyan4973/xxHash/blob/dev/xxhash.h):
  xxHash32 and xxHash64 prime families.
- [Google CityHash source](https://github.com/google/cityhash/blob/master/src/city.cc)
  and [city.h](https://github.com/google/cityhash/blob/master/src/city.h):
  `k0`, `k1`, `k2`, and `kMul`.
- [FNV draft](https://www.ietf.org/archive/id/draft-eastlake-fnv-25.txt): FNV
  primes, offset bases, and operation order.
- [RIPEMD-160 specification](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html):
  left- and right-line round constants.
- [RFC 2040, RC5](https://www.rfc-editor.org/rfc/rfc2040): RC5 constants and
  parameter conventions.
- [SM4 CFRG draft](https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10):
  SM4 system and key-schedule constants.
- [Blowfish description](https://www.schneier.com/academic/blowfish/): P-array
  values derived from the hexadecimal digits of pi.
- [SplitMix64 reference source](https://prng.di.unimi.it/splitmix64.c): state
  increment and finalizer multipliers.
- [Tiger specification](https://biham.cs.technion.ac.il/Reports/Tiger/):
  initial state values.

DER object identifier entries follow [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)
for RSA, [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480) for elliptic-curve
keys, and [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) for X25519 and
Ed25519.
