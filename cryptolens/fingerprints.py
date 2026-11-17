"""Detect crypto-library, key-material, and algorithm fingerprints.

Three signal types:

* string fingerprints - crypto libraries and embedded key material, searched in
  both ASCII and UTF-16LE;
* exact DER OBJECT IDENTIFIER TLVs - RSA, EC curves, Ed/X25519, SHA and AES
  modes;
* CryptoAPI CALG_* ids - small integer algorithm identifiers passed to legacy
  Wincrypt APIs.

``scan_bytes`` returns both text and binary fingerprint hits; ``calg_name`` maps
an integer id.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

# (needle, category, note)
STRING_FINGERPRINTS: List[Tuple[str, str, str]] = [
    # OpenSSL
    ("OpenSSL", "openssl", "OpenSSL library"),
    ("SSLeay", "openssl", "legacy OpenSSL"),
    ("part of OpenSSL", "openssl", "OpenSSL component string"),
    ("RSA part of OpenSSL", "openssl", "OpenSSL RSA"),
    ("aes-256-cbc", "openssl", "EVP cipher name"),
    ("aes-128-gcm", "openssl", "EVP cipher name"),
    ("chacha20-poly1305", "openssl", "EVP AEAD name"),
    # mbedTLS / PolarSSL
    ("mbed TLS", "mbedtls", "mbedTLS"),
    ("mbedtls", "mbedtls", "mbedTLS symbol"),
    ("PolarSSL", "mbedtls", "legacy PolarSSL"),
    # Crypto++
    ("Crypto++", "cryptopp", "Crypto++ library"),
    ("CryptoPP", "cryptopp", "Crypto++ symbol"),
    # libsodium / NaCl
    ("libsodium", "libsodium", "libsodium"),
    ("nacl", "libsodium", "NaCl"),
    # Windows CNG / BCrypt
    ("Microsoft Primitive Provider", "bcrypt", "CNG primitive provider"),
    ("BCryptOpenAlgorithmProvider", "bcrypt", "CNG API"),
    ("ChainingModeGCM", "bcrypt", "CNG chaining mode"),
    # PEM / key material
    ("-----BEGIN RSA PRIVATE KEY-----", "pem", "PKCS#1 RSA private key"),
    ("-----BEGIN PRIVATE KEY-----", "pem", "PKCS#8 private key"),
    ("-----BEGIN EC PRIVATE KEY-----", "pem", "EC private key"),
    ("-----BEGIN PUBLIC KEY-----", "pem", "public key"),
    ("-----BEGIN CERTIFICATE-----", "cert", "X.509 certificate"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "ssh", "OpenSSH private key"),
    ("ssh-rsa ", "ssh", "OpenSSH public key"),
    ("ssh-ed25519 ", "ssh", "OpenSSH ed25519 key"),
]

# DER OBJECT IDENTIFIER entries include the tag and length bytes.
BYTE_FINGERPRINTS = [
    (bytes.fromhex("06092A864886F70D010101"), "rsaEncryption OID", "oid", "PKCS#1 RSA"),
    (bytes.fromhex("06052B0E03021A"), "id-sha1 OID", "oid", "SHA-1"),
    (bytes.fromhex("0609608648016503040201"), "id-sha256 OID", "oid", "SHA-256"),
    (bytes.fromhex("0609608648016503040202"), "id-sha384 OID", "oid", "SHA-384"),
    (bytes.fromhex("0609608648016503040203"), "id-sha512 OID", "oid", "SHA-512"),
    (bytes.fromhex("06072A8648CE3D0201"), "id-ecPublicKey OID", "oid", "EC public key"),
    (bytes.fromhex("06082A8648CE3D030107"), "prime256v1 OID", "oid", "NIST P-256"),
    (bytes.fromhex("06052B8104000A"), "secp256k1 OID", "oid", "secp256k1"),
    (bytes.fromhex("06032B6570"), "Ed25519 OID", "oid", "Ed25519"),
    (bytes.fromhex("06032B656E"), "X25519 OID", "oid", "X25519"),
    (bytes.fromhex("0609608648016503040102"), "id-aes128-CBC OID", "oid", "AES-128-CBC"),
    (bytes.fromhex("0609608648016503040116"), "id-aes192-CBC OID", "oid", "AES-192-CBC"),
    (bytes.fromhex("060960864801650304012A"), "id-aes256-CBC OID", "oid", "AES-256-CBC"),
    (bytes.fromhex("0609608648016503040106"), "id-aes128-GCM OID", "oid", "AES-128-GCM"),
    (bytes.fromhex("060960864801650304011A"), "id-aes192-GCM OID", "oid", "AES-192-GCM"),
    (bytes.fromhex("060960864801650304012E"), "id-aes256-GCM OID", "oid", "AES-256-GCM"),
]

# Legacy CryptoAPI algorithm identifiers (wincrypt.h ALG_ID values).
CALG_IDS = {
    0x8001: "CALG_MD2", 0x8002: "CALG_MD4", 0x8003: "CALG_MD5",
    0x8004: "CALG_SHA1", 0x8009: "CALG_HMAC", 0x800C: "CALG_SHA_256",
    0x800D: "CALG_SHA_384", 0x800E: "CALG_SHA_512", 0x6601: "CALG_DES",
    0x6603: "CALG_3DES", 0x6609: "CALG_3DES_112", 0x6602: "CALG_RC2",
    0x6801: "CALG_RC4", 0x660E: "CALG_AES_128", 0x660F: "CALG_AES_192",
    0x6610: "CALG_AES_256", 0x6611: "CALG_AES", 0xA400: "CALG_RSA_KEYX",
    0x2400: "CALG_RSA_SIGN", 0xAA02: "CALG_DH_EPHEM", 0x2200: "CALG_DSS_SIGN",
}


def calg_name(value: int) -> Optional[str]:
    return CALG_IDS.get(value & 0xFFFFFFFF)


@dataclass
class StringHit:
    offset: int
    needle: str
    category: str
    note: str
    encoding: str          # "ascii" | "utf-16le"


def scan_bytes(buf: bytes, base: int = 0) -> List[StringHit]:
    out: List[StringHit] = []
    for needle, category, note in STRING_FINGERPRINTS:
        for enc in ("ascii", "utf-16le"):
            try:
                pat = needle.encode(enc)
            except Exception:
                continue
            start = 0
            while True:
                idx = buf.find(pat, start)
                if idx < 0:
                    break
                out.append(StringHit(base + idx, needle, category, note, enc))
                start = idx + 1
    for pat, label, category, note in BYTE_FINGERPRINTS:
        start = 0
        while True:
            idx = buf.find(pat, start)
            if idx < 0:
                break
            out.append(StringHit(base + idx, label, category, note, "DER/binary"))
            start = idx + 1
    return out
