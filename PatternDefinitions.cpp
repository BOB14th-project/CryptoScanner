// PatternDefinitions.cpp
//
// Provides implementations for constructing default cryptographic
// pattern lists.  This includes both regular expressions for ASCII
// matching and raw byte sequences for DER-encoded OIDs.  The aim is
// to detect use of legacy (non-post-quantum) cryptographic
// algorithms within binary data.

#include "PatternDefinitions.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace {

// Encode a 32-bit integer into base-128 variable-length bytes.
static std::vector<uint8_t> encodeBase128(uint32_t v) {
    std::vector<uint8_t> out;
    do {
        out.push_back(static_cast<uint8_t>(v & 0x7Fu));
        v >>= 7;
    } while (v);
    std::reverse(out.begin(), out.end());
    // Set the high bit for all but the last byte
    for (size_t i = 0; i + 1 < out.size(); ++i) {
        out[i] |= 0x80u;
    }
    return out;
}

// Convert a dotted OID string into its value bytes (without tag or length), following ASN.1 rules.
static std::vector<uint8_t> oidValueBytes(const std::string& dotted) {
    std::vector<uint32_t> arcs;
    std::string tmp;
    for (char ch : dotted) {
        if (ch == '.') {
            if (!tmp.empty()) {
                arcs.push_back(static_cast<uint32_t>(std::stoul(tmp)));
                tmp.clear();
            }
        } else {
            tmp.push_back(ch);
        }
    }
    if (!tmp.empty()) {
        arcs.push_back(static_cast<uint32_t>(std::stoul(tmp)));
    }
    if (arcs.size() < 2) {
        throw std::runtime_error("OID requires at least two arcs");
    }
    std::vector<uint8_t> value;
    value.push_back(static_cast<uint8_t>(arcs[0] * 40 + arcs[1]));
    for (size_t i = 2; i < arcs.size(); ++i) {
        auto encoded = encodeBase128(arcs[i]);
        value.insert(value.end(), encoded.begin(), encoded.end());
    }
    return value;
}

// Build a full DER-encoded OID from a dotted string.
static std::vector<uint8_t> oidDERBytes(const std::string& dotted) {
    auto val = oidValueBytes(dotted);
    std::vector<uint8_t> out;
    out.push_back(0x06u);
    if (val.size() <= 127) {
        out.push_back(static_cast<uint8_t>(val.size()));
    } else {
        // Determine number of bytes needed to represent length
        std::vector<uint8_t> lenBytes;
        size_t n = val.size();
        while (n > 0) {
            lenBytes.push_back(static_cast<uint8_t>(n & 0xFFu));
            n >>= 8;
        }
        std::reverse(lenBytes.begin(), lenBytes.end());
        out.push_back(static_cast<uint8_t>(0x80u | lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

// Create a case-insensitive regex from a raw string.
static std::regex icase_re(const std::string& r) {
    return std::regex(r, std::regex_constants::icase);
}

// Create a regex that matches a literal uppercase hex string (e.g., a prime or coefficient).
static std::regex hex_literal(const std::string& hexUpper) {
    return std::regex(hexUpper, std::regex_constants::icase);
}

} // namespace

namespace crypto_patterns {

std::vector<AlgorithmPattern> getDefaultPatterns() {
    std::vector<AlgorithmPattern> P;

    // RSA keywords and related terms
    P.push_back({
        "RSA",
        icase_re(R"(\bRSA(?:-?(?:1024|2048|4096))?\b|PKCS#?1\b|PKCS#?8\b|modulus\b|public\s+exponent\b|private\s+exponent\b)")
    });
    // RSA e = 65537
    P.push_back({
        "RSA exponent 65537",
        icase_re(R"(\b(?:public\s+exponent\s*(?:=|:)?\s*)?(?:65537|0x?10001)\b)")
    });

    // ECC/ECDSA/ECDH and named curves
    P.push_back({
        "ECC/ECDSA/ECDH",
        icase_re(R"(\b(?:ECC|ECDSA|ECDH|EC_KEY|EC_GROUP)\b|secp(?:256r1|384r1|521r1|224r1|224k1|256k1)\b|\bP-(?:256|384|521)\b|\b(?:Curve25519|Ed25519|X25519|X448|Ed448)\b)")
    });

    // DSA
    P.push_back({
        "DSA",
        icase_re(R"(\b(?:DSA|DSS|Digital\s+Signature\s+Algorithm)\b|DSA_(?:sign|verify))")
    });

    // Diffie-Hellman
    P.push_back({
        "Diffie-Hellman",
        icase_re(R"(\b(?:DH|Diffie-?Hellman)\b(?:-(?:1024|2048|4096))?|modexp\b|prime\s+modulus\b)")
    });

    // ElGamal
    P.push_back({
        "ElGamal",
        icase_re(R"(\bElGamal(?:\s+Encryption|\s+Signature)?\b)")
    });

    // AES-128 and modes
    P.push_back({
        "AES-128/modes",
        icase_re(R"(\bAES(?:[-_]?128)?\b|Rijndael\b|Advanced\s+Encryption\s+Standard\b|AES-(?:CBC|GCM|ECB|OFB|CTR)\b|AES_set_(?:encrypt|decrypt)_key\b)")
    });

    // 3DES / DES
    P.push_back({
        "3DES",
        icase_re(R"(\b(?:3DES|TripleDES|DES|Data\s+Encryption\s+Standard)\b)")
    });

    // Blowfish / bcrypt
    P.push_back({
        "Blowfish/bcrypt",
        icase_re(R"(\bBlowfish\b|\bbcrypt\b)")
    });

    // RC4
    P.push_back({
        "RC4",
        icase_re(R"(\b(?:RC4|ARC4|Rivest\s+Cipher\s*4)\b)")
    });

    // SHA (SHA-1/224/256/384/512 + Secure Hash Algorithm 1/2)
    P.push_back({
        "SHA",
        icase_re(R"(\b(?:SHA[-_]?1|SHA[-_]?224|SHA[-_]?256|SHA[-_]?384|SHA[-_]?512)\b|\bsha1sum\b|\bsha256sum\b|\bsha512sum\b|\bSecure\s+Hash\s+Algorithm\s+1\b|\bSecure\s+Hash\s+Algorithm\s+2\b)")
    });

    // MD5
    P.push_back({
        "MD5",
        icase_re(R"(\bMD5\b|\bMessage\s+Digest\s+5\b|\bmd5sum\b)")
    });

    // -------- ASCII dotted OIDs --------
    // RSA
    P.push_back({ "OID dotted (rsaEncryption)",                   icase_re(R"(\b1\.2\.840\.113549\.1\.1\.1\b)") });
    P.push_back({ "OID dotted (rsassaPss)",                       icase_re(R"(\b1\.2\.840\.113549\.1\.1\.10\b)") });
    P.push_back({ "OID dotted (sha256WithRSAEncryption)",        icase_re(R"(\b1\.2\.840\.113549\.1\.1\.11\b)") });
    P.push_back({ "OID dotted (pkcs-1)",                          icase_re(R"(\b1\.2\.840\.113549\.1\.1\b)") });
    P.push_back({ "OID dotted (pbeWithMD2AndDES-CBC)",           icase_re(R"(\b1\.2\.840\.113549\.1\.5\.1\b)") });
    P.push_back({ "OID dotted (emailAddress)",                    icase_re(R"(\b1\.2\.840\.113549\.1\.9\.1\b)") });

    // ECC
    P.push_back({ "OID dotted (ecPublicKey)",                     icase_re(R"(\b1\.2\.840\.10045\.2\.1\b)") });
    P.push_back({ "OID dotted (secp256r1/prime256v1)",            icase_re(R"(\b1\.2\.840\.10045\.3\.1\.7\b)") });
    P.push_back({ "OID dotted (secp384r1)",                       icase_re(R"(\b1\.3\.132\.0\.34\b)") });
    P.push_back({ "OID dotted (secp521r1)",                       icase_re(R"(\b1\.3\.132\.0\.35\b)") });
    P.push_back({ "OID dotted (secp224r1)",                       icase_re(R"(\b1\.3\.132\.0\.33\b)") });
    P.push_back({ "OID dotted (secp224k1)",                       icase_re(R"(\b1\.3\.132\.0\.32\b)") });
    P.push_back({ "OID dotted (secp256k1)",                       icase_re(R"(\b1\.3\.132\.0\.10\b)") });
    P.push_back({ "OID dotted (brainpoolP256r1)",                 icase_re(R"(\b1\.3\.36\.3\.3\.2\.8\.1\.1\.7\b)") });
    P.push_back({ "OID dotted (brainpoolP384r1)",                 icase_re(R"(\b1\.3\.36\.3\.3\.2\.8\.1\.1\.11\b)") });
    P.push_back({ "OID dotted (brainpoolP512r1)",                 icase_re(R"(\b1\.3\.36\.3\.3\.2\.8\.1\.1\.13\b)") });
    P.push_back({ "OID dotted (X25519)",                          icase_re(R"(\b1\.3\.101\.110\b)") });
    P.push_back({ "OID dotted (X448)",                            icase_re(R"(\b1\.3\.101\.111\b)") });
    P.push_back({ "OID dotted (Ed25519)",                         icase_re(R"(\b1\.3\.101\.112\b)") });
    P.push_back({ "OID dotted (Ed448)",                           icase_re(R"(\b1\.3\.101\.113\b)") });

    // -------- ECC representative parameters --------
    // NIST P-256
    P.push_back({ "ECC(secp256r1 param p)",  hex_literal("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF") });
    P.push_back({ "ECC(secp256r1 param a)",  hex_literal("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC") });
    P.push_back({ "ECC(secp256r1 param b)",  hex_literal("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B") });
    P.push_back({ "ECC(secp256r1 param Gx)", hex_literal("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296") });
    P.push_back({ "ECC(secp256r1 param Gy)", hex_literal("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5") });
    P.push_back({ "ECC(secp256r1 param n)",  hex_literal("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551") });

    // NIST P-384
    P.push_back({ "ECC(secp384r1 param p)",  hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF") });
    P.push_back({ "ECC(secp384r1 param n)",  hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973") });

    // NIST P-521
    P.push_back({ "ECC(secp521r1 param p)",  hex_literal("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") });

    // secp224r1 / secp224k1 / secp256k1
    P.push_back({ "ECC(secp224r1 param p)",  hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001") });
    P.push_back({ "ECC(secp224k1 param p)",  hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D") });
    P.push_back({ "ECC(secp256k1 param p)",  hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F") });

    // brainpool
    P.push_back({ "ECC(brainpoolP256r1 param p)", hex_literal("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377") });
    P.push_back({ "ECC(brainpoolP384r1 param p)", hex_literal("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53") });
    P.push_back({ "ECC(brainpoolP512r1 param p)", hex_literal("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BCC66842AECDA12AE6A380E6") });

    // Montgomery / Edwards
    P.push_back({ "Curve(X25519) param p",  hex_literal("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED") });
    // X448 p
    P.push_back({ "Curve(X448) param p",     hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") });
    // Ed25519 p
    P.push_back({ "Curve(Ed25519) param p", hex_literal("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED") });

    // GOST
    P.push_back({ "GOSTR3410-A param p",    hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97") });
    P.push_back({ "GOSTR3410-A param a",    hex_literal("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94") });

    return P;
}

std::vector<BytePattern> getDefaultOIDBytePatterns() {
    // List of dotted OIDs and descriptive names.
    const std::vector<std::pair<std::string, std::string>> OIDS = {
        // --- RSA OIDs (29p) ---
        { "pkcs-1",                        "1.2.840.113549.1.1"   },
        { "rsaEncryption",                 "1.2.840.113549.1.1.1" },
        { "md2WithRSAEncryption",          "1.2.840.113549.1.1.2" },
        { "md4WithRSAEncryption",          "1.2.840.113549.1.1.3" },
        { "md5WithRSAEncryption",          "1.2.840.113549.1.1.4" },
        { "sha1WithRSAEncryption",         "1.2.840.113549.1.1.5" },
        { "rsassaPss",                     "1.2.840.113549.1.1.10"},
        { "sha256WithRSAEncryption",       "1.2.840.113549.1.1.11"},
        { "sha384WithRSAEncryption",       "1.2.840.113549.1.1.12"},
        { "sha512WithRSAEncryption",       "1.2.840.113549.1.1.13"},
        { "sha224WithRSAEncryption",       "1.2.840.113549.1.1.14"},
        { "sha512_224WithRSAEncryption",   "1.2.840.113549.1.1.15"},
        { "sha512_256WithRSAEncryption",   "1.2.840.113549.1.1.16"},
        { "pbeWithMD2AndDES-CBC",          "1.2.840.113549.1.5.1" },
        { "emailAddress",                  "1.2.840.113549.1.9.1" },

        // --- ECC OIDs (30~31p) ---
        { "ecPublicKey",                   "1.2.840.10045.2.1" },
        { "ecdsa-with-SHA1",               "1.2.840.10045.4.1" },
        { "ecdsa-with-SHA224",             "1.2.840.10045.4.3.1" },
        { "ecdsa-with-SHA256",             "1.2.840.10045.4.3.2" },
        { "ecdsa-with-SHA384",             "1.2.840.10045.4.3.3" },
        { "ecdsa-with-SHA512",             "1.2.840.10045.4.3.4" },

        { "secp256r1 (prime256v1)",        "1.2.840.10045.3.1.7" },
        { "secp384r1",                     "1.3.132.0.34" },
        { "secp521r1",                     "1.3.132.0.35" },
        { "secp224r1",                     "1.3.132.0.33" },
        { "secp224k1",                     "1.3.132.0.32" },
        { "secp256k1",                     "1.3.132.0.10" },
        { "sect283k1",                     "1.3.132.0.16" },
        { "sect283r1",                     "1.3.132.0.17" },
        { "sect163k1",                     "1.3.132.0.1"  },
        { "sect163r2",                     "1.3.132.0.15" },
        { "sect233k1",                     "1.3.132.0.24" },
        { "sect233r1",                     "1.3.132.0.26" },

        { "brainpoolP256r1",               "1.3.36.3.3.2.8.1.1.7" },
        { "brainpoolP384r1",               "1.3.36.3.3.2.8.1.1.11" },
        { "brainpoolP512r1",               "1.3.36.3.3.2.8.1.1.13" },

        { "X25519",                        "1.3.101.110" },
        { "X448",                          "1.3.101.111" },
        { "Ed25519",                       "1.3.101.112" },
        { "Ed448",                         "1.3.101.113" },

        // --- ECDH OIDs (32p) ---
        { "dhSinglePass-stdDH-sha224kdf-scheme", "1.3.132.1.11.1" },
        { "dhSinglePass-stdDH-sha256kdf-scheme", "1.3.132.1.11.2" },
        { "dhSinglePass-stdDH-sha384kdf-scheme", "1.3.132.1.11.3" },
        { "dhSinglePass-stdDH-sha512kdf-scheme", "1.3.132.1.11.4" },
        { "dhSinglePass-cofactorDH-sha1kdf-scheme","1.3.132.1.12" },
        { "id-alg-ESDH",                   "1.2.840.113549.1.9.16.3.5"  },
        { "id-alg-SDHW",                   "1.2.840.113549.1.9.16.3.16" },
        { "id-alg-ESDHwith3DES",           "1.2.840.113549.1.9.16.3.15" },
        { "id-alg-ESDHwithAES128",         "1.2.840.113549.1.9.16.3.17" },
        { "id-alg-ESDHwithAES192",         "1.2.840.113549.1.9.16.3.18" },
        { "id-alg-ESDHwithAES256",         "1.2.840.113549.1.9.16.3.19" },

        // --- GOST ECC (31p) ---
        { "id-GostR3410-2001-CryptoPro-A",   "1.2.643.2.2.35.1" },
        { "id-GostR3410-2001-CryptoPro-B",   "1.2.643.2.2.35.2" },
        { "id-GostR3410-2001-CryptoPro-C",   "1.2.643.2.2.35.3" },
        { "id-GostR3410-2001-CryptoPro-XchA","1.2.643.2.2.36.0" },
        { "id-GostR3410-2001-CryptoPro-XchB","1.2.643.2.2.36.1" },
    };

    std::vector<BytePattern> B;
    B.reserve(OIDS.size() * 2);
    for (const auto& kv : OIDS) {
        const std::string& name   = kv.first;
        const std::string& dotted = kv.second;
        auto der = oidDERBytes(dotted);
        B.push_back({ "OID: " + name + " (" + dotted + ") [DER]", der });
        auto val = oidValueBytes(dotted);
        B.push_back({ "OID: " + name + " (" + dotted + ") [VAL]", val });
    }
    return B;
}

} // namespace crypto_patterns
