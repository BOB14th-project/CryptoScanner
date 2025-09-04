// PatternDefinitions.h
//
// Defines structures and helper functions for non-post-quantum
// cryptography detection.  The AlgorithmPattern struct couples a
// descriptive name with a regular expression used to scan ASCII
// strings.  BytePattern represents a raw byte sequence (e.g., DER
// encoded OIDs) along with a name.  The functions in the
// crypto_patterns namespace construct comprehensive default lists of
// patterns for legacy cryptographic algorithms and object identifiers.

#pragma once

#include <regex>
#include <string>
#include <vector>
#include <cstdint>

// Describes a single algorithm signature.  The `name` identifies
// what algorithm or feature is detected, and `pattern` is a
// case-insensitive regular expression applied to ASCII strings.
struct AlgorithmPattern {
    std::string name;
    std::regex  pattern;
};

// Represents a raw sequence of bytes to search for.  Typically used
// to match DER‑encoded object identifiers (OIDs) or their value
// components.  The `name` gives context to the pattern, while
// `bytes` holds the exact byte sequence to locate.
struct BytePattern {
    std::string name;
    std::vector<uint8_t> bytes;
};

namespace crypto_patterns {

    // Returns a list of AlgorithmPattern structures covering common
    // classical (non‑PQC) cryptographic algorithms.  These include
    // keywords, dotted OIDs expressed in ASCII and representative hex
    // constants for certain ECC curve parameters.
    std::vector<AlgorithmPattern> getDefaultPatterns();

    // Returns a list of BytePattern structures for DER‑encoded OIDs
    // and their value‑only representations.  This enables scanning
    // binary data for ASN.1 object identifiers corresponding to RSA,
    // ECC, brainpool and other legacy schemes.
    std::vector<BytePattern> getDefaultOIDBytePatterns();

} // namespace crypto_patterns
