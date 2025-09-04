#pragma once

#include "PatternDefinitions.h"
#include <string>
#include <vector>
#include <unordered_map>

/*
 * FileScanner provides functions to extract printable ASCII strings
 * along with their offsets from a byte buffer and to match those
 * strings against cryptographic pattern definitions.  Offsets are
 * essential for reporting the precise location of each match within
 * the file or archive.
 */

// Holds an ASCII substring and its starting offset within the file.
struct AsciiString {
    std::size_t offset;   // starting byte position of the string in the file
    std::string text;
};

class FileScanner {
public:
    // Extract printable ASCII strings (length >= minLength) from a byte buffer.
    // Returns a vector of AsciiString entries with text and offset.
    static std::vector<AsciiString>
        extractAsciiStrings(const std::vector<unsigned char>& data,
            std::size_t minLength = 4);

    // For each string in `strings`, apply each regex in `patterns`.
    // For every match, record the matched substring and its absolute
    // offset in the file (string offset + match position).  Returns
    // a map keyed by algorithm name with a vector of (match string, offset).
    static std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
        scanStringsWithOffsets(const std::vector<AsciiString>& strings,
            const std::vector<AlgorithmPattern>& patterns);

    // Scan the raw byte buffer for each BytePattern and record
    // occurrences.  For every match, returns the hex string of the
    // pattern and its offset in the file.  The map is keyed by the
    // pattern's name.
    static std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
        scanBytesWithOffsets(const std::vector<unsigned char>& data,
            const std::vector<BytePattern>& patterns);
};
