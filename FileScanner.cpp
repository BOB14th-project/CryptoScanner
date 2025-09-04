#include "FileScanner.h"

#include <cctype>
#include <regex>
#include <unordered_map>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <iomanip>

// Extract printable ASCII substrings from a buffer, storing their
// starting offsets.  Non-printable bytes reset the current string.
std::vector<AsciiString>
FileScanner::extractAsciiStrings(const std::vector<unsigned char>& data,
    std::size_t minLength) {
    std::vector<AsciiString> results;
    std::string current;
    std::size_t start = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        unsigned char ch = data[i];
        if (ch >= 0x20 && ch <= 0x7E) {
            if (current.empty()) start = i;
            current.push_back(static_cast<char>(ch));
        }
        else {
            if (current.size() >= minLength) {
                results.push_back({ start, current });
            }
            current.clear();
        }
    }
    if (current.size() >= minLength) {
        results.push_back({ start, current });
    }
    return results;
}

// Iterate each AsciiString and match against each AlgorithmPattern.
// For every match, compute the absolute file offset and collect
// the results under the algorithm name.
std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanStringsWithOffsets(const std::vector<AsciiString>& strings,
    const std::vector<AlgorithmPattern>& patterns) {
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> results;
    for (const auto& s : strings) {
        for (const auto& pat : patterns) {
            std::smatch m;
            if (std::regex_search(s.text, m, pat.pattern)) {
                std::size_t absOffset = s.offset + static_cast<std::size_t>(m.position());
                results[pat.name].push_back({ m.str(), absOffset });
            }
        }
    }
    return results;
}

// Convert a vector of bytes into an uppercase hex string separated by
// spaces.  This helper is used when returning the matched byte
// sequences to the caller.
static std::string toHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::uppercase << std::hex << std::setw(2)
            << std::setfill('0') << static_cast<int>(b) << ' ';
    }
    std::string s = oss.str();
    if (!s.empty()) s.pop_back();
    return s;
}

// Search the raw byte buffer for each BytePattern's exact sequence.
// Matches may overlap; each occurrence is reported.  Results are
// grouped by pattern name with a vector of (hex string, offset).
std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanBytesWithOffsets(const std::vector<unsigned char>& data,
    const std::vector<BytePattern>& patterns) {
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> results;
    for (const auto& pat : patterns) {
        const auto& needle = pat.bytes;
        if (needle.empty() || data.size() < needle.size()) continue;
        auto it = data.begin();
        while (true) {
            it = std::search(it, data.end(), needle.begin(), needle.end());
            if (it == data.end()) break;
            std::size_t offset = static_cast<std::size_t>(std::distance(data.begin(), it));
            results[pat.name].push_back({ toHex(needle), offset });
            ++it; // allow overlapping matches
        }
    }
    return results;
}
