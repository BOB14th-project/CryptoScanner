#pragma once

#include <regex>
#include <string>
#include <vector>
#include <cstdint>

struct AlgorithmPattern {
    std::string name;
    std::regex  pattern;
};

struct BytePattern {
    std::string name;
    std::vector<uint8_t> bytes;
    std::string type;
};

namespace crypto_patterns {
    std::vector<AlgorithmPattern> getDefaultPatterns();        // from JSON
    std::vector<BytePattern>      getDefaultOIDBytePatterns(); // from JSON
}
