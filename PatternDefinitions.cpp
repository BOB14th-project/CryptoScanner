#include "PatternDefinitions.h"
#include "PatternLoader.h"

#include <iostream>

namespace crypto_patterns {

std::vector<AlgorithmPattern> getDefaultPatterns() {
    auto r = pattern_loader::loadFromJson();
    if (!r.error.empty()) std::cerr << "[PatternDefinitions] " << r.error << "\n";
    else std::cerr << "[PatternDefinitions] Loaded regex from: " << r.sourcePath << "\n";
    return std::move(r.regexPatterns);
}

std::vector<BytePattern> getDefaultOIDBytePatterns() {
    auto r = pattern_loader::loadFromJson();
    if (!r.error.empty()) std::cerr << "[PatternDefinitions] " << r.error << "\n";
    else std::cerr << "[PatternDefinitions] Loaded bytes/OIDs from: " << r.sourcePath << "\n";
    return std::move(r.bytePatterns);
}

} // namespace crypto_patterns
