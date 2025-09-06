#pragma once

#include "PatternDefinitions.h"

#include <string>
#include <vector>

namespace pattern_loader {

struct LoadResult {
    std::vector<AlgorithmPattern> regexPatterns;
    std::vector<BytePattern>      bytePatterns;
    std::string                   sourcePath;
    std::string                   error;
};

// Resolve path (ENV > ./patterns.json > ./config/patterns.json) and load.
LoadResult loadFromJson();

// Load explicitly from a given path.
LoadResult loadFromJsonFile(const std::string& path);

} // namespace pattern_loader
