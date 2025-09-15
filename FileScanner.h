#pragma once

#include "PatternDefinitions.h"

#include <string>
#include <vector>
#include <unordered_map>

struct AsciiString { std::size_t offset; std::string text; };

class FileScanner {
public:
    static void setCurrentSourceName(const std::string& path);
    static void clearCurrentSourceName();

    static std::vector<AsciiString> extractAsciiStrings(const std::vector<unsigned char>& data, std::size_t minLength = 4);

    static std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
    scanStringsWithOffsets(const std::vector<AsciiString>& strings, const std::vector<AlgorithmPattern>& patterns);

    static std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
    scanBytesWithOffsets(const std::vector<unsigned char>& data, const std::vector<BytePattern>& patterns);
};
