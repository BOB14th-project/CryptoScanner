#pragma once

#include "PatternDefinitions.h"
#include "FileScanner.h"

#include <string>
#include <vector>

struct Detection {
    std::string filePath;
    std::size_t offset;
    std::string algorithm;
    std::string matchString;
};

class CryptoScanner {
public:
    CryptoScanner();
    std::vector<Detection> scanFileDetailed(const std::string& filePath);
    std::vector<Detection> scanPathRecursive(const std::string& rootPath);

    std::vector<AlgorithmPattern> patterns;
    std::vector<BytePattern>      oidBytePatterns;

private:
    std::vector<Detection> scanBinaryFileDetailed(const std::string& filePath);
    std::vector<Detection> scanClassFileDetailed(const std::string& filePath);
    std::vector<Detection> scanJarFileDetailed(const std::string& filePath);

    std::vector<Detection> scanJarViaMiniZ(const std::string& filePath);
    std::vector<Detection> scanJarViaUnzip(const std::string& filePath);

    static bool runCommandText(const std::string& cmd, std::string& outText);
    static bool runCommandBinary(const std::string& cmd, std::vector<unsigned char>& outBin);
    static std::string shellQuote(const std::string& s);
};
