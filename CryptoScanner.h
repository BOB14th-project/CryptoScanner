#pragma once

#include "PatternDefinitions.h"
#include "FileScanner.h"

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

struct Detection {
    std::string filePath;
    std::size_t offset;
    std::string algorithm;
    std::string matchString;
    std::string evidenceType;
    std::string severity;
};

class CryptoScanner {
public:
    CryptoScanner();

    std::vector<Detection> scanFileDetailed(const std::string& filePath);
    std::vector<Detection> scanPathRecursive(const std::string& rootPath);

    std::vector<Detection> scanClassFileDetailed(const std::string& filePath);
    std::vector<Detection> scanJarFileDetailed(const std::string& filePath);
    std::vector<Detection> scanCertOrKeyFileDetailed(const std::string& filePath);

    std::vector<Detection> scanBinaryFileHeaderLimited(const std::string& filePath, std::size_t maxBytes);

    static std::uintmax_t getFileSizeSafe(const std::string& path);
    static std::string lowercaseExt(const std::string& p);
    static bool isCertOrKeyExt(const std::string& ext);
    static bool isLikelyPem(const std::string& path);
    static bool readTextFile(const std::string& path, std::string& out);
    static bool readAllBytes(const std::string& path, std::vector<unsigned char>& out);

private:
    std::vector<Detection> scanJarViaMiniZ(const std::string& filePath);

    std::vector<AlgorithmPattern> patterns;
    std::vector<BytePattern>      oidBytePatterns;

    static std::string severityForTextPattern(const std::string& algName, const std::string& matched);
    static std::string severityForByteType(const std::string& type);
    static std::string evidenceTypeForTextPattern(const std::string& algName);
    static std::string evidenceLabelForByteType(const std::string& type);

    static bool isPemText(const std::string& text);
    static std::vector<std::vector<unsigned char>> pemDecodeAll(const std::string& text);
    static std::vector<unsigned char> b64decode(const std::string& s);
};
