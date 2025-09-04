#pragma once

#include "PatternDefinitions.h"
#include "FileScanner.h"
#include <string>
#include <vector>

struct Detection
{
    std::string filePath;    // file or "jar::entry"
    std::size_t offset;      // byte offset inside the scanned blob
    std::string algorithm;   // e.g., "RSA", "AES-128", "SHA-1"
    std::string matchString; // matched text or OID bytes rendered
};

class CryptoScanner
{
public:
    CryptoScanner();

    // Scan a single file. Dispatches by extension (.jar/.class/other)
    std::vector<Detection> scanFileDetailed(const std::string &filePath);

    // Recursively scan a directory (follows regular files only).
    std::vector<Detection> scanPathRecursive(const std::string &rootPath);

    // Patterns are public so GUI can swap/extend if needed.
    std::vector<AlgorithmPattern> patterns;
    std::vector<BytePattern> oidBytePatterns;

private:
    std::vector<Detection> scanBinaryFileDetailed(const std::string &filePath);
    std::vector<Detection> scanClassFileDetailed(const std::string &filePath);
    std::vector<Detection> scanJarFileDetailed(const std::string &filePath);

    // JAR helpers
    std::vector<Detection> scanJarViaMiniZ(const std::string &filePath);
    std::vector<Detection> scanJarViaUnzip(const std::string &filePath);

    // popen helpers (fallback when no miniz)
    static bool runCommandText(const std::string &cmd, std::string &outText);
    static bool runCommandBinary(const std::string &cmd, std::vector<unsigned char> &outBin);
    static std::string shellQuote(const std::string &s);
};
