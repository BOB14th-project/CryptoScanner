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

    static bool runCommandText(const std::string& cmd, std::string& outText);
    static bool runCommandBinary(const std::string& cmd, std::vector<unsigned char>& outBin);
    static std::string shellQuote(const std::string& s);

    static bool toolExists(const std::string& program);
    static bool readTextFile(const std::string& path, std::string& out);
    static std::string makeTempDir();
    static void removeDirRecursive(const std::string& path);

private:
    // file-type routers
    std::vector<Detection> scanBinaryFileDetailed(const std::string& filePath);
    std::vector<Detection> scanClassFileDetailed(const std::string& filePath);
    std::vector<Detection> scanJarFileDetailed(const std::string& filePath);
    std::vector<Detection> scanJavaSourceFileDetailed(const std::string& filePath);
    std::vector<Detection> scanPythonSourceFileDetailed(const std::string& filePath);
    std::vector<Detection> scanCppSourceFileDetailed(const std::string& filePath);

    // jar helpers
    std::vector<Detection> scanJarViaMiniZ(const std::string& filePath);
    std::vector<Detection> scanJarViaUnzip(const std::string& filePath);

    std::vector<Detection> scanJarViaJarTool(const std::string& filePath);

    std::vector<Detection> scanBinaryFileHeaderLimited(const std::string& filePath, std::size_t maxBytes);

    std::vector<Detection> analyzeJarWithJadx(const std::string& filePath);
    std::vector<Detection> analyzeJarBytecode(const std::string& filePath);

    static std::uintmax_t getFileSizeSafe(const std::string& path);
    static std::size_t getJadxMaxBytes();
};
