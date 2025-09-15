#pragma once

#include "PatternDefinitions.h"
#include "FileScanner.h"

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <functional>

struct Detection {
    std::string filePath;
    std::size_t offset;
    std::string algorithm;
    std::string matchString;
    std::string evidenceType;
    std::string severity;
};

enum class ScanProfile {
    Default,
    InstitutionStrict,
    DeveloperMax
};

struct ScanOptions {
    bool recurse = true;
    bool deepJar = true;
    bool excludeSystemDirs = false;
    bool excludeDevDirs = false;
    std::size_t jarMaxEntryJava = 0;
    std::size_t jarMaxEntryClass = 0;
    std::size_t jarMaxTotalUncomp = 0;
    std::size_t jarMaxEntries = 0;
    ScanProfile profile = ScanProfile::Default;
    std::vector<std::string> includeGlobs;
    std::vector<std::string> excludeGlobs;
    std::string csvSkipPath;
};

class CryptoScanner {
public:
    CryptoScanner();

    std::vector<Detection> scanFileDetailed(const std::string& filePath);
    std::vector<Detection> scanPathRecursive(const std::string& rootPath);

    std::vector<Detection> scanClassFileDetailed(const std::string& filePath);
    std::vector<Detection> scanJarFileDetailed(const std::string& filePath);
    std::vector<Detection> scanCertOrKeyFileDetailed(const std::string& filePath);

    std::vector<Detection> scanBinaryWholeFile(const std::string& filePath);

    static std::uintmax_t getFileSizeSafe(const std::string& path);
    static std::string lowercaseExt(const std::string& p);
    static bool isCertOrKeyExt(const std::string& ext);
    static bool isLikelyPem(const std::string& path);
    static bool readTextFile(const std::string& path, std::string& out);
    static bool readAllBytes(const std::string& path, std::vector<unsigned char>& out);

    void scanPathLikeAntivirus(
        const std::string& rootPath,
        const ScanOptions& opt,
        const std::function<void(const Detection&)>& onDetect,
        const std::function<void(const std::string&, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>& onProgress,
        const std::function<bool()>& isCancelled
    );

private:
    std::vector<Detection> scanJarViaMiniZ(const std::string& filePath);

    std::vector<AlgorithmPattern> patterns;
    std::vector<AlgorithmPattern> patternsApiOnly;
    std::vector<BytePattern>      oidBytePatterns;

    static std::string severityForTextPattern(const std::string& algName, const std::string& matched);
    static std::string severityForByteType(const std::string& type);
    static std::string evidenceTypeForTextPattern(const std::string& algName);
    static std::string evidenceLabelForByteType(const std::string& type);

    static bool isPemText(const std::string& text);
    static std::vector<std::vector<unsigned char>> pemDecodeAll(const std::string& text);
    static std::vector<unsigned char> b64decode(const std::string& s);

    static std::vector<std::string> loadExcludeGlobsFromCsv(const std::string& csvPath);

    std::function<bool()> cancelCb;
    ScanOptions activeOpt;
};

namespace scanprofile {
    inline const std::vector<std::string> kInstitutionExcludeGlobs = {
        "/proc/*",
        "/sys/*",
        "/dev/*",
        "/run/*",
        "/snap/*",
        "/var/lib/docker/*",
        "/var/lib/flatpak/*",
        "/var/cache/*",
        "/var/log/*",
        "/tmp/*",
        "/var/tmp/*",
        "/lost+found/*",
        "/usr/lib/aarch64-linux-gnu/*",
        "/usr/lib/x86_64-linux-gnu/*",
        "/lib/aarch64-linux-gnu/*",
        "/lib/x86_64-linux-gnu/*",
        "/usr/lib/python3/dist-packages/*",
        "/usr/lib/node_modules/*",
        "/usr/lib/gcc/*",
        "/usr/i686-w64-mingw32/*",
        "/usr/x86_64-w64-mingw32/*",
        "/usr/include/*",
        "/usr/share/doc/*",
        "/usr/share/locale/*",
        "/usr/share/man/*",
        "/usr/share/icons/*",
        "/usr/src/*",
        "/opt/cuda/*",
        "/usr/local/cuda/*",
        "/usr/local/share/*",
        "/usr/local/include/*",
        "/home/*/.vscode/*",
        "/home/*/.vscode-server/*",
        "/home/*/.cache/*",
        "/home/*/.cache/vmware/*",
        "/home/*/.config/Code/*",
        "/home/*/.local/share/Code/*",
        "/home/*/.npm/*",
        "/home/*/.nvm/*",
        "/home/*/.gradle/*",
        "/home/*/.m2/repository/*",
        "/home/*/.cargo/*",
        "/home/*/.rustup/*",
        "/home/*/.android/*",
        "/home/*/.conda/*",
        "/root/.vscode/*",
        "/root/.vscode-server/*",
        "/root/.cache/*",
        "/root/.config/Code/*",
        "/root/.local/share/Code/*"
    };

    inline const std::vector<std::string> kPreferredRootDirs = {
        "/home",
        "/root",
        "/etc",
        "/opt",
        "/srv",
        "/var/www",
        "/var/lib/tomcat",
        "/mnt",
        "/media",
        "/data",
        "/usr/local"
    };

    struct JarLimits {
        std::size_t maxEntryJava;
        std::size_t maxEntryClass;
        std::size_t maxTotalUncomp;
        std::size_t maxEntries;
    };

    inline const JarLimits kInstitutionJarLimits = {
        1024 * 1024,
        512 * 1024,
        200ull * 1024ull * 1024ull,
        5000
    };
}
