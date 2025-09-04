#include "CryptoScanner.h"
#include <fstream>
#include <iostream>
#include <cctype>
#include <sstream>
#include <array>
#include <cstdio>
#include <cstring>

#include <filesystem>
namespace fs = std::filesystem;

#ifdef USE_MINIZ
#include "miniz.h"
#endif

CryptoScanner::CryptoScanner()
{
    patterns = crypto_patterns::getDefaultPatterns();
    oidBytePatterns = crypto_patterns::getDefaultOIDBytePatterns();
}

static std::string lowercaseExt(const std::string &p)
{
    auto pos = p.find_last_of('.');
    if (pos == std::string::npos)
        return {};
    std::string ext = p.substr(pos);
    for (char &c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return ext;
}

std::vector<Detection> CryptoScanner::scanFileDetailed(const std::string &filePath)
{
    std::ifstream check(filePath.c_str(), std::ios::binary);
    if (!check)
    {
        std::cerr << "[CryptoScanner] File not found: " << filePath << "\n";
        return {};
    }
    check.close();

    std::string ext = lowercaseExt(filePath);
    if (ext == ".jar")
        return scanJarFileDetailed(filePath);
    if (ext == ".class")
        return scanClassFileDetailed(filePath);
    return scanBinaryFileDetailed(filePath);
}

std::vector<Detection> CryptoScanner::scanBinaryFileDetailed(const std::string &filePath)
{
    std::ifstream in(filePath.c_str(), std::ios::binary);
    if (!in)
    {
        std::cerr << "[CryptoScanner] Failed to open file: " << filePath << "\n";
        return {};
    }
    in.seekg(0, std::ios::end);
    std::streampos size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(static_cast<std::size_t>(size));
    if (size > 0)
        in.read(reinterpret_cast<char *>(buffer.data()), size);

    auto strings = FileScanner::extractAsciiStrings(buffer);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches = FileScanner::scanBytesWithOffsets(buffer, oidBytePatterns);

    std::vector<Detection> out;
    auto collect = [&](const auto &M)
    {
        for (const auto &alg : M)
        {
            for (const auto &entry : alg.second)
            {
                Detection d;
                d.filePath = filePath;
                d.offset = entry.second;
                d.algorithm = alg.first;
                d.matchString = entry.first;
                out.push_back(d);
            }
        }
    };
    collect(textMatches);
    collect(oidMatches);
    return out;
}

std::vector<Detection> CryptoScanner::scanClassFileDetailed(const std::string &filePath)
{
    return scanBinaryFileDetailed(filePath);
}

std::vector<Detection> CryptoScanner::scanJarFileDetailed(const std::string &filePath)
{
#ifdef USE_MINIZ
    return scanJarViaMiniZ(filePath);
#else
    auto det = scanJarViaUnzip(filePath);
    if (!det.empty())
        return det;
    return scanBinaryFileDetailed(filePath);
#endif
}

std::vector<Detection> CryptoScanner::scanPathRecursive(const std::string &rootPath)
{
    std::vector<Detection> all;
    std::error_code ec;
    if (fs::is_regular_file(rootPath, ec))
    {
        auto v = scanFileDetailed(rootPath);
        all.insert(all.end(), v.begin(), v.end());
        return all;
    }
    if (!fs::is_directory(rootPath, ec))
    {
        std::cerr << "[CryptoScanner] Not a file or directory: " << rootPath << "\n";
        return all;
    }

    for (fs::recursive_directory_iterator it(rootPath, fs::directory_options::skip_permission_denied), end; it != end; ++it)
    {
        const fs::directory_entry &de = *it;
        if (!de.is_regular_file(ec))
            continue;
        std::string path = de.path().string();
        try
        {
            auto v = scanFileDetailed(path);
            if (!v.empty())
            {
                all.insert(all.end(), v.begin(), v.end());
            }
        }
        catch (...)
        {
            // keep walking
        }
    }
    return all;
}

// =========================
//  JAR via miniz
// =========================
std::vector<Detection> CryptoScanner::scanJarViaMiniZ(const std::string &filePath)
{
    std::vector<Detection> results;
#ifdef USE_MINIZ
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_file(&zip, filePath.c_str(), 0))
    {
        std::cerr << "[CryptoScanner] Failed to open JAR: " << filePath << "\n";
        return results;
    }

    mz_uint numFiles = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < numFiles; ++i)
    {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st))
            continue;
        if (mz_zip_reader_is_file_a_directory(&zip, i))
            continue;

        size_t outSize = 0;
        void *p = mz_zip_reader_extract_to_heap(&zip, i, &outSize, 0);
        if (!p || outSize == 0)
        {
            mz_free(p);
            continue;
        }
        std::vector<unsigned char> data(
            static_cast<unsigned char *>(p),
            static_cast<unsigned char *>(p) + outSize);
        mz_free(p);

        auto strings = FileScanner::extractAsciiStrings(data);
        auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

        std::string entryName = filePath + "::" + st.m_filename;
        auto collect = [&](const auto &M)
        {
            for (const auto &alg : M)
            {
                for (const auto &entry : alg.second)
                {
                    Detection d;
                    d.filePath = entryName;
                    d.offset = entry.second;
                    d.algorithm = alg.first;
                    d.matchString = entry.first;
                    results.push_back(d);
                }
            }
        };
        collect(textMatches);
        collect(oidMatches);
    }
    mz_zip_reader_end(&zip);
#endif
    return results;
}

// =============================
//  JAR via unzip
// =============================
std::vector<Detection> CryptoScanner::scanJarViaUnzip(const std::string &filePath)
{
    std::vector<Detection> results;

    std::string listOut;
    if (!runCommandText("zipinfo -1 " + shellQuote(filePath), listOut))
    {
        if (!runCommandText("unzip -Z -1 " + shellQuote(filePath), listOut))
        {
            if (!runCommandText("jar tf " + shellQuote(filePath), listOut))
            {
                std::cerr << "[CryptoScanner] No zipinfo/unzip/jar for: " << filePath << "\n";
                return results;
            }
        }
    }

    std::istringstream iss(listOut);
    std::string entry;
    while (std::getline(iss, entry))
    {
        if (entry.empty())
            continue;
        if (entry.back() == '/')
            continue;

        std::vector<unsigned char> data;
        std::string cmd = "unzip -p " + shellQuote(filePath) + " " + shellQuote(entry);
        if (!runCommandBinary(cmd, data))
        {
            cmd = "bsdtar -xO -f " + shellQuote(filePath) + " " + shellQuote(entry);
            if (!runCommandBinary(cmd, data))
            {
                continue;
            }
        }

        auto strings = FileScanner::extractAsciiStrings(data);
        auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

        std::string entryName = filePath + "::" + entry;
        auto collect = [&](const auto &M)
        {
            for (const auto &alg : M)
            {
                for (const auto &e : alg.second)
                {
                    Detection d;
                    d.filePath = entryName;
                    d.offset = e.second;
                    d.algorithm = alg.first;
                    d.matchString = e.first;
                    results.push_back(d);
                }
            }
        };
        collect(textMatches);
        collect(oidMatches);
    }
    return results;
}

// --------------------
// popen helpers
// --------------------
std::string CryptoScanner::shellQuote(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s)
    {
        if (c == '\'')
            out += "'\"'\"'";
        else
            out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

bool CryptoScanner::runCommandText(const std::string &cmd, std::string &outText)
{
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        return false;
    std::array<char, 8192> buf{};
    std::ostringstream oss;
    size_t total = 0, limit = 64 * 1024 * 1024;
    while (true)
    {
        size_t n = fread(buf.data(), 1, buf.size(), pipe);
        if (n == 0)
            break;
        oss.write(buf.data(), n);
        total += n;
        if (total > limit)
            break;
    }
    int rc = pclose(pipe);
    if (rc != 0)
        return false;
    outText = oss.str();
    return true;
}

bool CryptoScanner::runCommandBinary(const std::string &cmd, std::vector<unsigned char> &outBin)
{
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        return false;
    std::array<unsigned char, 8192> buf{};
    std::vector<unsigned char> data;
    data.reserve(64 * 1024);
    size_t total = 0, limit = 128 * 1024 * 1024;
    while (true)
    {
        size_t n = fread(buf.data(), 1, buf.size(), pipe);
        if (n == 0)
            break;
        data.insert(data.end(), buf.begin(), buf.begin() + n);
        total += n;
        if (total > limit)
            break;
    }
    int rc = pclose(pipe);
    if (rc != 0)
        return false;
    outBin.swap(data);
    return true;
}
