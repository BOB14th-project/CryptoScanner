#include "CryptoScanner.h"
#include "PatternLoader.h"
#include "JavaBytecodeScanner.h"
#include "JavaASTScanner.h"
#include "PythonASTScanner.h"
#include "CppASTScanner.h"
#include "ASTSymbol.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef USE_MINIZ
#include <miniz.h>
#endif

namespace fs = std::filesystem;

static inline bool ends_with(const std::string& s, const std::string& suffix){
    if(s.size() < suffix.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

static std::string toLowerStr(const std::string& s){
    std::string o; o.reserve(s.size());
    for(unsigned char c: s) o.push_back((char)std::tolower(c));
    return o;
}

static bool pathStartsWith(const fs::path& p, const std::string& rootPrefix){
    auto s = p.string();
    if(rootPrefix.empty()) return false;
    if(s.size() < rootPrefix.size()) return false;
    return std::equal(rootPrefix.begin(), rootPrefix.end(), s.begin());
}

static const AsciiString* findContextString(const std::vector<AsciiString>& strings, std::size_t matchOffset){
    for(const auto& s: strings){
        const std::size_t begin = s.offset;
        const std::size_t end   = s.offset + s.text.size();
        if(matchOffset >= begin && matchOffset < end) return &s;
    }
    return nullptr;
}

static bool isIsolatedNoiseToken(const std::string& algName, const std::string& matched, const std::string& contextLower){
    (void)algName; (void)matched; (void)contextLower;
    return false;
}

static std::string makeKey(const std::string& file, std::size_t line, const std::string& alg, const std::string& match, const std::string& ev){
    std::string k;
    k.reserve(file.size()+alg.size()+match.size()+32);
    k.append(file).push_back('|');
    k.append(std::to_string(line)).push_back('|');
    k.append(alg).push_back('|');
    k.append(match).push_back('|');
    k.append(ev);
    return k;
}

std::string CryptoScanner::lowercaseExt(const std::string& p){
    fs::path x(p);
    std::string e = x.has_extension()? x.extension().string() : std::string();
    std::string out; out.reserve(e.size());
    for(char c: e) out.push_back((char)std::tolower((unsigned char)c));
    return out;
}

std::uintmax_t CryptoScanner::getFileSizeSafe(const std::string& path){
    std::error_code ec; auto s = fs::file_size(path, ec);
    if(ec) return 0; return s;
}

bool CryptoScanner::readTextFile(const std::string& path, std::string& out){
    std::ifstream in(path, std::ios::binary);
    if(!in) return false;
    std::ostringstream ss; ss<<in.rdbuf();
    out = ss.str();
    return true;
}

bool CryptoScanner::readAllBytes(const std::string& path, std::vector<unsigned char>& out){
    std::ifstream in(path, std::ios::binary);
    if(!in) return false;
    in.seekg(0, std::ios::end);
    std::streamoff n = in.tellg();
    in.seekg(0, std::ios::beg);
    out.resize((size_t)std::max<int64_t>(0, n));
    in.read((char*)out.data(), (std::streamsize)out.size());
    return true;
}

bool CryptoScanner::isCertOrKeyExt(const std::string& ext){
    static const std::unordered_set<std::string> exts = {
        ".cer",".crt",".der",".pem",".key",".p7b",".p7c",".p12",".pfx",".csr"
    };
    return exts.count(ext) != 0;
}

static bool isPemLine(const std::string& s){
    return s.find("-----BEGIN ")!=std::string::npos || s.find("-----END ")!=std::string::npos;
}

bool CryptoScanner::isPemText(const std::string& text){
    std::istringstream is(text);
    std::string line;
    int found=0;
    while(std::getline(is, line)){
        if(isPemLine(line)) { found++; if(found>=2) return true; }
    }
    return false;
}

bool CryptoScanner::isLikelyPem(const std::string& path){
    std::array<char, 4096> buf{};
    std::ifstream in(path, std::ios::binary);
    if(!in) return false;
    in.read(buf.data(), (std::streamsize)buf.size());
    std::string s(buf.data(), (size_t)in.gcount());
    return isPemText(s);
}

std::vector<unsigned char> CryptoScanner::b64decode(const std::string& s){
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<unsigned char> out;
    int val=0, valb=-8;
    for(unsigned char c: s){
        if(std::isspace(c)) continue;
        int d = T[c];
        if(d==-1) break;
        val = (val<<6) + d;
        valb += 6;
        if(valb>=0){
            out.push_back((unsigned char)((val>>valb)&0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::vector<std::vector<unsigned char>> CryptoScanner::pemDecodeAll(const std::string& text){
    std::vector<std::vector<unsigned char>> der;
    std::istringstream is(text);
    std::string line;
    bool inBlock=false;
    std::string b64;
    while(std::getline(is, line)){
        if(line.rfind("-----BEGIN ",0)==0){ inBlock=true; b64.clear(); continue; }
        if(line.rfind("-----END ",0)==0){ inBlock=false; if(!b64.empty()) der.push_back(b64decode(b64)); b64.clear(); continue; }
        if(inBlock){ b64 += line; }
    }
    return der;
}

CryptoScanner::CryptoScanner(){
    auto LR = pattern_loader::loadFromJson();
    if(!LR.error.empty()){
        std::cerr << "[CryptoScanner] Warning: failed to load patterns.json: " << LR.error << "\n";
    }
    patterns        = LR.regexPatterns;
    oidBytePatterns = LR.bytePatterns;
}

std::string CryptoScanner::severityForTextPattern(const std::string& algName, const std::string& matched){
    std::string a = toLowerStr(algName);
    std::string m = toLowerStr(matched);
    if(a.find("md5")!=std::string::npos || a.find("sha1")!=std::string::npos) return "high";
    if(a.find("3des")!=std::string::npos) return "high";
    if(a.find("des")!=std::string::npos && (m=="des" || m=="des-ede" || m=="3des")) return "high";
    return "low";
}

std::string CryptoScanner::severityForByteType(const std::string& type){
    if(type=="sig_md5" || type=="sig_sha1") return "high";
    return "low";
}

std::string CryptoScanner::evidenceTypeForTextPattern(const std::string&){
    return "text";
}

std::string CryptoScanner::evidenceLabelForByteType(const std::string& type){
    if(type=="oid") return "x509-oid";
    if(!type.empty()) return type;
    return "bytes";
}

static void add_ast_unique(std::vector<Detection>& out, std::unordered_set<std::string>& seen,
                           const std::string& file, std::size_t line,
                           const std::string& alg, const std::string& match,
                           const std::string& sev){
    const std::string ev = "ast";
    std::string key = makeKey(file, line, alg, match, ev);
    if(seen.insert(key).second){
        out.push_back({ file, line, alg, match, ev, sev });
    }
}

static void match_patterns_over_candidates(const std::vector<AlgorithmPattern>& patterns,
                                           const std::vector<std::string>& candidates,
                                           const std::string& file, std::size_t line,
                                           std::vector<Detection>& out,
                                           std::unordered_set<std::string>& seen,
                                           const std::function<std::string(const std::string&, const std::string&)>& sevFn){
    for(const auto& cand: candidates){
        if(cand.empty()) continue;
        for(const auto& ap: patterns){
            try{
                std::smatch m;
                if(std::regex_search(cand, m, ap.pattern)){
                    const std::string hit = m.str(0);
                    add_ast_unique(out, seen, file, line, ap.name, hit, sevFn(ap.name, hit));
                }
            }catch(...){}
        }
    }
}

std::vector<Detection> CryptoScanner::scanBinaryWholeFile(const std::string& filePath){
    std::vector<Detection> results;
    std::vector<unsigned char> data;
    if(!readAllBytes(filePath, data)) return results;

    auto strings     = FileScanner::extractAsciiStrings(data);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches  = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

    for(const auto& alg : textMatches){
        for(const auto& e : alg.second){
            const AsciiString* ctx = findContextString(strings, e.second);
            std::string ctxLower = ctx ? toLowerStr(ctx->text) : std::string();
            if(isIsolatedNoiseToken(alg.first, e.first, ctxLower)) continue;
            results.push_back({ filePath, e.second, alg.first, e.first, evidenceTypeForTextPattern(alg.first), severityForTextPattern(alg.first, e.first) });
        }
    }
    for(const auto& alg : oidMatches){
        for(const auto& e : alg.second){
            results.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType("oid"), severityForByteType("oid") });
        }
    }
    return results;
}

std::vector<Detection> CryptoScanner::scanClassFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    std::vector<unsigned char> data;
    if(!readAllBytes(filePath, data)) return out;

    auto strings     = FileScanner::extractAsciiStrings(data);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches  = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

    for(const auto& alg : textMatches){
        for(const auto& e : alg.second){
            const AsciiString* ctx = findContextString(strings, e.second);
            std::string ctxLower = ctx ? toLowerStr(ctx->text) : std::string();
            if(isIsolatedNoiseToken(alg.first, e.first, ctxLower)) continue;
            out.push_back({ filePath, e.second, alg.first, e.first, evidenceTypeForTextPattern(alg.first), severityForTextPattern(alg.first, e.first) });
        }
    }
    for(const auto& alg : oidMatches){
        for(const auto& e : alg.second){
            out.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType("oid"), severityForByteType("oid") });
        }
    }

    auto bc = analyzers::JavaBytecodeScanner::scanClassBytes(filePath, data);
    out.insert(out.end(), bc.begin(), bc.end());
    return out;
}

std::vector<Detection> CryptoScanner::scanJarFileDetailed(const std::string& filePath){
    return scanJarViaMiniZ(filePath);
}

std::vector<Detection> CryptoScanner::scanJarViaMiniZ(const std::string& filePath){
    std::vector<Detection> results;
#ifndef USE_MINIZ
    (void)filePath;
    return results;
#else
    mz_zip_archive zip; std::memset(&zip, 0, sizeof(zip));
    if(!mz_zip_reader_init_file(&zip, filePath.c_str(), 0)){
        return results;
    }
    const int n = (int)mz_zip_reader_get_num_files(&zip);

    std::unordered_map<std::string,std::string> byteType;
    for(const auto& bp: oidBytePatterns) byteType[bp.name] = bp.type;

    std::unordered_set<std::string> seen;

    for(int i=0; i<n; ++i){
        mz_zip_archive_file_stat st;
        if(!mz_zip_reader_file_stat(&zip, i, &st)) continue;
        if(st.m_is_directory) continue;

        std::string entry = st.m_filename;

        size_t out_size = 0;
        void* p = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if(!p) continue;
        std::vector<unsigned char> data((unsigned char*)p, (unsigned char*)p + out_size);
        mz_free(p);

        const std::string display = filePath + "::" + entry;
        std::string ext = lowercaseExt(entry);
        bool isSrc = (ext==".java");

        if(!isSrc){
            auto strings     = FileScanner::extractAsciiStrings(data);
            auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
            auto oidMatches  = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

            for(const auto& alg : textMatches){
                for(const auto& e : alg.second){
                    const AsciiString* ctx = findContextString(strings, e.second);
                    std::string ctxLower = ctx ? toLowerStr(ctx->text) : std::string();
                    if(isIsolatedNoiseToken(alg.first, e.first, ctxLower)) continue;
                    results.push_back({ display, e.second, alg.first, e.first, evidenceTypeForTextPattern(alg.first), severityForTextPattern(alg.first, e.first) });
                }
            }
            for(const auto& alg : oidMatches){
                const std::string et = byteType.count(alg.first)? byteType[alg.first] : std::string();
                for(const auto& e : alg.second){
                    results.push_back({ display, e.second, alg.first, e.first, evidenceLabelForByteType(et), severityForByteType(et) });
                }
            }
        }

        if(ends_with(entry, ".class")){
            auto bc = analyzers::JavaBytecodeScanner::scanClassBytes(display, data);
            results.insert(results.end(), bc.begin(), bc.end());
        }
        if(ends_with(entry, ".java")){
            std::string src((const char*)data.data(), data.size());
            auto syms = analyzers::JavaASTScanner::collectSymbols(display, src);
            for(const auto& s: syms){
                std::vector<std::string> cands;
                cands.push_back(s.callee_full);
                if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
                if(!s.first_arg.empty()) cands.push_back(s.first_arg);
                match_patterns_over_candidates(patterns, cands, s.filePath, s.line, results, seen,
                                               [&](const std::string& a, const std::string& m){ return severityForTextPattern(a, m); });
            }
        }
    }

    mz_zip_reader_end(&zip);
    return results;
#endif
}

std::vector<Detection> CryptoScanner::scanCertOrKeyFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    std::string text;
    readTextFile(filePath, text);
    if(isPemText(text)){
        auto all = pemDecodeAll(text);
        for(const auto& der: all){
            auto oidMatches = FileScanner::scanBytesWithOffsets(der, oidBytePatterns);
            for(const auto& alg : oidMatches){
                for(const auto& e : alg.second){
                    out.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType("oid"), severityForByteType("oid") });
                }
            }
        }
        return out;
    }

    std::vector<unsigned char> data;
    if(readAllBytes(filePath, data)){
        auto oidMatches = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);
        for(const auto& alg : oidMatches){
            for(const auto& e : alg.second){
                out.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType("oid"), severityForByteType("oid") });
            }
        }
    }
    return out;
}

std::vector<Detection> CryptoScanner::scanFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    const std::string ext = lowercaseExt(filePath);

    if(ext==".jar" || ext==".zip"){
        auto v = scanJarFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }
    if(ext==".class"){
        auto v = scanClassFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }
    if(isCertOrKeyExt(ext) || isLikelyPem(filePath)){
        auto v = scanCertOrKeyFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }

    if(ext==".java"){
        std::string code; readTextFile(filePath, code);
        auto syms = analyzers::JavaASTScanner::collectSymbols(filePath, code);
        std::unordered_set<std::string> seen;
        for(const auto& s: syms){
            std::vector<std::string> cands;
            cands.push_back(s.callee_full);
            if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if(!s.first_arg.empty()) cands.push_back(s.first_arg);
            match_patterns_over_candidates(patterns, cands, s.filePath, s.line, out, seen,
                                           [&](const std::string& a, const std::string& m){ return severityForTextPattern(a, m); });
        }
        return out;
    } else if(ext==".py"){
        auto syms = analyzers::PythonASTScanner::collectSymbols(filePath);
        std::unordered_set<std::string> seen;
        for(const auto& s: syms){
            std::vector<std::string> cands;
            cands.push_back(s.callee_full);
            if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if(!s.first_arg.empty()) cands.push_back(s.first_arg);
            match_patterns_over_candidates(patterns, cands, s.filePath, s.line, out, seen,
                                           [&](const std::string& a, const std::string& m){ return severityForTextPattern(a, m); });
        }
        return out;
    } else if(ext==".c" || ext==".cc" || ext==".cpp" || ext==".cxx" || ext==".h" || ext==".hpp" || ext==".hh" || ext==".ld"){
        auto syms = analyzers::CppASTScanner::collectSymbols(filePath);
        std::unordered_set<std::string> seen;
        for(const auto& s: syms){
            std::vector<std::string> cands;
            cands.push_back(s.callee_full);
            if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if(!s.first_arg.empty()) cands.push_back(s.first_arg);
            match_patterns_over_candidates(patterns, cands, s.filePath, s.line, out, seen,
                                           [&](const std::string& a, const std::string& m){ return severityForTextPattern(a, m); });
        }
        return out;
    }

    auto v = scanBinaryWholeFile(filePath);
    out.insert(out.end(), v.begin(), v.end());
    return out;
}

std::vector<Detection> CryptoScanner::scanPathRecursive(const std::string& rootPath){
    std::vector<Detection> all;
    for(auto it = fs::recursive_directory_iterator(rootPath, fs::directory_options::skip_permission_denied);
        it != fs::recursive_directory_iterator(); ++it){
        const fs::directory_entry& de = *it;
        if(!de.is_regular_file()) continue;
        std::string path = de.path().string();
        auto v = scanFileDetailed(path);
        all.insert(all.end(), v.begin(), v.end());
    }
    return all;
}

void CryptoScanner::scanPathLikeAntivirus(
    const std::string& rootPath,
    const ScanOptions& opt,
    const std::function<void(const Detection&)>& onDetect,
    const std::function<void(const std::string&, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>& onProgress,
    const std::function<bool()>& isCancelled
){
    std::unordered_set<std::string> hardSkipRoots = {
        "/proc","/sys","/dev","/run","/lost+found"
    };
    std::vector<std::string> broadSystemRoots = {
        "/usr","/lib","/lib64","/var/lib","/usr/share","/usr/include"
    };
    std::vector<std::string> allowExceptions = {
        "/usr/local","/opt","/etc","/home","/root","/srv","/var/www","/var/opt"
    };

    std::unordered_set<std::string> srcExts = {".c",".cc",".cpp",".cxx",".py",".java",".ld",".h",".hh",".hpp"};
    std::unordered_set<std::string> classExts = {".class"};
    std::unordered_set<std::string> jarExts = {".jar",".zip"};

    auto sizeOf = [&](const fs::path& p){ return (std::uint64_t)getFileSizeSafe(p.string()); };
    const std::uint64_t maxSrcSize = 32ull * 1024ull * 1024ull;
    const std::uint64_t maxHdrSize = 8ull  * 1024ull * 1024ull;
    const std::uint64_t maxClassSize = 32ull * 1024ull * 1024ull;
    const std::uint64_t maxArchiveSize = 1024ull * 1024ull * 1024ull;
    const std::uint64_t maxJarDeepBytes = 256ull * 1024ull * 1024ull;

    std::vector<std::string> files;
    if(fs::is_regular_file(rootPath)){
        files.push_back(rootPath);
    }else{
        for(auto it = fs::recursive_directory_iterator(rootPath, fs::directory_options::skip_permission_denied);
            it != fs::recursive_directory_iterator(); ++it){
            if(isCancelled && isCancelled()) return;
            const fs::directory_entry& de = *it;
            const fs::path p = de.path();

            bool skip = false;
            for(const auto& r: hardSkipRoots) if(pathStartsWith(p, r)) { skip=true; break; }
            if(skip) { it.disable_recursion_pending(); continue; }

            if(de.is_regular_file()){
                std::string ext = lowercaseExt(p.string());
                if(srcExts.count(ext)){
                    if(ext==".h" || ext==".hh" || ext==".hpp"){
                        if(sizeOf(p) > maxHdrSize) continue;
                    }else{
                        if(sizeOf(p) > maxSrcSize) continue;
                    }
                }
                if(classExts.count(ext) && sizeOf(p) > maxClassSize) continue;
                if(jarExts.count(ext) && sizeOf(p) > maxArchiveSize) continue;
                files.push_back(p.string());
            }
        }
    }

    std::uint64_t totalFiles = files.size();
    std::uint64_t doneFiles = 0;
    std::uint64_t totalBytes = 0;
    std::uint64_t doneBytes = 0;
    for(const auto& f: files) totalBytes += getFileSizeSafe(f);

    for(const auto& cur: files){
        if(isCancelled && isCancelled()) return;
        fs::path p(cur);
        std::string ext = lowercaseExt(cur);
        std::vector<Detection> v;
        if(ext==".jar" && opt.deepJar){
            if(sizeOf(p) > maxJarDeepBytes) v = scanBinaryWholeFile(cur);
            else v = scanJarFileDetailed(cur);
        }else{
            v = scanFileDetailed(cur);
        }
        for(const auto& d: v) onDetect(d);
        doneFiles++;
        const std::uint64_t sz = sizeOf(p);
        doneBytes += sz;
        onProgress(cur, doneFiles, totalFiles, doneBytes, totalBytes);
    }
}
