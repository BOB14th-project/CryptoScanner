#include "CryptoScanner.h"
#include "PatternLoader.h"
#include "JavaBytecodeScanner.h"
#include "JavaASTScanner.h"
#include "PythonASTScanner.h"
#include "CppASTScanner.h"

#include <fstream>
#include <iostream>
#include <cctype>
#include <sstream>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>

#ifdef USE_MINIZ
#include "third_party/miniz/miniz.h"
#endif

namespace fs = std::filesystem;

static inline bool ends_with(const std::string& s, const std::string& suffix){
    if(s.size() < suffix.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

std::uintmax_t CryptoScanner::getFileSizeSafe(const std::string& path){
    std::error_code ec; auto sz = fs::file_size(path, ec);
    if(ec) return 0;
    return sz;
}

std::string CryptoScanner::lowercaseExt(const std::string& p){
    auto pos = p.find_last_of('.');
    std::string e = (pos==std::string::npos)? std::string() : p.substr(pos);
    for(char& c: e) c = std::tolower((unsigned char)c);
    return e;
}

bool CryptoScanner::isCertOrKeyExt(const std::string& ext){
    static const std::unordered_set<std::string> exts = {
        ".pem",".crt",".cer",".der",".key",".csr",".p7b",".p7c",".pkcs7",".spc"
    };
    return exts.count(ext)>0;
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
    in.seekg(0,std::ios::end);
    auto sz = in.tellg();
    in.seekg(0,std::ios::beg);
    out.resize((size_t)sz);
    if(sz>0) in.read((char*)out.data(), sz);
    return true;
}

std::string CryptoScanner::severityForTextPattern(const std::string& algName, const std::string& matched){
    (void)matched;
    if(algName.find("OID dotted") != std::string::npos) return "high";
    if(algName.find("PEM Header") != std::string::npos)  return "med";
    if(algName.find("API (OpenSSL)") != std::string::npos
    || algName.find("API (Windows CNG/CAPI)") != std::string::npos
    || algName.find("API (libgcrypt)") != std::string::npos) return "med";
    if(algName.find("MD5")!=std::string::npos || algName.find("SHA-1")!=std::string::npos) return "med";
    return "low";
}
std::string CryptoScanner::evidenceTypeForTextPattern(const std::string& algName){
    if(algName.find("OID dotted") != std::string::npos) return "oid";
    return "text";
}
std::string CryptoScanner::severityForByteType(const std::string& type){
    if(type=="oid" || type=="asn1-oid") return "high";
    if(type=="asn1-tag" || type=="der") return "med";
    return "low";
}
std::string CryptoScanner::evidenceLabelForByteType(const std::string& type){
    if(type=="oid" || type=="asn1-oid") return "oid";
    return "bytes";
}

static inline int b64v(int c){
    if(c>='A'&&c<='Z') return c-'A';
    if(c>='a'&&c<='z') return c-'a'+26;
    if(c>='0'&&c<='9') return c-'0'+52;
    if(c=='+') return 62;
    if(c=='/') return 63;
    return -1;
}

std::vector<unsigned char> CryptoScanner::b64decode(const std::string& s){
    std::vector<unsigned char> out; out.reserve(s.size()*3/4);
    int val=0, valb=-8;
    for(unsigned char c: s){
        if(c=='=' || c=='\r' || c=='\n') break;
        int d = b64v(c);
        if(d<0) continue;
        val = (val<<6) | d; valb += 6;
        if(valb>=0){ out.push_back(char((val>>valb)&0xFF)); valb-=8; }
    }
    return out;
}

bool CryptoScanner::isPemText(const std::string& t){
    return t.find("-----BEGIN ") != std::string::npos;
}

std::vector<std::vector<unsigned char>> CryptoScanner::pemDecodeAll(const std::string& text){
    std::vector<std::vector<unsigned char>> der_list;
    size_t p=0;
    while(true){
        size_t s = text.find("-----BEGIN ", p);
        if(s==std::string::npos) break;
        size_t e = text.find("-----END ", s+11);
        if(e==std::string::npos) break;
        size_t nl = text.find('\n', s);
        size_t nl_end = text.find('\n', e);
        if(nl==std::string::npos || nl_end==std::string::npos){ p = e+8; continue; }
        std::string b64 = text.substr(nl+1, e - (nl+1));
        std::string clean; clean.reserve(b64.size());
        for(char ch: b64){ if(ch!='\r' && ch!='\n' && ch!=' ' && ch!='\t') clean.push_back(ch); }
        auto der = b64decode(clean);
        if(!der.empty()) der_list.push_back(std::move(der));
        p = e + 8;
    }
    return der_list;
}

CryptoScanner::CryptoScanner(){
    auto LR = pattern_loader::loadFromJson();
    if(!LR.error.empty()){
        std::cerr << "[CryptoScanner] Warning: failed to load patterns.json: " << LR.error << "\n";
    }
    patterns        = LR.regexPatterns;
    oidBytePatterns = LR.bytePatterns;
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
        auto ast = analyzers::JavaASTScanner::scanSource(filePath, code);
        out.insert(out.end(), ast.begin(), ast.end());
    } else if(ext==".py"){
        auto ast = analyzers::PythonASTScanner::scanFile(filePath);
        out.insert(out.end(), ast.begin(), ast.end());
    } else if(ext==".c" || ext==".cc" || ext==".cpp" || ext==".cxx" || ext==".h" || ext==".hpp" || ext==".hh"){
        auto ast = analyzers::CppASTScanner::scanFile(filePath);
        out.insert(out.end(), ast.begin(), ast.end());
    }

    auto v = scanBinaryFileHeaderLimited(filePath, 64u * 1024u * 1024u);
    out.insert(out.end(), v.begin(), v.end());
    return out;
}

std::vector<Detection> CryptoScanner::scanPathRecursive(const std::string& rootPath){
    std::vector<Detection> all; std::error_code ec;
    if(fs::is_regular_file(rootPath, ec)){
        auto v = scanFileDetailed(rootPath);
        all.insert(all.end(), v.begin(), v.end());
        return all;
    }
    if(!fs::is_directory(rootPath, ec)){
        std::cerr<<"[CryptoScanner] Not a file or directory: "<<rootPath<<"\n";
        return all;
    }
    for(fs::recursive_directory_iterator it(rootPath, fs::directory_options::skip_permission_denied, ec), end; it!=end; ++it){
        const auto& de=*it; if(!de.is_regular_file(ec)) continue;
        try{
            auto v=scanFileDetailed(de.path().string());
            all.insert(all.end(),v.begin(),v.end());
        }catch(...){}
    }
    return all;
}

bool CryptoScanner::isLikelyPem(const std::string& path){
    std::string t;
    if(!readTextFile(path, t)) return false;
    return isPemText(t);
}

std::vector<Detection> CryptoScanner::scanCertOrKeyFileDetailed(const std::string& filePath){
    std::vector<Detection> out;

    std::string text;
    std::vector<unsigned char> whole;
    bool isPem = false;

    if(readTextFile(filePath, text) && isPemText(text)) {
        isPem = true;
    } else {
        readAllBytes(filePath, whole);
    }

    std::vector<std::vector<unsigned char>> ders;
    if(isPem) {
        ders = pemDecodeAll(text);
        if(ders.empty()){
            if(whole.empty()) readAllBytes(filePath, whole);
            if(!whole.empty()) ders.push_back(whole);
        }
    } else {
        if(!whole.empty()) ders.push_back(whole);
    }

    std::unordered_map<std::string,std::string> byteType;
    for(const auto& bp: oidBytePatterns) byteType[bp.name] = bp.type;

    auto collect = [&](const std::string& disp, const auto& data){
        auto strings     = FileScanner::extractAsciiStrings(data);
        auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches  = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

        for(const auto& alg: textMatches){
            for(const auto& e: alg.second){
                out.push_back({ disp, e.second, alg.first, e.first,
                    evidenceTypeForTextPattern(alg.first),
                    severityForTextPattern(alg.first, e.first) });
            }
        }
        for(const auto& alg: oidMatches){
            const std::string et = byteType.count(alg.first)? byteType[alg.first] : std::string();
            const std::string evType = evidenceLabelForByteType(et);
            const std::string sev    = severityForByteType(et);
            for(const auto& e: alg.second){
                out.push_back({ disp, e.second, alg.first, e.first, evType, sev });
            }
        }
    };

    if(ders.empty()){
        if(!whole.empty()) collect(filePath, whole);
    } else {
        for(size_t i=0;i<ders.size();++i){
            std::string name = filePath;
            if(ders.size()>1) name += std::string("::block#") + std::to_string(i+1);
            collect(name, ders[i]);
        }
    }
    return out;
}

std::vector<Detection> CryptoScanner::scanBinaryFileHeaderLimited(const std::string& filePath, std::size_t maxBytes){
    std::vector<Detection> results;
    std::ifstream in(filePath, std::ios::binary);
    if(!in) return results;
    std::vector<unsigned char> data;
    std::size_t reserve = std::min<std::size_t>((std::size_t)getFileSizeSafe(filePath), maxBytes);
    data.resize(reserve);
    in.read((char*)data.data(), data.size());
    data.resize((size_t)in.gcount());

    auto strings     = FileScanner::extractAsciiStrings(data);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches  = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

    std::unordered_map<std::string,std::string> byteType;
    for(const auto& bp: oidBytePatterns) byteType[bp.name] = bp.type;

    auto collect = [&](const auto& matches, bool isText){
        for(const auto& alg: matches){
            for(const auto& e: alg.second){
                const std::string evType = isText ? evidenceTypeForTextPattern(alg.first)
                                                  : evidenceLabelForByteType(byteType.count(alg.first)? byteType[alg.first] : "");
                const std::string sev    = isText ? severityForTextPattern(alg.first, e.first)
                                                  : severityForByteType(byteType.count(alg.first)? byteType[alg.first] : "");
                results.push_back({ filePath, e.second, alg.first, e.first, evType, sev });
            }
        }
    };
    collect(textMatches, true);
    collect(oidMatches,  false);

    return results;
}

std::vector<Detection> CryptoScanner::scanClassFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    std::vector<unsigned char> buf; readAllBytes(filePath, buf);
    if(buf.empty()) return out;

    auto bc = analyzers::JavaBytecodeScanner::scanClassBytes(filePath, buf);
    out.insert(out.end(), bc.begin(), bc.end());

    auto strings     = FileScanner::extractAsciiStrings(buf);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches  = FileScanner::scanBytesWithOffsets(buf, oidBytePatterns);

    std::unordered_map<std::string,std::string> byteType;
    for(const auto& bp: oidBytePatterns) byteType[bp.name] = bp.type;

    auto collect = [&](const auto& matches, bool isText){
        for(const auto& alg: matches){
            for(const auto& e: alg.second){
                const std::string evType = isText ? evidenceTypeForTextPattern(alg.first)
                                                  : evidenceLabelForByteType(byteType.count(alg.first)? byteType[alg.first] : "");
                const std::string sev    = isText ? severityForTextPattern(alg.first, e.first)
                                                  : severityForByteType(byteType.count(alg.first)? byteType[alg.first] : "");
                out.push_back({ filePath, e.second, alg.first, e.first, evType, sev });
            }
        }
    };
    collect(textMatches, true);
    collect(oidMatches,  false);

    return out;
}

std::vector<Detection> CryptoScanner::scanJarFileDetailed(const std::string& filePath){
#ifdef USE_MINIZ
    return scanJarViaMiniZ(filePath);
#else
    return scanBinaryFileHeaderLimited(filePath, 64u * 1024u * 1024u);
#endif
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

        auto strings     = FileScanner::extractAsciiStrings(data);
        auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches  = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

        auto collect = [&](const auto& matches, bool isText){
            for(const auto& alg: matches){
                for(const auto& e: alg.second){
                    const std::string evType = isText ? evidenceTypeForTextPattern(alg.first)
                                                      : evidenceLabelForByteType(byteType.count(alg.first)? byteType[alg.first] : "");
                    const std::string sev    = isText ? severityForTextPattern(alg.first, e.first)
                                                      : severityForByteType(byteType.count(alg.first)? byteType[alg.first] : "");
                    results.push_back({ display, e.second, alg.first, e.first, evType, sev });
                }
            }
        };
        collect(textMatches, true);
        collect(oidMatches,  false);

        if(ends_with(entry, ".class")){
            auto bc = analyzers::JavaBytecodeScanner::scanClassBytes(display, data);
            results.insert(results.end(), bc.begin(), bc.end());
        }
        if(ends_with(entry, ".java")){
            std::string src((const char*)data.data(), data.size());
            auto ast = analyzers::JavaASTScanner::scanSource(display, src);
            results.insert(results.end(), ast.begin(), ast.end());
        } else if(ends_with(entry, ".py")){
            // not likely, but just in case
        }
    }

    mz_zip_reader_end(&zip);
    return results;
#endif
}
