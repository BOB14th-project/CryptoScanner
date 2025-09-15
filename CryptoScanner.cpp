#include "CryptoScanner.h"
#include "PatternLoader.h"
#include "JavaBytecodeScanner.h"
#include "JavaASTScanner.h"
#include "PythonASTScanner.h"
#include "CppASTScanner.h"
#include "ASTSymbol.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef USE_MINIZ
#include "third_party/miniz/miniz.h"
#endif

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

namespace fs = std::filesystem;

static inline std::string toLowerStr(const std::string& s){
    std::string t; t.reserve(s.size());
    for(unsigned char c: s) t.push_back((char)std::tolower(c));
    return t;
}

static inline bool ends_with(const std::string& s, const std::string& suf){
    if(s.size() < suf.size()) return false;
    return std::equal(suf.rbegin(), suf.rend(), s.rbegin());
}

static std::string lowercaseExtCached(const std::string& p){
    auto pos = p.find_last_of('.');
    if(pos == std::string::npos) return std::string();
    std::string e = p.substr(pos);
    for(char& c: e) c = (char)std::tolower((unsigned char)c);
    return e;
}

static bool globMatches(const std::string& path, const std::vector<std::string>& globs){
    if(globs.empty()) return false;
    for(const auto& g: globs){
        std::string r; r.reserve(g.size()*2);
        for(char c: g){
            if(c=='*') r += ".*";
            else if(c=='?') r += ".";
            else if(std::isalnum((unsigned char)c) || c=='/' || c=='_' || c=='-' || c=='.') r.push_back(c);
            else { r.push_back('\\'); r.push_back(c); }
        }
        try{
            if(std::regex_search(path, std::regex(r))) return true;
        }catch(...){}
    }
    return false;
}

static inline bool isVersionedSoName(const std::string& fileName){
    if(ends_with(fileName, ".so")) return true;
    if(fileName.find(".so.") != std::string::npos) return true;
    return false;
}

static inline bool isJarLikeExt(const std::string& ext){
    static const std::unordered_set<std::string> exts = {".jar",".zip",".war",".ear",".apk",".aar",".jmod"};
    return exts.count(ext) > 0;
}

static bool quickIsExecutableByHeader(const std::string& path){
    std::array<unsigned char, 4> h{};
    std::ifstream in(path, std::ios::binary);
    if(!in) return false;
    in.read((char*)h.data(), 4);
    if(in.gcount() < 4) return false;
    if(h[0]==0x7F && h[1]=='E' && h[2]=='L' && h[3]=='F') return true;
    if(h[0]=='M' && h[1]=='Z') return true;
    return false;
}

static bool isCurveParamNName(const std::string& name){
    return name.find(" n)") != std::string::npos;
}

static std::string curveFamily(const std::string& alg){
    std::string s = toLowerStr(alg);
    if(s.find("secp256")!=std::string::npos) return "secp256";
    if(s.find("secp384")!=std::string::npos) return "secp384";
    if(s.find("secp521")!=std::string::npos) return "secp521";
    if(s.find("brainpoolp256")!=std::string::npos) return "brainpoolp256";
    if(s.find("brainpoolp384")!=std::string::npos) return "brainpoolp384";
    if(s.find("brainpoolp512")!=std::string::npos) return "brainpoolp512";
    if(s.find("prime256v1")!=std::string::npos) return "prime256v1";
    return alg;
}

static inline bool nearAny(const std::vector<std::size_t>& anchors, std::size_t off, std::size_t win){
    if(anchors.empty()) return false;
    auto it = std::lower_bound(anchors.begin(), anchors.end(), off);
    if(it!=anchors.end() && *it >= off && *it - off <= win) return true;
    if(it!=anchors.begin()){
        --it;
        if(off >= *it && off - *it <= win) return true;
    }
    return false;
}

std::string CryptoScanner::lowercaseExt(const std::string& p){ return lowercaseExtCached(p); }

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
    out.assign(std::istreambuf_iterator<char>(in), {});
    return true;
}

bool CryptoScanner::isCertOrKeyExt(const std::string& ext){
    static const std::unordered_set<std::string> exts = {
        ".cer",".crt",".der",".pem",".p7b",".p7c",".pfx",".p12",".key",".pub",".csr"
    };
    return exts.count(ext) > 0;
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
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<unsigned char> out;
    out.reserve(s.size()*3/4+3);
    unsigned int val=0, valb= -8;
    for(unsigned char c: s){
        int d = T[c];
        if(d==-1) continue;
        val = (val<<6) + (unsigned int)d;
        valb += 6;
        if(valb>=0){
            out.push_back((unsigned char)((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

std::vector<std::vector<unsigned char>> CryptoScanner::pemDecodeAll(const std::string& text){
    std::vector<std::vector<unsigned char>> all;
    std::istringstream is(text);
    std::string line;
    bool inBlock=false;
    std::string b64;
    while(std::getline(is, line)){
        if(line.rfind("-----BEGIN ",0)==0){ inBlock=true; b64.clear(); continue; }
        if(line.rfind("-----END ",0)==0){ inBlock=false; auto v=b64decode(b64); if(!v.empty()) all.push_back(std::move(v)); continue; }
        if(inBlock){
            for(char c: line){
                if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')
                    b64.push_back(c);
            }
        }
    }
    return all;
}

CryptoScanner::CryptoScanner(){
    auto LR = pattern_loader::loadFromJson();
    if(!LR.error.empty()){
        std::cerr << "[CryptoScanner] Warning: failed to load patterns.json: " << LR.error << "\n";
    }
    patterns        = LR.regexPatterns;
    oidBytePatterns = LR.bytePatterns;
    patternsApiOnly.clear();
    patternsApiOnly.reserve(patterns.size());
    for(const auto& ap : patterns){
        std::string et = evidenceTypeForTextPattern(ap.name);
        if(et=="api" || et=="pem" || et=="oid") patternsApiOnly.push_back(ap);
    }
    cancelCb = nullptr;
    activeOpt = ScanOptions();
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

std::string CryptoScanner::severityForByteType(const std::string& type){
    if(type=="oid" || type=="asn1-oid") return "high";
    if(type=="curve_param" || type=="prime") return "med";
    return "low";
}

std::string CryptoScanner::evidenceTypeForTextPattern(const std::string& algName){
    std::string s = toLowerStr(algName);
    if(s.find("oid")!=std::string::npos) return "oid";
    if(s.find("pem")!=std::string::npos) return "pem";
    if(s.find("api")!=std::string::npos) return "api";
    return "text";
}

std::string CryptoScanner::evidenceLabelForByteType(const std::string& type){
    if(type=="oid" || type=="asn1-oid") return "oid";
    if(type=="curve_param") return "curve_param";
    if(type=="prime") return "prime";
    return "byte";
}

std::vector<Detection> CryptoScanner::scanClassFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    std::vector<unsigned char> data;
    if(!readAllBytes(filePath, data)) return out;
    auto bc = analyzers::JavaBytecodeScanner::scanClassBytes(filePath, data);
    out.insert(out.end(), bc.begin(), bc.end());
    return out;
}

std::vector<Detection> CryptoScanner::scanJarViaMiniZ(const std::string& filePath){
    std::vector<Detection> results;
#ifndef USE_MINIZ
    (void)filePath;
    return results;
#else
    if(!activeOpt.deepJar) return results;
    if(cancelCb && cancelCb()) return results;

    std::size_t maxEntryJava = activeOpt.jarMaxEntryJava;
    std::size_t maxEntryClass = activeOpt.jarMaxEntryClass;
    std::size_t maxTotalUncomp = activeOpt.jarMaxTotalUncomp;
    std::size_t maxEntries = activeOpt.jarMaxEntries;

    mz_zip_archive zip; std::memset(&zip, 0, sizeof(zip));
    if(!mz_zip_reader_init_file(&zip, filePath.c_str(), 0)){
        return results;
    }
    const int n = (int)mz_zip_reader_get_num_files(&zip);
    std::size_t totalUncomp = 0;
    std::size_t entriesSeen = 0;

    for(int i=0; i<n; ++i){
        if(cancelCb && cancelCb()) break;

        mz_zip_archive_file_stat st;
        if(!mz_zip_reader_file_stat(&zip, i, &st)) continue;
        if(st.m_is_directory) continue;

        if(maxEntries && entriesSeen >= maxEntries) break;

        std::string entry = st.m_filename ? st.m_filename : "";
        std::string ext = lowercaseExt(entry);

        if(!(ext==".class" || ext==".java")) continue;

        if(ext==".java" && maxEntryJava && st.m_uncomp_size > maxEntryJava) continue;
        if(ext==".class" && maxEntryClass && st.m_uncomp_size > maxEntryClass) continue;

        if(maxTotalUncomp && totalUncomp + st.m_uncomp_size > maxTotalUncomp) break;

        size_t out_size = 0;
        void* p = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if(!p) continue;
        totalUncomp += out_size;
        entriesSeen++;

        std::vector<unsigned char> data((unsigned char*)p, (unsigned char*)p + out_size);
        mz_free(p);

        std::string display = filePath + "::" + entry;

        if(ext==".java"){
            std::string src((const char*)data.data(), data.size());
            auto syms = analyzers::JavaASTScanner::collectSymbols(display, src);
            for(const auto& s: syms){
                if(cancelCb && cancelCb()) { results.clear(); mz_zip_reader_end(&zip); return results; }
                std::vector<std::string> cands;
                cands.push_back(s.callee_full);
                if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
                if(!s.first_arg.empty()) cands.push_back(s.first_arg);
                for(const auto& cand: cands){
                    if(cand.empty()) continue;
                    for(const auto& ap: patterns){
                        try{
                            std::smatch m;
                            if(std::regex_search(cand, m, ap.pattern)){
                                results.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                            }
                        }catch(...){}
                    }
                }
            }
            continue;
        }

        if(ext==".class"){
            auto strings = FileScanner::extractAsciiStrings(data, 4);
            auto strMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
            for(const auto& kv: strMatches){
                for(const auto& m: kv.second){
                    results.push_back({ display, m.second, kv.first, m.first, evidenceTypeForTextPattern(kv.first), severityForTextPattern(kv.first, m.first) });
                }
            }
            auto byteMatchesAll = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);
            std::unordered_map<std::string,std::string> typeByName;
            for(const auto& bp: oidBytePatterns) typeByName[bp.name]=bp.type;
            std::vector<std::size_t> oidAnchors;
            for(const auto& alg : byteMatchesAll){
                const std::string t = typeByName.count(alg.first)? typeByName[alg.first] : std::string();
                if(!(t=="oid" || t=="asn1-oid")) continue;
                for(const auto& e: alg.second) oidAnchors.push_back(e.second);
            }
            std::sort(oidAnchors.begin(), oidAnchors.end());
            oidAnchors.erase(std::unique(oidAnchors.begin(), oidAnchors.end()), oidAnchors.end());
            const std::size_t ctxWin = 2048;
            for(const auto& alg : byteMatchesAll){
                const std::string t = typeByName.count(alg.first)? typeByName[alg.first] : std::string();
                if(t=="curve_param" || t=="prime"){
                    if(isCurveParamNName(alg.first)) continue;
                    for(const auto& e: alg.second){
                        if(!nearAny(oidAnchors, e.second, ctxWin)) continue;
                        results.push_back({ display, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) });
                    }
                } else if(t=="oid" || t=="asn1-oid"){
                    for(const auto& e: alg.second){
                        results.push_back({ display, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) });
                    }
                }
            }
            continue;
        }
    }
    mz_zip_reader_end(&zip);
    return results;
#endif
}

std::vector<Detection> CryptoScanner::scanJarFileDetailed(const std::string& filePath){
    return scanJarViaMiniZ(filePath);
}

std::vector<Detection> CryptoScanner::scanCertOrKeyFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    std::unordered_set<std::string> seen;
    std::vector<unsigned char> buffer;
    if(!readAllBytes(filePath, buffer)) return out;
    BIO* bio = BIO_new_mem_buf(buffer.data(), (int)buffer.size());
    if(!bio) return out;
    auto mkKey = [&](const Detection& d){
        std::ostringstream os; os<<d.filePath<<"|"<<d.offset<<"|"<<d.algorithm<<"|"<<d.evidenceType;
        return os.str();
    };
    auto push = [&](const std::string& alg, const std::string& ev, const std::string& sev){
        Detection d{ filePath, 0, alg, ev, "x509", sev };
        std::string k = mkKey(d);
        if(seen.insert(k).second) out.push_back(std::move(d));
    };
    bool parsed_any = false;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(!cert){
        BIO_reset(bio);
        cert = d2i_X509_bio(bio, NULL);
    }
    if(cert){
        parsed_any = true;
        const ASN1_BIT_STRING* sig = nullptr;
        const X509_ALGOR* sig_alg = nullptr;
        X509_get0_signature(&sig, &sig_alg, cert);
        if(sig_alg && sig_alg->algorithm){
            char name_buf[256]; char oid_buf[256];
            OBJ_obj2txt(name_buf, sizeof(name_buf), sig_alg->algorithm, 0);
            OBJ_obj2txt(oid_buf, sizeof(oid_buf), sig_alg->algorithm, 1);
            std::string alg_name_str(name_buf);
            std::string sev = (alg_name_str.find("sha1")!=std::string::npos || alg_name_str.find("md5")!=std::string::npos) ? "high" : "med";
            push(alg_name_str, std::string(oid_buf), sev);
        }
        EVP_PKEY* pkey = X509_get_pubkey(cert);
        if(pkey){
            int nid = EVP_PKEY_base_id(pkey);
            const char* sn = OBJ_nid2sn(nid);
            const ASN1_OBJECT* obj = OBJ_nid2obj(nid);
            if(sn && obj){
                char oid_buf[256];
                OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
                push(std::string(sn), std::string(oid_buf), "high");
            }
            EVP_PKEY_free(pkey);
        }
        X509_free(cert);
    }
    if(!parsed_any){
        BIO_reset(bio);
        X509_REQ* req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
        if(!req){
            BIO_reset(bio);
            req = d2i_X509_REQ_bio(bio, NULL);
        }
        if(req){
            parsed_any = true;
            const ASN1_BIT_STRING* rsig = nullptr;
            const X509_ALGOR* ralg = nullptr;
            X509_REQ_get0_signature(req, &rsig, &ralg);
            if(ralg && ralg->algorithm){
                char oid_buf[256];
                OBJ_obj2txt(oid_buf, sizeof(oid_buf), ralg->algorithm, 1);
                push("csr.sig_alg", std::string(oid_buf), "med");
            }
            EVP_PKEY* rpk = X509_REQ_get0_pubkey(req);
            if(rpk){
                int nid = EVP_PKEY_base_id(rpk);
                const char* sn = OBJ_nid2sn(nid);
                const ASN1_OBJECT* obj = OBJ_nid2obj(nid);
                if(sn && obj){
                    char oid_buf[256];
                    OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
                    push(std::string(sn), std::string(oid_buf), "high");
                }
            }
            X509_REQ_free(req);
        }
    }
    BIO_free(bio);
    if(!parsed_any){
        auto byteMatches = FileScanner::scanBytesWithOffsets(buffer, oidBytePatterns);
        std::unordered_map<std::string,std::string> typeByName;
        for(const auto& bp: oidBytePatterns) typeByName[bp.name]=bp.type;
        for(const auto& alg: byteMatches){
            const std::string t = typeByName.count(alg.first)? typeByName[alg.first] : std::string();
            if(!(t=="oid" || t=="asn1-oid")) continue;
            for(const auto& e : alg.second){
                Detection d{ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) };
                out.push_back(std::move(d));
            }
        }
    }
    return out;
}

std::vector<Detection> CryptoScanner::scanBinaryWholeFile(const std::string& filePath){
    std::vector<Detection> results;
    std::vector<unsigned char> buffer;
    if(!readAllBytes(filePath, buffer)) return results;

    const std::string ext = lowercaseExt(filePath);
    bool isBin = quickIsExecutableByHeader(filePath) || ext==".so" || ext==".dll" || ext==".exe" || ext==".a" || ext==".ld";

    auto strings = FileScanner::extractAsciiStrings(buffer, 4);
    auto strMatches = FileScanner::scanStringsWithOffsets(strings, patterns);

    for(const auto& kv: strMatches){
        const std::string& alg = kv.first;
        for(const auto& m: kv.second){
            Detection d{ filePath, m.second, alg, m.first, evidenceTypeForTextPattern(alg), severityForTextPattern(alg, m.first) };
            results.push_back(std::move(d));
        }
    }

    auto byteMatchesAll = FileScanner::scanBytesWithOffsets(buffer, oidBytePatterns);
    std::unordered_map<std::string,std::string> typeByName;
    for(const auto& bp: oidBytePatterns) typeByName[bp.name]=bp.type;

    std::vector<std::size_t> oidAnchors;
    for(const auto& alg : byteMatchesAll){
        const std::string t = typeByName.count(alg.first)? typeByName[alg.first] : std::string();
        if(!(t=="oid" || t=="asn1-oid")) continue;
        for(const auto& e: alg.second) oidAnchors.push_back(e.second);
    }
    std::sort(oidAnchors.begin(), oidAnchors.end());
    oidAnchors.erase(std::unique(oidAnchors.begin(), oidAnchors.end()), oidAnchors.end());

    const std::size_t ctxWin = 2048;
    for(const auto& alg : byteMatchesAll){
        const std::string t = typeByName.count(alg.first)? typeByName[alg.first] : std::string();
        if(t=="curve_param" || t=="prime"){
            if(isCurveParamNName(alg.first)) continue;
            for(const auto& e: alg.second){
                if(!nearAny(oidAnchors, e.second, ctxWin)) continue;
                Detection d{ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) };
                results.push_back(std::move(d));
            }
        } else if(t=="oid" || t=="asn1-oid"){
            for(const auto& e: alg.second){
                Detection d{ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) };
                results.push_back(std::move(d));
            }
        }
    }

    if(isBin){
        std::unordered_map<std::string, Detection> keepAlgoOnce;
        std::unordered_map<std::string, Detection> keepCurveFamilyOnce;
        std::vector<Detection> filtered;
        for(const auto& d: results){
            std::string lowAlg = toLowerStr(d.algorithm);
            if(d.evidenceType=="oid" && (lowAlg.find("dh")!=std::string::npos || lowAlg.find("esdh")!=std::string::npos)){
                if(keepAlgoOnce.find(d.algorithm)==keepAlgoOnce.end()) keepAlgoOnce[d.algorithm]=d;
                continue;
            }
            if(d.evidenceType=="curve_param"){
                std::string fam = curveFamily(d.algorithm);
                if(keepCurveFamilyOnce.find(fam)==keepCurveFamilyOnce.end()) keepCurveFamilyOnce[fam]=d;
                continue;
            }
            filtered.push_back(d);
        }
        for(auto& kv: keepAlgoOnce) filtered.push_back(kv.second);
        for(auto& kv: keepCurveFamilyOnce) filtered.push_back(kv.second);
        results.swap(filtered);
    }

    return results;
}

std::vector<Detection> CryptoScanner::scanFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    if(cancelCb && cancelCb()) return out;
    const std::string ext = lowercaseExt(filePath);
    std::error_code ec;

    if(ext==".jar" || ext==".zip" || ext==".war" || ext==".ear" || ext==".apk" || ext==".aar" || ext==".jmod"){
        auto v = scanJarFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }

    if(isCertOrKeyExt(ext) || isLikelyPem(filePath)){
        auto v = scanCertOrKeyFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }

    if(ext==".java"){
        std::string src;
        if(readTextFile(filePath, src)){
            auto syms = analyzers::JavaASTScanner::collectSymbols(filePath, src);
            for(const auto& s: syms){
                std::vector<std::string> cands{ s.callee_full };
                if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
                if(!s.first_arg.empty()) cands.push_back(s.first_arg);
                for(const auto& cand: cands){
                    if(cand.empty()) continue;
                    for(const auto& ap: patterns){
                        try{
                            std::smatch m;
                            if(std::regex_search(cand, m, ap.pattern)){
                                out.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                            }
                        }catch(...){}
                    }
                }
            }
            return out;
        }
    }

    if(ext==".py"){
        auto syms = analyzers::PythonASTScanner::collectSymbols(filePath);
        for(const auto& s: syms){
            std::vector<std::string> cands{ s.callee_full };
            if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if(!s.first_arg.empty()) cands.push_back(s.first_arg);
            for(const auto& cand: cands){
                if(cand.empty()) continue;
                for(const auto& ap: patterns){
                    try{
                        std::smatch m;
                        if(std::regex_search(cand, m, ap.pattern)){
                            out.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                        }
                    }catch(...){}
                }
            }
        }
        return out;
    }

    if(ext==".c" || ext==".cc" || ext==".cpp" || ext==".cxx" || ext==".h" || ext==".hpp" || ext==".hh"){
        auto syms = analyzers::CppASTScanner::collectSymbols(filePath);
        for(const auto& s: syms){
            std::vector<std::string> cands{ s.callee_full };
            if(s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if(!s.first_arg.empty()) cands.push_back(s.first_arg);
            for(const auto& cand: cands){
                if(cand.empty()) continue;
                for(const auto& ap: patterns){
                    try{
                        std::smatch m;
                        if(std::regex_search(cand, m, ap.pattern)){
                            out.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                        }
                    }catch(...){}
                }
            }
        }
        return out;
    }

    auto v = scanBinaryWholeFile(filePath);
    out.insert(out.end(), v.begin(), v.end());
    return out;
}

static bool pathStartsWith(const std::string& s, const std::string& prefix){
    return s.rfind(prefix, 0) == 0;
}

void CryptoScanner::scanPathLikeAntivirus(
    const std::string& rootPath,
    const ScanOptions& opt,
    const std::function<void(const Detection&)>& onDetect,
    const std::function<void(const std::string&, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>& onProgress,
    const std::function<bool()>& isCancelled
){
    cancelCb = isCancelled;
    activeOpt = opt;

    if(rootPath == "/" && activeOpt.profile == ScanProfile::Default){
        activeOpt.profile = ScanProfile::InstitutionStrict;
        activeOpt.excludeSystemDirs = true;
        activeOpt.excludeDevDirs = true;
        activeOpt.jarMaxEntryJava = 1024*1024;
        activeOpt.jarMaxEntryClass = 512*1024;
        activeOpt.jarMaxTotalUncomp = 200*1024*1024;
        activeOpt.jarMaxEntries = 5000;
    }

    static const std::vector<std::string> kInstitutionExcludeGlobs = {
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
        "/usr/local/include/*"
    };

    auto shouldSkipByProfile = [&](const fs::path& p)->bool{
        std::string s = p.string();
        if(s == "/") return false;
        if(activeOpt.profile == ScanProfile::InstitutionStrict || activeOpt.excludeSystemDirs){
            if(pathStartsWith(s, "/proc")) return true;
            if(pathStartsWith(s, "/sys")) return true;
            if(pathStartsWith(s, "/dev")) return true;
            if(pathStartsWith(s, "/run")) return true;
            if(pathStartsWith(s, "/snap")) return true;
            if(pathStartsWith(s, "/var/lib/docker")) return true;
            if(pathStartsWith(s, "/var/lib/flatpak")) return true;
            if(pathStartsWith(s, "/var/cache")) return true;
            if(pathStartsWith(s, "/var/log")) return true;
            if(pathStartsWith(s, "/tmp")) return true;
            if(pathStartsWith(s, "/var/tmp")) return true;
            if(pathStartsWith(s, "/lost+found")) return true;
            if(pathStartsWith(s, "/usr/lib/aarch64-linux-gnu")) return true;
            if(pathStartsWith(s, "/usr/lib/x86_64-linux-gnu")) return true;
            if(pathStartsWith(s, "/lib/aarch64-linux-gnu")) return true;
            if(pathStartsWith(s, "/lib/x86_64-linux-gnu")) return true;
            if(pathStartsWith(s, "/usr/lib/gcc")) return true;
            if(pathStartsWith(s, "/usr/lib/python3/dist-packages")) return true;
            if(pathStartsWith(s, "/usr/lib/node_modules")) return true;
            if(pathStartsWith(s, "/usr/i686-w64-mingw32")) return true;
            if(pathStartsWith(s, "/usr/x86_64-w64-mingw32")) return true;
        }
        if(activeOpt.profile == ScanProfile::InstitutionStrict || activeOpt.excludeDevDirs){
            if(pathStartsWith(s, "/usr/include")) return true;
            if(pathStartsWith(s, "/usr/share/doc")) return true;
            if(pathStartsWith(s, "/usr/share/locale")) return true;
            if(pathStartsWith(s, "/usr/share/man")) return true;
            if(pathStartsWith(s, "/usr/share/icons")) return true;
            if(pathStartsWith(s, "/usr/src")) return true;
            if(pathStartsWith(s, "/opt/cuda")) return true;
            if(pathStartsWith(s, "/usr/local/cuda")) return true;
            if(pathStartsWith(s, "/usr/local/share")) return true;
            if(pathStartsWith(s, "/usr/local/include")) return true;
        }
        if(activeOpt.profile == ScanProfile::InstitutionStrict){
            if(globMatches(s, kInstitutionExcludeGlobs)) return true;
        }
        if(!activeOpt.excludeGlobs.empty()){
            if(globMatches(s, activeOpt.excludeGlobs)) return true;
        }
        return false;
    };

    std::vector<std::string> files;
    auto pushCandidate = [&](const fs::path& p){
        std::string s = p.string();
        const std::string ext = lowercaseExt(s);
        bool isCandidate = false;
        if(isCertOrKeyExt(ext) || isLikelyPem(s)) isCandidate = true;
        else if(ext==".c" || ext==".cc" || ext==".cpp" || ext==".cxx" || ext==".h" || ext==".hpp" || ext==".hh") isCandidate = true;
        else if(ext==".py" || ext==".java") isCandidate = true;
        else if(ext==".class") isCandidate = true;
        else if(isJarLikeExt(ext)) isCandidate = true;
        else if(isVersionedSoName(s) || ext==".so" || ext==".dll" || ext==".exe" || ext==".a" || ext==".ld" || quickIsExecutableByHeader(s)) isCandidate = true;
        if(!isCandidate) return;
        if(!activeOpt.includeGlobs.empty()){
            if(!globMatches(s, activeOpt.includeGlobs)) return;
        }
        if(shouldSkipByProfile(p)) return;
        if(globMatches(s, activeOpt.excludeGlobs)) return;
        files.push_back(s);
    };

    std::vector<fs::path> roots;
    if(activeOpt.profile==ScanProfile::InstitutionStrict && rootPath=="/"){
        std::vector<std::string> preferred = {"/home","/root","/etc","/opt","/srv","/var/www","/var/lib/tomcat","/mnt","/media","/data","/usr/local"};
        for(const auto& r: preferred){ std::error_code ec; if(fs::exists(r, ec)) roots.emplace_back(r); }
        if(roots.empty()) roots.push_back("/");
    } else {
        roots.push_back(rootPath);
    }

    std::error_code ec;
    auto addFromRoot = [&](const fs::path& r){
        if(fs::is_regular_file(r, ec)){ pushCandidate(r); return; }
        if(!fs::is_directory(r, ec)) return;
        if(activeOpt.recurse){
            for(fs::recursive_directory_iterator it(r, fs::directory_options::skip_permission_denied, ec), end; it!=end; ++it){
                const auto& de = *it;
                if(isCancelled && isCancelled()) break;
                if(de.is_directory(ec)){
                    if(shouldSkipByProfile(de.path())) it.disable_recursion_pending();
                    continue;
                }
                if(de.is_symlink(ec)) continue;
                if(!de.is_regular_file(ec)) continue;
                if(shouldSkipByProfile(de.path().parent_path())) continue;
                pushCandidate(de.path());
            }
        } else {
            for(fs::directory_iterator it(r, ec), end; it!=end; ++it){
                const auto& de = *it;
                if(!de.is_regular_file(ec)) continue;
                pushCandidate(de.path());
            }
        }
    };

    for(const auto& r: roots) addFromRoot(r);

    std::uint64_t totalFiles = files.size();
    std::uint64_t totalBytes = 0;
    for(const auto& f: files) totalBytes += (std::uint64_t)getFileSizeSafe(f);

    std::atomic<std::uint64_t> filesDone{0};
    std::atomic<std::uint64_t> bytesDone{0};
    std::mutex cbMutex;
    const unsigned int th = std::min(32u, std::max(2u, std::thread::hardware_concurrency()*2));
    std::atomic<std::size_t> idx{0};

    auto worker = [&](){
        while(true){
            if(isCancelled && isCancelled()) break;
            std::size_t i = idx.fetch_add(1);
            if(i>=files.size()) break;
            if(isCancelled && isCancelled()) break;
            const std::string path = files[i];
            const std::uint64_t sz = (std::uint64_t)getFileSizeSafe(path);
            std::vector<Detection> dets;
            try{
                dets = scanFileDetailed(path);
            }catch(...){
                dets.clear();
            }
            {
                std::lock_guard<std::mutex> lk(cbMutex);
                for(const auto& d: dets) onDetect(d);
                onProgress(path, filesDone.load()+1, totalFiles, bytesDone.load()+sz, totalBytes);
            }
            filesDone.fetch_add(1);
            bytesDone.fetch_add(sz);
        }
    };

    std::vector<std::thread> pool;
    for(unsigned int t=0;t<th;t++) pool.emplace_back(worker);
    for(auto& t: pool) t.join();

    cancelCb = nullptr;
}
