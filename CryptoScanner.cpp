#include "CryptoScanner.h"
#include "PatternLoader.h"
#include "JavaBytecodeScanner.h"
#include "JavaASTScanner.h"
#include "PythonASTScanner.h"
#include "CppASTScanner.h"
#include "ASTSymbol.h"
#include "FileScanner.h"
#include "DynLinkParser.h"

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

static inline std::string toLowerStr(const std::string& s) {
    std::string t;
    t.reserve(s.size());
    for (unsigned char c : s) t.push_back((char)std::tolower(c));
    return t;
}

static inline bool ends_with(const std::string& s, const std::string& suf) {
    if (s.size() < suf.size()) return false;
    return std::equal(suf.rbegin(), suf.rend(), s.rbegin());
}

static std::string lowercaseExtCached(const std::string& p) {
    auto pos = p.find_last_of('.');
    if (pos == std::string::npos) return std::string();
    std::string e = p.substr(pos);
    for (char& c : e) c = (char)std::tolower((unsigned char)c);
    return e;
}

static bool globMatches(const std::string& path, const std::vector<std::string>& globs) {
    if (globs.empty()) return false;
    for (const auto& g : globs) {
        std::string r;
        r.reserve(g.size() * 2);
        for (char c : g) {
            if (c == '*') r += ".*";
            else if (c == '?') r += ".";
            else if (std::isalnum((unsigned char)c) || c == '/' || c == '_' || c == '-' || c == '.') r.push_back(c);
            else { r.push_back('\\'); r.push_back(c); }
        }
        try { if (std::regex_search(path, std::regex(r))) return true; } catch (...) {}
    }
    return false;
}

static inline bool isVersionedSoName(const std::string& fileName) {
    if (ends_with(fileName, ".so")) return true;
    if (fileName.find(".so.") != std::string::npos) return true;
    return false;
}

static inline bool isJarLikeExt(const std::string& ext) {
    static const std::unordered_set<std::string> exts = { ".jar", ".zip", ".war", ".ear", ".apk", ".aar", ".jmod" };
    return exts.count(ext) > 0;
}

static bool quickIsExecutableByHeader(const std::string& path) {
    std::array<unsigned char, 4> h{};
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.read((char*)h.data(), 4);
    if (in.gcount() < 4) return false;
    if (h[0] == 0x7F && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') return true;
    if (h[0] == 'M' && h[1] == 'Z') return true;
    return false;
}

static bool isCurveParamNName(const std::string& name) {
    return name.find(" n)") != std::string::npos;
}

static std::string curveFamily(const std::string& alg) {
    std::string s = toLowerStr(alg);
    if (s.find("secp256") != std::string::npos) return "secp256";
    if (s.find("secp384") != std::string::npos) return "secp384";
    if (s.find("secp521") != std::string::npos) return "secp521";
    if (s.find("brainpoolp256") != std::string::npos) return "brainpoolp256";
    if (s.find("brainpoolp384") != std::string::npos) return "brainpoolp384";
    if (s.find("brainpoolp512") != std::string::npos) return "brainpoolp512";
    if (s.find("prime256v1") != std::string::npos) return "prime256v1";
    return alg;
}

static inline bool isOidType(const std::string& t) {
    return t == "oid" || t == "asn1-oid" || t == "asn1_oid";
}

static inline bool nearAny(const std::vector<std::size_t>& anchors, std::size_t off, std::size_t win) {
    if (anchors.empty()) return false;
    auto it = std::lower_bound(anchors.begin(), anchors.end(), off);
    if (it != anchors.end() && *it >= off && *it - off <= win) return true;
    if (it != anchors.begin()) {
        --it;
        if (off >= *it && off - *it <= win) return true;
    }
    return false;
}

static void postprocessDetections(std::vector<Detection>& results) {
    std::unordered_set<std::string> apiFuncs;
    std::unordered_set<std::string> importLibTokens;
    for (const auto& d : results) {
        if (d.evidenceType == "api") {
            apiFuncs.insert(toLowerStr(d.matchString));
        } else if (d.evidenceType == "import") {
            std::string s = toLowerStr(d.matchString);
            std::string base = s;
            size_t p = base.find_last_of("/\\");
            if (p != std::string::npos) base = base.substr(p + 1);
            if (ends_with(base, ".dll") || ends_with(base, ".so")) {
                size_t dot = base.find_last_of('.');
                if (dot != std::string::npos) base = base.substr(0, dot);
            }
            importLibTokens.insert(base);
        }
    }
    std::vector<Detection> filtered;
    std::unordered_set<std::string> seenKey;
    std::unordered_set<std::string> seenOidAlg;
    std::unordered_set<std::string> seenCurveFam;
    auto key = [&](const Detection& d){
        return d.evidenceType + "|" + d.algorithm + "|" + toLowerStr(d.matchString);
    };
    for (const auto& d : results) {
        if (d.evidenceType == "oid") {
            if (!seenOidAlg.insert(d.algorithm).second) continue;
        } else if (d.evidenceType == "curve_param") {
            std::string fam = curveFamily(d.algorithm);
            if (!seenCurveFam.insert(fam).second) continue;
        } else if (d.evidenceType == "text") {
            std::string m = toLowerStr(d.matchString);
            if (apiFuncs.count(m)) continue;
            bool overshadow = false;
            for (const auto& f : apiFuncs) {
                if (f.find(m) != std::string::npos || m.find(f) != std::string::npos) { overshadow = true; break; }
            }
            if (overshadow) continue;
            if (importLibTokens.count(m)) continue;
        } else if (d.algorithm == "ImportedWeakCrypto") {
            std::string m = toLowerStr(d.matchString);
            if (apiFuncs.count(m)) continue;
        }
        std::string k = key(d);
        if (seenKey.insert(k).second) filtered.push_back(d);
    }
    results.swap(filtered);
}

std::string CryptoScanner::lowercaseExt(const std::string& p) { return lowercaseExtCached(p); }

std::uintmax_t CryptoScanner::getFileSizeSafe(const std::string& path) {
    std::error_code ec;
    auto s = fs::file_size(path, ec);
    if (ec) return 0;
    return s;
}

bool CryptoScanner::readTextFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool CryptoScanner::readAllBytes(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), {});
    return true;
}

bool CryptoScanner::isCertOrKeyExt(const std::string& ext) {
    static const std::unordered_set<std::string> exts = {
        ".cer", ".crt", ".der", ".pem", ".p7b", ".p7c", ".pfx", ".p12", ".key", ".pub", ".csr"
    };
    return exts.count(ext) > 0;
}

static bool isPemLine(const std::string& s) {
    return s.find("-----BEGIN ") != std::string::npos || s.find("-----END ") != std::string::npos;
}

bool CryptoScanner::isPemText(const std::string& text) {
    std::istringstream is(text);
    std::string line;
    int found = 0;
    while (std::getline(is, line)) {
        if (isPemLine(line)) {
            found++;
            if (found >= 2) return true;
        }
    }
    return false;
}

bool CryptoScanner::isLikelyPem(const std::string& path) {
    std::array<char, 4096> buf{};
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.read(buf.data(), (std::streamsize)buf.size());
    std::string s(buf.data(), (size_t)in.gcount());
    return isPemText(s);
}

std::vector<unsigned char> CryptoScanner::b64decode(const std::string& s) {
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() * 3 / 4 + 3);
    unsigned int val = 0, valb = -8;
    for (unsigned char c : s) {
        int d = T[c];
        if (d == -1) continue;
        val = (val << 6) + (unsigned int)d;
        valb += 6;
        if (valb >= 0) {
            out.push_back((unsigned char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::vector<std::vector<unsigned char>> CryptoScanner::pemDecodeAll(const std::string& text) {
    std::vector<std::vector<unsigned char>> all;
    std::istringstream is(text);
    std::string line;
    bool inBlock = false;
    std::string b64;
    while (std::getline(is, line)) {
        if (line.rfind("-----BEGIN ", 0) == 0) { inBlock = true; b64.clear(); continue; }
        if (line.rfind("-----END ", 0) == 0) { inBlock = false; auto v = b64decode(b64); if (!v.empty()) all.push_back(std::move(v)); continue; }
        if (inBlock) {
            for (char c : line) {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') b64.push_back(c);
            }
        }
    }
    return all;
}

CryptoScanner::CryptoScanner() {
    auto LR = pattern_loader::loadFromJson();
    if (!LR.error.empty()) {
        std::cerr << "[CryptoScanner] Warning: failed to load patterns.json: " << LR.error << "\n";
    }
    patterns = LR.regexPatterns;
    oidBytePatterns = LR.bytePatterns;
    patternsApiOnly.clear();
    patternsApiOnly.reserve(patterns.size());
    for (const auto& ap : patterns) {
        std::string et = evidenceTypeForTextPattern(ap.name);
        if (et == "api" || et == "pem" || et == "oid") patternsApiOnly.push_back(ap);
    }
    cancelCb = nullptr;
    activeOpt = ScanOptions();
}

std::string CryptoScanner::severityForTextPattern(const std::string& algName, const std::string& matched) {
    (void)matched;
    if (algName.find("OID dotted") != std::string::npos) return "high";
    if (algName.find("PEM Header") != std::string::npos) return "med";
    if (algName.find("API (OpenSSL)") != std::string::npos
        || algName.find("API (Windows CNG/CAPI)") != std::string::npos
        || algName.find("API (libgcrypt)") != std::string::npos) return "med";
    if (algName.find("MD5") != std::string::npos || algName.find("SHA-1") != std::string::npos) return "med";
    return "low";
}

std::string CryptoScanner::severityForByteType(const std::string& type) {
    if (isOidType(type)) return "high";
    if (type == "curve_param" || type == "prime") return "med";
    return "low";
}

std::string CryptoScanner::evidenceTypeForTextPattern(const std::string& algName) {
    std::string s = toLowerStr(algName);
    if (s.find("oid") != std::string::npos) return "oid";
    if (s.find("pem") != std::string::npos) return "pem";
    if (s.find("api") != std::string::npos) return "api";
    return "text";
}

std::string CryptoScanner::evidenceLabelForByteType(const std::string& type) {
    if (isOidType(type)) return "oid";
    if (type == "curve_param") return "curve_param";
    if (type == "prime") return "prime";
    return "bytes";
}

std::vector<Detection> CryptoScanner::scanCertOrKeyFileDetailed(const std::string& filePath) {
    std::vector<Detection> out;
    std::vector<unsigned char> buffer;
    if (!readAllBytes(filePath, buffer)) return out;
    auto push = [&](const std::string& alg, const std::string& match, const std::string& sev){
        Detection d{ filePath, 0, alg, match, "oid", sev };
        out.push_back(std::move(d));
    };
    BIO* bio = BIO_new_mem_buf(buffer.data(), (int)buffer.size());
    if (!bio) return out;
    bool parsed_any = false;
    const unsigned char* p = buffer.data();
    X509* certDer = d2i_X509(nullptr, &p, (long)buffer.size());
    if (certDer) {
        const X509_ALGOR* alg = nullptr; const ASN1_BIT_STRING* sig = nullptr;
        X509_get0_signature(&sig, &alg, certDer);
        if (alg && alg->algorithm) {
            char oid_buf[256];
            OBJ_obj2txt(oid_buf, sizeof(oid_buf), alg->algorithm, 1);
            push("x509.sig_alg", std::string(oid_buf), "med");
        }
        EVP_PKEY* pk = X509_get0_pubkey(certDer);
        if (pk) {
            int nid = EVP_PKEY_base_id(pk);
            const ASN1_OBJECT* obj = OBJ_nid2obj(nid);
            const char* sn = OBJ_nid2sn(nid);
            if (obj && sn) {
                char oid_buf[256];
                OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
                push(std::string(sn), std::string(oid_buf), "high");
            }
        }
        X509_free(certDer);
        parsed_any = true;
    }
    if (!parsed_any) {
        BIO_reset(bio);
        X509* certPem = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (certPem) {
            const X509_ALGOR* alg = nullptr; const ASN1_BIT_STRING* sig = nullptr;
            X509_get0_signature(&sig, &alg, certPem);
            if (alg && alg->algorithm) {
                char oid_buf[256];
                OBJ_obj2txt(oid_buf, sizeof(oid_buf), alg->algorithm, 1);
                push("x509.sig_alg", std::string(oid_buf), "med");
            }
            EVP_PKEY* pk = X509_get0_pubkey(certPem);
            if (pk) {
                int nid = EVP_PKEY_base_id(pk);
                const ASN1_OBJECT* obj = OBJ_nid2obj(nid);
                const char* sn = OBJ_nid2sn(nid);
                if (obj && sn) {
                    char oid_buf[256];
                    OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
                    push(std::string(sn), std::string(oid_buf), "high");
                }
            }
            X509_free(certPem);
            parsed_any = true;
        }
    }
    if (!parsed_any) {
        BIO_reset(bio);
        X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
        if (!req) {
            const unsigned char* p2 = buffer.data();
            req = d2i_X509_REQ(nullptr, &p2, (long)buffer.size());
        }
        if (req) {
            const X509_ALGOR* ralg = nullptr; const ASN1_BIT_STRING* rsig = nullptr;
            X509_REQ_get0_signature(req, &rsig, &ralg);
            if (ralg && ralg->algorithm) {
                char oid_buf[256];
                OBJ_obj2txt(oid_buf, sizeof(oid_buf), ralg->algorithm, 1);
                push("csr.sig_alg", std::string(oid_buf), "med");
            }
            EVP_PKEY* rpk = X509_REQ_get0_pubkey(req);
            if (rpk) {
                int nid = EVP_PKEY_base_id(rpk);
                const ASN1_OBJECT* obj = OBJ_nid2obj(nid);
                const char* sn = OBJ_nid2sn(nid);
                if (obj && sn) {
                    char oid_buf[256];
                    OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
                    push(std::string(sn), std::string(oid_buf), "high");
                }
            }
            X509_REQ_free(req);
            parsed_any = true;
        }
    }
    BIO_free(bio);
    if (out.empty()) {
        auto byteMatches = FileScanner::scanBytesWithOffsets(buffer, oidBytePatterns);
        std::unordered_map<std::string, std::string> typeByName;
        for (const auto& bp : oidBytePatterns) typeByName[bp.name] = bp.type;
        for (const auto& alg : byteMatches) {
            const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
            if (!isOidType(t)) continue;
            for (const auto& e : alg.second) {
                Detection d{ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) };
                out.push_back(std::move(d));
            }
        }
    }
    return out;
}

std::vector<Detection> CryptoScanner::scanBinaryWholeFile(const std::string& filePath) {
    std::vector<Detection> results;
    std::vector<unsigned char> buffer;
    if (!readAllBytes(filePath, buffer)) return results;
    FileScanner::setCurrentSourceName(filePath);
    const std::string ext = lowercaseExt(filePath);
    bool isBin = quickIsExecutableByHeader(filePath) || ext == ".so" || ext == ".dll" || ext == ".exe" || ext == ".a" || ext == ".ld";
    auto strings = FileScanner::extractAsciiStrings(buffer, 4);
    auto strMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    for (const auto& kv : strMatches) {
        const std::string& alg = kv.first;
        for (const auto& m : kv.second) {
            Detection d{ filePath, m.second, alg, m.first, evidenceTypeForTextPattern(alg), severityForTextPattern(alg, m.first) };
            results.push_back(std::move(d));
        }
    }
    auto byteMatchesAll = FileScanner::scanBytesWithOffsets(buffer, oidBytePatterns);
    std::unordered_map<std::string, std::string> typeByName;
    for (const auto& bp : oidBytePatterns) typeByName[bp.name] = bp.type;
    std::vector<std::size_t> oidAnchors;
    for (const auto& alg : byteMatchesAll) {
        const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
        if (!isOidType(t)) continue;
        for (const auto& e : alg.second) oidAnchors.push_back(e.second);
    }
    std::sort(oidAnchors.begin(), oidAnchors.end());
    oidAnchors.erase(std::unique(oidAnchors.begin(), oidAnchors.end()), oidAnchors.end());
    const std::size_t ctxWin = 2048;
    for (const auto& alg : byteMatchesAll) {
        const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
        if (t == "curve_param" || t == "prime") {
            if (isCurveParamNName(alg.first)) continue;
            for (const auto& e : alg.second) {
                if (!nearAny(oidAnchors, e.second, ctxWin)) continue;
                results.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) });
            }
        } else if (isOidType(t)) {
            for (const auto& e : alg.second) {
                results.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) });
            }
        }
    }
    if (isBin) {
        bool elf = dyn::isELF(buffer);
        bool pe  = dyn::isPE(buffer);
        if (elf) {
            auto imps = dyn::parseELF(buffer);
            for (const auto& imp : imps) {
                std::string sev = "low";
                std::string low = toLowerStr(imp.lib);
                if (low.find("crypto") != std::string::npos || low.find("openssl") != std::string::npos || low.find("mbed") != std::string::npos || low.find("wolf") != std::string::npos || low.find("gnutls") != std::string::npos || low.find("nss") != std::string::npos || low.find("gcrypt") != std::string::npos || low.find("sodium") != std::string::npos || low.find("nettle") != std::string::npos || low.find("botan") != std::string::npos) sev = "med";
                results.push_back({ filePath, 0, std::string("ELF DT_NEEDED"), imp.lib, "import", sev });
            }
        } else if (pe) {
            auto imps = dyn::parsePE(buffer);
            for (const auto& imp : imps) {
                std::string sev = "low";
                std::string low = toLowerStr(imp.lib);
                if (low.find("crypt") != std::string::npos || low.find("bcrypt") != std::string::npos || low.find("crypt32") != std::string::npos || low.find("ncrypt") != std::string::npos || low.find("schannel") != std::string::npos || low.find("secur32") != std::string::npos || low.find("libcrypto") != std::string::npos || low.find("openssl") != std::string::npos) sev = "med";
                results.push_back({ filePath, 0, std::string("PE IMPORT"), imp.lib, "import", sev });
                for (const auto& fn : imp.funcs) {
                    for (const auto& ap : patternsApiOnly) {
                        try {
                            std::smatch m;
                            if (std::regex_search(fn, m, ap.pattern)) {
                                results.push_back({ filePath, 0, ap.name, fn, "api", severityForTextPattern(ap.name, fn) });
                            }
                        } catch (...) {}
                    }
                    std::string fl = toLowerStr(fn);
                    bool weak = fl.find("md5")!=std::string::npos || fl.find("sha1")!=std::string::npos || fl.find("des_")!=std::string::npos || fl.find("rc4")!=std::string::npos || fl.find("rc2")!=std::string::npos || fl.find("rsa_generate_key")!=std::string::npos || fl.find("seed")!=std::string::npos;
                    if (weak) results.push_back({ filePath, 0, std::string("ImportedWeakCrypto"), fn, "api", "med" });
                }
            }
        }
        postprocessDetections(results);
    }
    FileScanner::clearCurrentSourceName();
    return results;
}

std::vector<Detection> CryptoScanner::scanClassFileDetailed(const std::string& filePath) {
    std::vector<Detection> out;
    std::vector<unsigned char> data;
    if (!readAllBytes(filePath, data)) return out;
    auto strings = FileScanner::extractAsciiStrings(data, 4);
    auto strMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    for (const auto& kv : strMatches) {
        for (const auto& m : kv.second) {
            out.push_back({ filePath, m.second, kv.first, m.first, evidenceTypeForTextPattern(kv.first), severityForTextPattern(kv.first, m.first) });
        }
    }
    auto byteMatchesAll = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);
    std::unordered_map<std::string, std::string> typeByName;
    for (const auto& bp : oidBytePatterns) typeByName[bp.name] = bp.type;
    std::vector<std::size_t> oidAnchors;
    for (const auto& alg : byteMatchesAll) {
        const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
        if (!isOidType(t)) continue;
        for (const auto& e : alg.second) oidAnchors.push_back(e.second);
    }
    std::sort(oidAnchors.begin(), oidAnchors.end());
    oidAnchors.erase(std::unique(oidAnchors.begin(), oidAnchors.end()), oidAnchors.end());
    const std::size_t ctxWin = 2048;
    for (const auto& alg : byteMatchesAll) {
        const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
        if (t == "curve_param" || t == "prime") {
            if (isCurveParamNName(alg.first)) continue;
            for (const auto& e : alg.second) {
                if (!nearAny(oidAnchors, e.second, ctxWin)) continue;
                out.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) });
            }
        } else if (isOidType(t)) {
            for (const auto& e : alg.second) {
                out.push_back({ filePath, e.second, alg.first, e.first, evidenceLabelForByteType(t), severityForByteType(t) });
            }
        }
    }
    return out;
}

#ifdef USE_MINIZ
static std::string sev_text_local(const std::string& algName, const std::string& matched) {
    (void)matched;
    if (algName.find("OID dotted") != std::string::npos) return "high";
    if (algName.find("PEM Header") != std::string::npos) return "med";
    if (algName.find("API (OpenSSL)") != std::string::npos
        || algName.find("API (Windows CNG/CAPI)") != std::string::npos
        || algName.find("API (libgcrypt)") != std::string::npos) return "med";
    if (algName.find("MD5") != std::string::npos || algName.find("SHA-1") != std::string::npos) return "med";
    return "low";
}
static std::string sev_byte_local(const std::string& type) {
    if (type == "oid" || type == "asn1-oid" || type == "asn1_oid") return "high";
    if (type == "curve_param" || type == "prime") return "med";
    return "low";
}
static std::string evtype_text_local(const std::string& algName) {
    std::string s = toLowerStr(algName);
    if (s.find("oid") != std::string::npos) return "oid";
    if (s.find("pem") != std::string::npos) return "pem";
    if (s.find("api") != std::string::npos) return "api";
    return "text";
}
static std::string evlabel_byte_local(const std::string& type) {
    if (type == "oid" || type == "asn1-oid" || type == "asn1_oid") return "oid";
    if (type == "curve_param") return "curve_param";
    if (type == "prime") return "prime";
    return "bytes";
}
static std::vector<Detection> scanJarViaMiniZ_impl(const std::string& filePath,
                                                   const std::vector<AlgorithmPattern>& patterns,
                                                   const std::vector<BytePattern>& oidBytePatterns) {
    std::vector<Detection> results;
    mz_zip_archive zip; std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_file(&zip, filePath.c_str(), 0)) return results;
    const int n = (int)mz_zip_reader_get_num_files(&zip);
    for (int i = 0; i < n; ++i) {
        mz_zip_archive_file_stat st; std::memset(&st, 0, sizeof(st));
        if (!mz_zip_reader_file_stat(&zip, i, &st)) continue;
        if (st.m_is_directory) continue;
        std::string entry = st.m_filename ? st.m_filename : "";
        std::string ext = CryptoScanner::lowercaseExt(entry);
        if (!(ext == ".class" || ext == ".java")) continue;
        size_t out_size = 0;
        void* p = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if (!p) continue;
        std::vector<unsigned char> data((unsigned char*)p, (unsigned char*)p + out_size);
        mz_free(p);
        std::string display = filePath + "::" + entry;
        if (ext == ".java") {
            std::string src((const char*)data.data(), data.size());
            auto syms = analyzers::JavaASTScanner::collectSymbols(display, src);
            for (const auto& s : syms) {
                std::vector<std::string> cands;
                cands.push_back(s.callee_full);
                if (s.callee_base != s.callee_full) cands.push_back(s.callee_base);
                if (!s.first_arg.empty()) cands.push_back(s.first_arg);
                for (const auto& cand : cands) {
                    if (cand.empty()) continue;
                    for (const auto& ap : patterns) {
                        try {
                            std::smatch m;
                            if (std::regex_search(cand, m, ap.pattern)) {
                                results.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", sev_text_local(ap.name, m.str(0)) });
                            }
                        } catch (...) {}
                    }
                }
            }
            return results;
        }
        if (ext == ".class") {
            auto strings = FileScanner::extractAsciiStrings(data, 4);
            auto strMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
            for (const auto& kv : strMatches) {
                for (const auto& m : kv.second) {
                    results.push_back({ display, m.second, kv.first, m.first, evtype_text_local(kv.first), sev_text_local(kv.first, m.first) });
                }
            }
            auto byteMatchesAll = FileScanner::scanBytesWithOffsets(data, oidBytePatterns);
            std::unordered_map<std::string, std::string> typeByName;
            for (const auto& bp : oidBytePatterns) typeByName[bp.name] = bp.type;
            std::vector<std::size_t> oidAnchors;
            for (const auto& alg : byteMatchesAll) {
                const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
                if (!isOidType(t)) continue;
                for (const auto& e : alg.second) oidAnchors.push_back(e.second);
            }
            std::sort(oidAnchors.begin(), oidAnchors.end());
            oidAnchors.erase(std::unique(oidAnchors.begin(), oidAnchors.end()), oidAnchors.end());
            const std::size_t ctxWin = 2048;
            for (const auto& alg : byteMatchesAll) {
                const std::string t = typeByName.count(alg.first) ? typeByName[alg.first] : std::string();
                if (t == "curve_param" || t == "prime") {
                    if (isCurveParamNName(alg.first)) continue;
                    for (const auto& e : alg.second) {
                        if (!nearAny(oidAnchors, e.second, ctxWin)) continue;
                        results.push_back({ display, e.second, alg.first, e.first, evlabel_byte_local(t), sev_byte_local(t) });
                    }
                } else if (isOidType(t)) {
                    for (const auto& e : alg.second) {
                        results.push_back({ display, e.second, alg.first, e.first, evlabel_byte_local(t), sev_byte_local(t) });
                    }
                }
            }
            return results;
        }
    }
    mz_zip_reader_end(&zip);
    return results;
}
#endif

std::vector<Detection> CryptoScanner::scanJarViaMiniZ(const std::string& filePath) {
#ifdef USE_MINIZ
    return scanJarViaMiniZ_impl(filePath, patterns, oidBytePatterns);
#else
    return {};
#endif
}

std::vector<Detection> CryptoScanner::scanJarFileDetailed(const std::string& filePath) {
    return scanJarViaMiniZ(filePath);
}

std::vector<Detection> CryptoScanner::scanFileDetailed(const std::string& filePath) {
    std::vector<Detection> out;
    const std::string ext = lowercaseExt(filePath);
    if (isCertOrKeyExt(ext) || isLikelyPem(filePath)) {
        auto v = scanCertOrKeyFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }
    if (ext == ".py") {
        auto syms = analyzers::PythonASTScanner::collectSymbols(filePath);
        for (const auto& s : syms) {
            std::vector<std::string> cands{ s.callee_full };
            if (s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if (!s.first_arg.empty()) cands.push_back(s.first_arg);
            for (const auto& cand : cands) {
                if (cand.empty()) continue;
                for (const auto& ap : patterns) {
                    try {
                        std::smatch m;
                        if (std::regex_search(cand, m, ap.pattern)) {
                            out.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                        }
                    } catch (...) {}
                }
            }
        }
        return out;
    }
    if (ext == ".java") {
        std::string src;
        if (readTextFile(filePath, src)) {
            auto syms = analyzers::JavaASTScanner::collectSymbols(filePath, src);
            for (const auto& s : syms) {
                std::vector<std::string> cands{ s.callee_full };
                if (s.callee_base != s.callee_full) cands.push_back(s.callee_base);
                if (!s.first_arg.empty()) cands.push_back(s.first_arg);
                for (const auto& cand : cands) {
                    if (cand.empty()) continue;
                    for (const auto& ap : patterns) {
                        try {
                            std::smatch m;
                            if (std::regex_search(cand, m, ap.pattern)) {
                                out.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                            }
                        } catch (...) {}
                    }
                }
            }
            return out;
        }
    }
    if (ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" || ext == ".h" || ext == ".hpp" || ext == ".hh") {
        auto syms = analyzers::CppASTScanner::collectSymbols(filePath);
        for (const auto& s : syms) {
            std::vector<std::string> cands{ s.callee_full };
            if (s.callee_base != s.callee_full) cands.push_back(s.callee_base);
            if (!s.first_arg.empty()) cands.push_back(s.first_arg);
            for (const auto& cand : cands) {
                if (cand.empty()) continue;
                for (const auto& ap : patterns) {
                    try {
                        std::smatch m;
                        if (std::regex_search(cand, m, ap.pattern)) {
                            out.push_back({ s.filePath, s.line, ap.name, m.str(0), "ast", severityForTextPattern(ap.name, m.str(0)) });
                        }
                    } catch (...) {}
                }
            }
        }
        return out;
    }
    if (ext == ".class") {
        auto v = scanClassFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }
    if (isJarLikeExt(ext)) {
        auto v = scanJarFileDetailed(filePath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }
    auto v = scanBinaryWholeFile(filePath);
    out.insert(out.end(), v.begin(), v.end());
    return out;
}

std::vector<Detection> CryptoScanner::scanPathRecursive(const std::string& rootPath) {
    std::vector<Detection> out;
    std::error_code ec;
    if (fs::is_regular_file(rootPath, ec)) {
        auto v = scanFileDetailed(rootPath);
        out.insert(out.end(), v.begin(), v.end());
        return out;
    }
    if (!fs::is_directory(rootPath, ec)) return out;
    for (fs::recursive_directory_iterator it(rootPath, fs::directory_options::skip_permission_denied, ec), end; it != end; ++it) {
        const auto& de = *it;
        if (!de.is_regular_file(ec)) continue;
        auto v = scanFileDetailed(de.path().string());
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

static bool pathStartsWith(const std::string& s, const std::string& prefix) {
    return s.rfind(prefix, 0) == 0;
}

void CryptoScanner::scanPathLikeAntivirus(
    const std::string& rootPath,
    const ScanOptions& opt,
    const std::function<void(const Detection&)>& onDetect,
    const std::function<void(const std::string&, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>& onProgress,
    const std::function<bool()>& isCancelled
) {
    cancelCb = isCancelled;
    activeOpt = opt;
    if (rootPath == "/" && activeOpt.profile == ScanProfile::Default) {
        activeOpt.profile = ScanProfile::InstitutionStrict;
        activeOpt.excludeSystemDirs = true;
        activeOpt.excludeDevDirs = true;
        activeOpt.jarMaxEntryJava = 0;
        activeOpt.jarMaxEntryClass = 0;
        activeOpt.jarMaxTotalUncomp = 0;
        activeOpt.jarMaxEntries = 0;
    }
    auto shouldSkipByProfile = [&](const fs::path& p) -> bool {
        std::string s = p.string();
        if (s == "/") return false;
        if (activeOpt.profile == ScanProfile::InstitutionStrict || activeOpt.excludeSystemDirs) {
            if (pathStartsWith(s, "/proc")) return true;
            if (pathStartsWith(s, "/sys")) return true;
            if (pathStartsWith(s, "/dev")) return true;
            if (pathStartsWith(s, "/run")) return true;
            if (pathStartsWith(s, "/snap")) return true;
            if (pathStartsWith(s, "/var/lib/docker")) return true;
            if (pathStartsWith(s, "/var/lib/flatpak")) return true;
            if (pathStartsWith(s, "/var/cache")) return true;
            if (pathStartsWith(s, "/var/log")) return true;
            if (pathStartsWith(s, "/tmp")) return true;
            if (pathStartsWith(s, "/var/tmp")) return true;
            if (pathStartsWith(s, "/lost+found")) return true;
            if (pathStartsWith(s, "/usr/lib")) return true;
            if (pathStartsWith(s, "/lib/")) return true;
        }
        if (activeOpt.profile == ScanProfile::InstitutionStrict) {
            if (globMatches(s, scanprofile::kInstitutionExcludeGlobs)) return true;
        }
        if (!activeOpt.excludeGlobs.empty()) {
            if (globMatches(s, activeOpt.excludeGlobs)) return true;
        }
        return false;
    };
    std::vector<std::string> files;
    auto pushCandidate = [&](const fs::path& p) {
        std::string s = p.string();
        const std::string ext = lowercaseExt(s);
        bool isCandidate = false;
        if (isCertOrKeyExt(ext) || isLikelyPem(s)) isCandidate = true;
        else if (ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" || ext == ".h" || ext == ".hpp" || ext == ".hh") isCandidate = true;
        else if (ext == ".py" || ext == ".java") isCandidate = true;
        else if (ext == ".class") isCandidate = true;
        else if (isJarLikeExt(ext)) isCandidate = true;
        else if (isVersionedSoName(s) || ext == ".so" || ext == ".dll" || ext == ".exe" || ext == ".a" || ext == ".ld" || quickIsExecutableByHeader(s)) isCandidate = true;
        if (!isCandidate) return;
        if (!activeOpt.includeGlobs.empty()) {
            if (!globMatches(s, activeOpt.includeGlobs)) return;
        }
        if (shouldSkipByProfile(p)) return;
        if (globMatches(s, activeOpt.excludeGlobs)) return;
        files.push_back(s);
    };
    std::vector<fs::path> roots;
    if (activeOpt.profile == ScanProfile::InstitutionStrict && rootPath == "/") {
        for (const auto& r : scanprofile::kPreferredRootDirs) { std::error_code ec; if (fs::exists(r, ec)) roots.emplace_back(r); }
        if (roots.empty()) roots.push_back("/");
    } else {
        roots.push_back(rootPath);
    }
    std::error_code ec;
    auto addFromRoot = [&](const fs::path& r) {
        if (fs::is_regular_file(r, ec)) { pushCandidate(r); return; }
        if (!fs::is_directory(r, ec)) return;
        if (activeOpt.recurse) {
            for (fs::recursive_directory_iterator it(r, fs::directory_options::skip_permission_denied, ec), end; it != end; ++it) {
                const auto& de = *it;
                if (isCancelled && isCancelled()) break;
                if (de.is_directory(ec)) {
                    if (shouldSkipByProfile(de.path())) it.disable_recursion_pending();
                    continue;
                }
                if (de.is_symlink(ec)) continue;
                if (!de.is_regular_file(ec)) continue;
                if (shouldSkipByProfile(de.path().parent_path())) continue;
                pushCandidate(de.path());
            }
        } else {
            for (fs::directory_iterator it(r, ec), end; it != end; ++it) {
                const auto& de = *it;
                if (!de.is_regular_file(ec)) continue;
                pushCandidate(de.path());
            }
        }
    };
    for (const auto& r : roots) addFromRoot(r);
    std::uint64_t totalFiles = files.size();
    std::uint64_t totalBytes = 0;
    for (const auto& f : files) totalBytes += (std::uint64_t)getFileSizeSafe(f);
    std::atomic<std::uint64_t> filesDone{0};
    std::atomic<std::uint64_t> bytesDone{0};
    std::mutex cbMutex;
    const unsigned int th = std::min(32u, std::max(2u, std::thread::hardware_concurrency() * 2));
    std::atomic<std::size_t> idx{0};
    auto worker = [&]() {
        while (true) {
            if (isCancelled && isCancelled()) break;
            std::size_t i = idx.fetch_add(1);
            if (i >= files.size()) break;
            if (isCancelled && isCancelled()) break;
            const std::string path = files[i];
            const std::uint64_t sz = (std::uint64_t)getFileSizeSafe(path);
            std::vector<Detection> dets;
            try { dets = scanFileDetailed(path); } catch (...) { dets.clear(); }
            {
                std::lock_guard<std::mutex> lk(cbMutex);
                for (const auto& d : dets) onDetect(d);
                onProgress(path, filesDone.load() + 1, totalFiles, bytesDone.load() + sz, totalBytes);
            }
            filesDone.fetch_add(1);
            bytesDone.fetch_add(sz);
        }
    };
    std::vector<std::thread> pool;
    for (unsigned int t = 0; t < th; t++) pool.emplace_back(worker);
    for (auto& t : pool) t.join();
}
