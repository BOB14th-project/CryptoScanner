#include "FileScanner.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {
thread_local std::string g_currentSourceName;
thread_local std::string g_currentSourcePath;

static inline std::string basenameOnly(const std::string& path){
    fs::path p(path);
    return p.filename().string();
}

static inline std::string sanitizeFolder(const std::string& name){
    std::string s = name;
    for(char& c : s){
        unsigned char u = (unsigned char)c;
        if(c == '.') c = '_';
        else if(!(std::isalnum(u) || c=='_' || c=='-')) c = '_';
    }
    if(s.empty()) s = "unknown";
    return s;
}

static inline bool isPrintable(unsigned char c){
    return c >= 32 && c <= 126;
}

static inline bool hasMagic(const std::vector<unsigned char>& buf, const void* sig, size_t n){
    if(buf.size() < n) return false;
    return std::memcmp(buf.data(), sig, n) == 0;
}

static inline bool isExecutableCandidate(const std::vector<unsigned char>& buf, const std::string& path){
    if(buf.size() >= 4 && buf[0]==0x7F && buf[1]=='E' && buf[2]=='L' && buf[3]=='F') return true;
    if(buf.size() >= 2 && buf[0]=='M' && buf[1]=='Z') return true;
    static const char arsig[] = "!<arch>\n";
    if(hasMagic(buf, arsig, sizeof(arsig)-1)) return true;
    std::string lower = path;
    for(char& c: lower) c = (char)std::tolower((unsigned char)c);
    if(lower.size()){
        if(lower.rfind(".so") != std::string::npos) return true;
        if(lower.size()>=4 && lower.substr(lower.size()-4)==".exe") return true;
        if(lower.size()>=4 && lower.substr(lower.size()-4)==".dll") return true;
        if(lower.size()>=2 && lower.substr(lower.size()-2)==".a") return true;
        if(lower.size()>=3 && lower.substr(lower.size()-3)==".ld") return true;
    }
    return false;
}

static inline uint64_t fnv1a64(const void* p, size_t len){
    const uint8_t* s = static_cast<const uint8_t*>(p);
    uint64_t h = 1469598103934665603ull;
    for(size_t i=0;i<len;i++){ h ^= s[i]; h *= 1099511628211ull; }
    return h;
}

static inline std::string toHex16(uint64_t x){
    std::ostringstream oss;
    oss<<std::hex<<std::setw(16)<<std::setfill('0')<<x;
    return oss.str();
}

static inline std::string zpad(int v, int w){
    std::ostringstream oss; oss<<std::setw(w)<<std::setfill('0')<<v; return oss.str();
}

static inline std::string getExecDir(){
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if(n==0 || n==MAX_PATH) return fs::current_path().string();
    fs::path p(buf);
    return p.remove_filename().string();
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t sz = sizeof(buf);
    if(_NSGetExecutablePath(buf, &sz) != 0) return fs::current_path().string();
    fs::path p = fs::weakly_canonical(fs::path(buf));
    return p.remove_filename().string();
#else
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if(n <= 0) return fs::current_path().string();
    buf[n] = '\0';
    fs::path p = fs::weakly_canonical(fs::path(buf));
    return p.remove_filename().string();
#endif
}

static inline fs::path firstWritable(const std::vector<fs::path>& candidates){
    std::error_code ec;
    for(const auto& c: candidates){
        fs::create_directories(c, ec);
        if(!ec){
            std::ofstream t(c / ".touch", std::ios::binary | std::ios::trunc);
            if(t){ t.write("",0); t.close(); fs::remove(c / ".touch", ec); return c; }
        }
    }
    return fs::current_path();
}

static inline fs::path resultDirRoot(){
    std::vector<fs::path> cand;
    cand.push_back(fs::path(getExecDir()) / "result");
    cand.push_back(fs::current_path() / "result");
#if !defined(_WIN32)
    const char* home = std::getenv("HOME");
    if(home && *home) cand.push_back(fs::path(home) / ".cryptoscanner" / "result");
    cand.push_back(fs::path("/tmp") / "CryptoScanner" / "result");
#endif
    return firstWritable(cand);
}

static inline std::string q(const std::string& s){
    std::string out;
    out.reserve(s.size()+2);
    out.push_back('"');
    for(char c: s){
        if(c=='"') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

static inline bool writeAll(const fs::path& p, const uint8_t* data, size_t n){
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if(!f) return false;
    if(n){
        f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
        if(!f) return false;
    }
    f.flush();
    f.close();
    auto sz = fs::file_size(p, ec);
    if(ec) return false;
    return sz == n;
}

static inline bool truncateFile(const fs::path& p){
    std::error_code ec;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if(!f) return false;
    f.flush();
    f.close();
    return !fs::exists(p, ec) || fs::file_size(p, ec) == 0;
}

static inline size_t runCapture(const std::string& cmd, const fs::path& out){
#if defined(_WIN32)
    return 0;
#else
    FILE* pipe = popen(cmd.c_str(), "r");
    if(!pipe) return 0;
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if(!f){ pclose(pipe); return 0; }
    char buf[8192];
    size_t total = 0;
    for(;;){
        size_t r = fread(buf, 1, sizeof(buf), pipe);
        if(r == 0) break;
        f.write(buf, static_cast<std::streamsize>(r));
        total += r;
    }
    f.flush();
    pclose(pipe);
    return total;
#endif
}

static inline bool fileContainsAsm(const fs::path& p){
    std::ifstream in(p, std::ios::binary);
    if(!in) return false;
    const size_t cap = 4*1024*1024;
    std::string s; s.reserve(cap);
    std::vector<char> buf(65536);
    size_t readTot=0;
    while(in && readTot<cap){
        in.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize g = in.gcount();
        if(g<=0) break;
        s.append(buf.data(), (size_t)g);
        readTot += (size_t)g;
    }
    std::regex re("^\\s*[0-9A-Fa-f]+:\\s", std::regex::ECMAScript|std::regex::multiline);
    return std::regex_search(s, re);
}

static inline uint16_t rd16le(const unsigned char* p){ return (uint16_t)p[0] | ((uint16_t)p[1]<<8); }
static inline uint32_t rd32le(const unsigned char* p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }

static inline bool isELF(const std::vector<unsigned char>& b){ return b.size()>=4 && b[0]==0x7F && b[1]=='E' && b[2]=='L' && b[3]=='F'; }
static inline bool isPE(const std::vector<unsigned char>& b){ return b.size()>=2 && b[0]=='M' && b[1]=='Z'; }

static inline std::string elfMachine(const std::vector<unsigned char>& buf){
    if(buf.size()<20) return "";
    uint16_t e = (uint16_t)buf[18] | ((uint16_t)buf[19]<<8);
    switch(e){
        case 3: return "i386";
        case 62: return "i386:x86-64";
        case 40: return "arm";
        case 183: return "aarch64";
        case 20: return "ppc";
        case 21: return "ppc64";
        default: return "";
    }
}

static inline std::string peMachine(const std::vector<unsigned char>& buf){
    if(buf.size() < 0x3C+4) return "";
    uint32_t peoff = rd32le(&buf[0x3C]);
    if(buf.size() < peoff + 6) return "";
    if(!(buf[peoff]=='P' && buf[peoff+1]=='E' && buf[peoff+2]==0 && buf[peoff+3]==0)) return "";
    uint16_t m = rd16le(&buf[peoff+4]);
    switch(m){
        case 0x014c: return "i386";
        case 0x8664: return "i386:x86-64";
        case 0x01c0: return "arm";
        case 0x01c4: return "armv7";
        case 0xAA64: return "aarch64";
        default: return "";
    }
}

static inline std::string bfdForPE(const std::string& mach){
    if(mach=="i386") return "pei-i386";
    if(mach=="i386:x86-64") return "pei-x86-64";
    if(mach=="aarch64") return "pei-aarch64";
    if(mach=="arm"||mach=="armv7") return "pei-arm-wince-little";
    return "";
}

static inline bool moveOrCopy(const fs::path& src, const fs::path& dst){
    std::error_code ec;
    fs::create_directories(dst.parent_path(), ec);
    fs::rename(src, dst, ec);
    if(!ec) return true;
    std::ifstream in(src, std::ios::binary);
    if(!in) return false;
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if(!out) return false;
    std::vector<char> buf(1<<20);
    while(in){
        in.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize g = in.gcount();
        if(g>0) out.write(buf.data(), g);
    }
    out.flush();
    in.close();
    fs::remove(src, ec);
    return true;
}

static inline bool splitIntoTenBySize(const fs::path& asmPath, const fs::path& chunksDir, const std::string& hash){
    std::error_code ec;
    fs::create_directories(chunksDir, ec);
    ec.clear();
    auto total = fs::file_size(asmPath, ec);
    if(ec || total == 0) return false;
    std::ifstream in(asmPath, std::ios::binary);
    if(!in) return false;
    std::vector<uint64_t> parts(10, 0);
    uint64_t base = total / 10;
    uint64_t rem = total % 10;
    for(int i=0;i<10;i++){ parts[i] = base + (i < (int)rem ? 1 : 0); }
    const size_t BUFSZ = 1<<20;
    std::vector<char> buf(BUFSZ);
    for(int i=0;i<10;i++){
        fs::path out = chunksDir / (hash + "_" + zpad(i+1,4) + ".asm");
        std::ofstream o(out, std::ios::binary | std::ios::trunc);
        if(!o) return false;
        uint64_t left = parts[i];
        while(left){
            size_t take = (left > BUFSZ) ? BUFSZ : (size_t)left;
            in.read(buf.data(), (std::streamsize)take);
            std::streamsize got = in.gcount();
            if(got <= 0) break;
            o.write(buf.data(), got);
            left -= (uint64_t)got;
            if((uint64_t)got < take) break;
        }
        o.flush();
    }
    return true;
}

static inline size_t tryCmdSectionChecked(const std::string& baseCmd, const std::string& filePath, const std::string& section, const fs::path& outAsm){
    std::string cmd = baseCmd + " -j " + section + " " + q(filePath);
    size_t wrote = runCapture(cmd, outAsm);
    if(wrote < 32) { truncateFile(outAsm); return 0; }
    if(!fileContainsAsm(outAsm)) { truncateFile(outAsm); return 0; }
    return wrote;
}

static inline size_t tryCmdChecked(const std::string& cmd, const fs::path& outAsm){
    size_t wrote = runCapture(cmd, outAsm);
    if(wrote < 32) { truncateFile(outAsm); return 0; }
    if(!fileContainsAsm(outAsm)) { truncateFile(outAsm); return 0; }
    return wrote;
}

static inline size_t disassembleWithCandidatesPE(const std::string& arch, const std::string& filePath, const fs::path& outAsm){
    const char* sections[] = {".text","CODE",".code",".text$mn",".init",".text.startup"};
    size_t wrote = 0;
    if(arch=="i386"){
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("i686-w64-mingw32-objdump -d -M intel", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("objdump -d -M intel -b pei-i386", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("i686-w64-mingw32-objdump -d -M intel ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("objdump -d -M intel -b pei-i386 ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("objdump -D -M intel -b pei-i386 ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("objdump -D -M intel -b binary -m i386 ") + q(filePath), outAsm);
        return wrote;
    }else if(arch=="i386:x86-64"){
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("x86_64-w64-mingw32-objdump -d -M intel", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("objdump -d -M intel -b pei-x86-64", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("x86_64-w64-mingw32-objdump -d -M intel ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("objdump -d -M intel -b pei-x86-64 ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("objdump -D -M intel -b pei-x86-64 ") + q(filePath), outAsm);
        if(wrote) return wrote;
        wrote = tryCmdChecked(std::string("objdump -D -M intel -b binary -m i386:x86-64 ") + q(filePath), outAsm);
        return wrote;
    }else{
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("llvm-objdump -d --no-show-raw-insn", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("llvm-objdump -d --no-show-raw-insn ") + q(filePath), outAsm);
        return wrote;
    }
}

static inline size_t disassembleWithCandidatesELF(const std::string& arch, const std::string& filePath, const fs::path& outAsm){
    const char* sections[] = {".text",".init",".text.startup"};
    size_t wrote = 0;
    if(arch=="i386"||arch=="i386:x86-64"){
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("objdump -d -M intel --no-show-raw-insn", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("objdump -d -M intel --no-show-raw-insn ") + q(filePath), outAsm);
        if(wrote) return wrote;
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel ") + q(filePath), outAsm);
        return wrote;
    }else{
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("objdump -d --no-show-raw-insn", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("objdump -d --no-show-raw-insn ") + q(filePath), outAsm);
        if(wrote) return wrote;
        for(const char* s: sections){
            wrote = tryCmdSectionChecked("llvm-objdump -d --no-show-raw-insn", filePath, s, outAsm);
            if(wrote) return wrote;
        }
        wrote = tryCmdChecked(std::string("llvm-objdump -d --no-show-raw-insn ") + q(filePath), outAsm);
        return wrote;
    }
}

static inline size_t disassembleTextOnlyToFile(const std::string& filePath, const std::vector<unsigned char>& buf, const fs::path& outAsm){
#if defined(_WIN32)
    return 0;
#else
    if(isELF(buf)){
        std::string m = elfMachine(buf);
        return disassembleWithCandidatesELF(m, filePath, outAsm);
    }else if(isPE(buf)){
        std::string m = peMachine(buf);
        return disassembleWithCandidatesPE(m, filePath, outAsm);
    }else{
        return 0;
    }
#endif
}

static inline bool splitOrPlaceAsmBySize(const fs::path& tmpAsm, const fs::path& finalAsm, const fs::path& chunksDir, const std::string& hash){
    std::error_code ecf;
    auto sz = fs::file_size(tmpAsm, ecf);
    if(ecf || sz == 0) return false;
    const uint64_t threshold = 10ull * 1024ull * 1024ull;
    if(sz <= threshold){
        return moveOrCopy(tmpAsm, finalAsm);
    }else{
        bool ok = splitIntoTenBySize(tmpAsm, chunksDir, hash);
        std::error_code ecr; fs::remove(tmpAsm, ecr);
        return ok;
    }
}

static inline void dumpExecArtifactsIfNeeded(const std::vector<unsigned char>& buf){
    if(buf.empty()) return;
    if(!isExecutableCandidate(buf, g_currentSourcePath)) return;
    std::string folder = sanitizeFolder(g_currentSourceName.size()?g_currentSourceName:basenameOnly(g_currentSourcePath));
    if(folder=="unknown") folder = std::string("bin_") + toHex16(fnv1a64(buf.data(), buf.size()));
    fs::path root = resultDirRoot();
    fs::path outdir = root / folder;
    std::error_code ec;
    fs::create_directories(outdir, ec);
    uint64_t h = fnv1a64(buf.data(), buf.size());
    std::string hash = toHex16(h);
    std::string base = std::string("dump.") + hash;
    fs::path outBin = outdir / (base + ".bin");
    fs::path tmpAsm = outdir / (base + ".text.tmp");
    fs::path finalAsm = outdir / (base + ".asm");
    fs::path chunksDir = outdir / (base + ".chunks");
    writeAll(outBin, buf.data(), buf.size());
#if !defined(_WIN32)
    bool ok = false;
    if(!g_currentSourcePath.empty() && fs::exists(g_currentSourcePath)){
        size_t wrote = disassembleTextOnlyToFile(g_currentSourcePath, buf, tmpAsm);
        if(wrote && fileContainsAsm(tmpAsm)){
            ok = splitOrPlaceAsmBySize(tmpAsm, finalAsm, chunksDir, hash);
        }
    }
    if(!ok){
        std::error_code ecd1; fs::remove(tmpAsm, ecd1);
        std::error_code ecd2; fs::remove_all(chunksDir, ecd2);
        std::error_code ecd3; fs::remove(finalAsm, ecd3);
    }
#endif
}

static inline bool isAllSameByte(const std::vector<unsigned char>& v, uint8_t& val){
    if(v.empty()) return false;
    val = v[0];
    for(unsigned char b : v){ if(b != val) return false; }
    return true;
}

}

void FileScanner::setCurrentSourceName(const std::string& path){
    g_currentSourceName = basenameOnly(path);
    g_currentSourcePath = path;
}

void FileScanner::clearCurrentSourceName(){
    g_currentSourceName.clear();
    g_currentSourcePath.clear();
}

std::vector<AsciiString> FileScanner::extractAsciiStrings(const std::vector<unsigned char>& data, std::size_t minLength){
    dumpExecArtifactsIfNeeded(data);
    std::vector<AsciiString> out;
    std::size_t i = 0, N = data.size();
    while(i < N){
        while(i < N && !isPrintable(data[i])) i++;
        if(i >= N) break;
        std::size_t start = i;
        while(i < N && isPrintable(data[i])) i++;
        std::size_t len = i - start;
        if(len >= minLength){
            out.push_back(AsciiString{start, std::string(reinterpret_cast<const char*>(&data[start]), len)});
        }
    }
    return out;
}

std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanStringsWithOffsets(const std::vector<AsciiString>& strings, const std::vector<AlgorithmPattern>& patterns){
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> res;
    for(const auto& p: patterns){
        const std::regex& rx = p.pattern;
        for(const auto& s: strings){
            try{
                std::cregex_iterator it(s.text.c_str(), s.text.c_str()+s.text.size(), rx), end;
                for(; it!=end; ++it){
                    auto m = *it;
                    std::size_t off = s.offset + static_cast<std::size_t>(m.position());
                    res[p.name].push_back({ m.str(), off });
                }
            }catch(const std::regex_error&){}
        }
    }
    return res;
}

std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanBytesWithOffsets(const std::vector<unsigned char>& data, const std::vector<BytePattern>& patterns){
    dumpExecArtifactsIfNeeded(data);
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> res;
    for(const auto& p: patterns){
        const auto& needle = p.bytes;
        if(needle.empty() || data.size() < needle.size()) continue;
        uint8_t sameVal = 0;
        const bool allSame = isAllSameByte(needle, sameVal);
        const bool lowEntropy = [&](){
            if(needle.size() < 16) return false;
            bool seen[256] = {false};
            size_t distinct = 0;
            for (auto b: needle){
                if(!seen[b]){ seen[b] = true; ++distinct; if(distinct>2) break; }
            }
            return distinct <= 2;
        }();
        std::size_t pos = 0;
        while (pos <= data.size() - needle.size()){
            auto it = std::search(data.begin() + static_cast<std::ptrdiff_t>(pos),
                                  data.end(), needle.begin(), needle.end());
            if(it == data.end()) break;
            std::size_t off = static_cast<std::size_t>(std::distance(data.begin(), it));
            std::ostringstream hex; hex<<std::uppercase<<std::hex<<std::setfill('0');
            for(auto b: needle) hex<<std::setw(2)<<(unsigned)b;
            res[p.name].push_back({ hex.str(), off });
            if(allSame){
                std::size_t j = off + needle.size();
                while (j < data.size() && data[j] == sameVal) ++j;
                pos = j;
            }else if(lowEntropy){
                pos = off + needle.size();
            }else{
                pos = off + 1;
            }
        }
    }
    return res;
}
