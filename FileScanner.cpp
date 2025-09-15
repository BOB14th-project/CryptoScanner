#include "FileScanner.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstring>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

inline bool isPrintable(unsigned char c){
    return c >= 0x20 && c <= 0x7E;
}

static thread_local std::string g_currentSourceName;

static inline std::string toHex(const std::vector<uint8_t>& v) {
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setfill('0');
    for (auto b : v) {
        os << std::setw(2) << static_cast<unsigned>(b);
    }
    return os.str();
}

static inline bool isAllSameByte(const std::vector<uint8_t>& v, uint8_t& valOut){
    if(v.empty()) return false;
    uint8_t x = v[0];
    for(size_t i=1;i<v.size();++i) if(v[i]!=x) return false;
    valOut = x;
    return true;
}

static inline bool isLowEntropyPattern(const std::vector<uint8_t>& v){
    if(v.size() < 16) return false;
    bool seen[256] = {false};
    size_t distinct = 0;
    for (auto b: v){
        if(!seen[b]){ seen[b] = true; ++distinct; if(distinct>2) break; }
    }
    return distinct <= 2;
}

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

static inline bool isExecutableBuffer(const std::vector<unsigned char>& buf){
    if(buf.size() >= 4){
        if(buf[0]==0x7F && buf[1]=='E' && buf[2]=='L' && buf[3]=='F') return true;
    }
    if(buf.size() >= 2){
        if(buf[0]=='M' && buf[1]=='Z') return true;
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

static inline fs::path resultDirRoot(){
    return fs::path(getExecDir()) / "result";
}

static inline void dumpExecBufferIfNeeded(const std::vector<unsigned char>& buf){
    if(buf.empty()) return;
    if(!isExecutableBuffer(buf)) return;
    std::string folder = sanitizeFolder(g_currentSourceName);
    fs::path outdir = resultDirRoot() / folder;
    std::error_code ec;
    fs::create_directories(outdir, ec);
    uint64_t h = fnv1a64(buf.data(), buf.size());
    std::string outName = std::string("dump.") + toHex16(h) + ".bin";
    fs::path out = outdir / outName;
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if(!f) return;
    f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
}

} 

void FileScanner::setCurrentSourceName(const std::string& path){
    g_currentSourceName = basenameOnly(path);
}

void FileScanner::clearCurrentSourceName(){
    g_currentSourceName.clear();
}

std::vector<AsciiString> FileScanner::extractAsciiStrings(const std::vector<unsigned char>& data, std::size_t minLength){
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
    dumpExecBufferIfNeeded(data);
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
