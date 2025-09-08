#include "CryptoScanner.h"

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

namespace fs = std::filesystem;

#ifdef USE_MINIZ
#include "miniz.h"
#endif

#include "JavaASTScanner.h"
#include "JavaBytecodeScanner.h"
#include "PythonASTScanner.h"
#include "CppASTScanner.h"

static std::string lowercaseExt(const std::string& p){
    auto pos=p.find_last_of('.'); if(pos==std::string::npos) return {};
    std::string ext=p.substr(pos); for(char& c: ext) c=char(std::tolower((unsigned char)c)); return ext;
}

CryptoScanner::CryptoScanner() {
    patterns        = crypto_patterns::getDefaultPatterns();
    oidBytePatterns = crypto_patterns::getDefaultOIDBytePatterns();
}

// public
std::string CryptoScanner::shellQuote(const std::string& s){
    std::string out; out.reserve(s.size()+2); out.push_back('\'');
    for(char c: s){ if(c=='\'') out+="'\"'\"'"; else out.push_back(c); } out.push_back('\''); return out;
}
bool CryptoScanner::runCommandText(const std::string& cmd, std::string& outText){
    FILE* pipe=popen(cmd.c_str(),"r"); if(!pipe) return false; std::array<char,8192> b{}; std::ostringstream oss;
    size_t total=0, limit=64*1024*1024;
    while(true){ size_t n=fread(b.data(),1,b.size(),pipe); if(n==0) break; oss.write(b.data(),n); total+=n; if(total>limit) break; }
    int rc=pclose(pipe); if(rc!=0) return false; outText=oss.str(); return true;
}
bool CryptoScanner::runCommandBinary(const std::string& cmd, std::vector<unsigned char>& outBin){
    FILE* pipe=popen(cmd.c_str(),"r"); if(!pipe) return false; std::array<unsigned char,8192> b{}; std::vector<unsigned char> data; data.reserve(64*1024);
    size_t total=0, limit=128*1024*1024;
    while(true){ size_t n=fread(b.data(),1,b.size(),pipe); if(n==0) break; data.insert(data.end(),b.begin(),b.begin()+n); total+=n; if(total>limit) break; }
    int rc=pclose(pipe); if(rc!=0) return false; outBin.swap(data); return true;
}
bool CryptoScanner::readTextFile(const std::string& path, std::string& out){
    std::ifstream in(path, std::ios::binary); if(!in) return false;
    std::ostringstream oss; oss<<in.rdbuf(); out=oss.str(); return true;
}
bool CryptoScanner::toolExists(const std::string& program){
    return (system(("command -v " + program + " >/dev/null 2>&1").c_str()) == 0);
}
std::string CryptoScanner::makeTempDir(){
    std::string tmpl = "/tmp/crypto_scanner_XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char* p = mkdtemp(buf.data());
    return p ? std::string(p) : std::string();
}
static void removeOne(const fs::path& p){
    std::error_code ec; fs::remove(p, ec);
}
void CryptoScanner::removeDirRecursive(const std::string& path){
    std::error_code ec;
    if(!fs::exists(path, ec)) return;
    for (auto it = fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec);
        it != fs::recursive_directory_iterator(); ++it) {
        if (it->is_directory(ec)) continue;
        removeOne(it->path());
    }

    fs::remove_all(path, ec);
}

// Routing
std::vector<Detection> CryptoScanner::scanFileDetailed(const std::string& filePath){
    std::ifstream check(filePath, std::ios::binary);
    if(!check){ std::cerr<<"[CryptoScanner] File not found: "<<filePath<<"\n"; return {}; }
    std::string ext=lowercaseExt(filePath);

    if(ext==".jar")    return scanJarFileDetailed(filePath);
    if(ext==".class")  return scanClassFileDetailed(filePath);
    if(ext==".java")   return scanJavaSourceFileDetailed(filePath);
    if(ext==".py")     return scanPythonSourceFileDetailed(filePath);
    if(ext==".c" || ext==".cc" || ext==".cxx" || ext==".cpp" || ext==".h" || ext==".hpp")
                       return scanCppSourceFileDetailed(filePath);

    // fallback binary scan
    return scanBinaryFileDetailed(filePath);
}

std::vector<Detection> CryptoScanner::scanBinaryFileDetailed(const std::string& filePath){
    std::ifstream in(filePath, std::ios::binary);
    if(!in){ std::cerr<<"[CryptoScanner] Failed to open: "<<filePath<<"\n"; return {}; }
    in.seekg(0,std::ios::end); auto size=in.tellg(); in.seekg(0,std::ios::beg);
    std::vector<unsigned char> buf((size_t)size); if(size>0) in.read((char*)buf.data(), size);

    auto strings     = FileScanner::extractAsciiStrings(buf);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches  = FileScanner::scanBytesWithOffsets(buf, oidBytePatterns);

    std::vector<Detection> out;
    auto collect=[&](const auto& M){
        for(const auto& alg: M) for(const auto& e: alg.second){
            out.push_back({filePath, e.second, alg.first, e.first});
        }
    };
    collect(textMatches); collect(oidMatches); return out;
}

std::vector<Detection> CryptoScanner::scanBinaryFileHeaderLimited(const std::string& filePath, std::size_t maxBytes){
    std::ifstream in(filePath, std::ios::binary);
    if(!in){ std::cerr<<"[CryptoScanner] Failed to open: "<<filePath<<"\n"; return {}; }
    std::vector<unsigned char> buf;
    buf.resize(maxBytes);
    in.read((char*)buf.data(), (std::streamsize)maxBytes);
    buf.resize((size_t)in.gcount());

    auto strings     = FileScanner::extractAsciiStrings(buf);
    auto textMatches = FileScanner::scanStringsWithOffsets(strings, patterns);
    auto oidMatches  = FileScanner::scanBytesWithOffsets(buf, oidBytePatterns);

    std::vector<Detection> out;
    auto collect=[&](const auto& M){
        for(const auto& alg: M) for(const auto& e: alg.second){
            out.push_back({filePath, e.second, alg.first, e.first});
        }
    };
    collect(textMatches); collect(oidMatches); return out;
}

// Java source (.java)
std::vector<Detection> CryptoScanner::scanJavaSourceFileDetailed(const std::string& filePath){
    std::string code;
    if(!readTextFile(filePath, code)) return {};
    return analyzers::JavaASTScanner::scanSource(filePath, code);
}

// Python source (.py)
std::vector<Detection> CryptoScanner::scanPythonSourceFileDetailed(const std::string& filePath){
    return analyzers::PythonASTScanner::scanFile(filePath);
}

// C/C++ source (.c/.cpp/.h/.hpp)
std::vector<Detection> CryptoScanner::scanCppSourceFileDetailed(const std::string& filePath){
    return analyzers::CppASTScanner::scanFile(filePath);
}

// .class
std::vector<Detection> CryptoScanner::scanClassFileDetailed(const std::string& filePath){
    std::vector<Detection> out;
    auto bc = analyzers::JavaBytecodeScanner::scanSingleClass(filePath);
    out.insert(out.end(), bc.begin(), bc.end());
    auto bin = scanBinaryFileDetailed(filePath);
    out.insert(out.end(), bin.begin(), bin.end());
    return out;
}

// .jar
std::vector<Detection> CryptoScanner::scanJarFileDetailed(const std::string& filePath){
    std::vector<Detection> base;
#ifdef USE_MINIZ
    base = scanJarViaMiniZ(filePath);
#else
    base = scanJarViaUnzip(filePath);
    if(base.empty()){
        auto viaJar = scanJarViaJarTool(filePath);
        if(!viaJar.empty()){
            base.swap(viaJar);
        }else{
            std::cerr<<"[CryptoScanner] Falling back to header-limited scan for JAR (no unzip/bsdtar/jar extraction).\n";
            base = scanBinaryFileHeaderLimited(filePath, 16u * 1024u * 1024u); // 16MB cap
        }
    }
#endif
    auto bc   = analyzeJarBytecode(filePath);

    auto ast  = analyzeJarWithJadx(filePath);

    base.insert(base.end(), bc.begin(),  bc.end());
    base.insert(base.end(), ast.begin(), ast.end());
    return base;
}

// zipinfo / unzip / jar / bsdtar
std::vector<Detection> CryptoScanner::scanJarViaUnzip(const std::string& filePath){
    std::vector<Detection> results; std::string listOut;
    if(!runCommandText("zipinfo -1 "+shellQuote(filePath), listOut))
        if(!runCommandText("unzip -Z -1 "+shellQuote(filePath), listOut))
            if(!runCommandText("jar tf "+shellQuote(filePath), listOut)){
                std::cerr<<"[CryptoScanner] No zipinfo/unzip/jar for: "<<filePath<<"\n"; return results;
            }
    std::istringstream iss(listOut); std::string entry;
    while(std::getline(iss, entry)){
        if(entry.empty() || entry.back()=='/') continue;
        std::vector<unsigned char> data;
        std::string cmd="unzip -p "+shellQuote(filePath)+" "+shellQuote(entry);
        if(!runCommandBinary(cmd, data)){
            cmd="bsdtar -xO -f "+shellQuote(filePath)+" "+shellQuote(entry);
            if(!runCommandBinary(cmd, data)) continue;
        }
        auto strings=FileScanner::extractAsciiStrings(data);
        auto textMatches=FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches =FileScanner::scanBytesWithOffsets(data, oidBytePatterns);
        auto collect=[&](const auto& M){
            for(const auto& alg: M) for(const auto& e: alg.second)
                results.push_back({ filePath+"::"+entry, e.second, alg.first, e.first});
        };
        collect(textMatches); collect(oidMatches);
    }
    return results;
}

#ifdef USE_MINIZ
std::vector<Detection> CryptoScanner::scanJarViaMiniZ(const std::string& filePath){
    std::vector<Detection> results; mz_zip_archive zip{}; if(!mz_zip_reader_init_file(&zip, filePath.c_str(), 0)) return results;
    mz_uint n=mz_zip_reader_get_num_files(&zip);
    for(mz_uint i=0;i<n;++i){
        if(mz_zip_reader_is_file_a_directory(&zip,i)) continue;
        mz_zip_archive_file_stat st; if(!mz_zip_reader_file_stat(&zip,i,&st)) continue;
        size_t outSize=0; void* p=mz_zip_reader_extract_to_heap(&zip,i,&outSize,0); if(!p||!outSize){ mz_free(p); continue; }
        std::vector<unsigned char> data((unsigned char*)p,(unsigned char*)p+outSize); mz_free(p);
        auto strings=FileScanner::extractAsciiStrings(data);
        auto textMatches=FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches =FileScanner::scanBytesWithOffsets(data, oidBytePatterns);
        auto collect=[&](const auto& M){
            for(const auto& alg: M) for(const auto& e: alg.second)
                results.push_back({ filePath+std::string("::")+st.m_filename, e.second, alg.first, e.first});
        };
        collect(textMatches); collect(oidMatches);
    }
    mz_zip_reader_end(&zip); return results;
}
#endif

std::vector<Detection> CryptoScanner::scanJarViaJarTool(const std::string& filePath){
    std::vector<Detection> results;
    if(!toolExists("jar")){
        std::cerr<<"[CryptoScanner] jar tool not found for "<<filePath<<"\n"; 
        return results;
    }
    const std::string tmpRoot = makeTempDir();
    if(tmpRoot.empty()){
        std::cerr<<"[CryptoScanner] mkdtemp failed for "<<filePath<<"\n";
        return results;
    }

    {
        std::string cmd = "sh -c " + shellQuote("cd " + tmpRoot + " && jar xf " + filePath + " 2>/dev/null");
        int rc = system(cmd.c_str());
        if(rc != 0){
            std::cerr<<"[CryptoScanner] `jar xf` failed for "<<filePath<<"\n";
            removeDirRecursive(tmpRoot);
            return results;
        }
    }

    std::error_code ec;
    for(fs::recursive_directory_iterator it(tmpRoot, fs::directory_options::skip_permission_denied, ec), end; it!=end; ++it){
        if(!it->is_regular_file(ec)) continue;
        std::ifstream in(it->path(), std::ios::binary);
        if(!in) continue;
        std::vector<unsigned char> data;
        std::array<char, 8192> buf{};
        while(in){
            in.read(buf.data(), (std::streamsize)buf.size());
            std::streamsize got = in.gcount();
            if(got > 0) data.insert(data.end(), (unsigned char*)buf.data(), (unsigned char*)buf.data()+got);
        }
        auto strings=FileScanner::extractAsciiStrings(data);
        auto textMatches=FileScanner::scanStringsWithOffsets(strings, patterns);
        auto oidMatches =FileScanner::scanBytesWithOffsets(data, oidBytePatterns);

        fs::path rel = fs::relative(it->path(), tmpRoot, ec);
        std::string display = filePath + "::" + rel.generic_string();

        auto collect=[&](const auto& M){
            for(const auto& alg: M) for(const auto& e: alg.second)
                results.push_back({ display, e.second, alg.first, e.first});
        };
        collect(textMatches); collect(oidMatches);
    }

    removeDirRecursive(tmpRoot);
    return results;
}

// Java analyzers
std::vector<Detection> CryptoScanner::analyzeJarBytecode(const std::string& filePath){
    if(!toolExists("javap") || !toolExists("jar")) {
        std::cerr<<"[CryptoScanner] javap/jar not found; skip bytecode analysis\n";
        return {};
    }
    return analyzers::JavaBytecodeScanner::scanJar(filePath);
}

std::uintmax_t CryptoScanner::getFileSizeSafe(const std::string& path){
    std::error_code ec; auto sz = fs::file_size(path, ec); if(ec) return 0; return sz;
}
std::size_t CryptoScanner::getJadxMaxBytes(){
    const char* env = std::getenv("CRYPTO_SCANNER_JADX_MAXMB");
    std::size_t mb = env ? (std::size_t)std::strtoul(env, nullptr, 10) : 50;
    if(mb == 0) return 0;
    return mb * 1024ull * 1024ull;
}

std::vector<Detection> CryptoScanner::analyzeJarWithJadx(const std::string& filePath){
    const auto maxBytes = getJadxMaxBytes();
    if(maxBytes == 0){
        std::cerr<<"[CryptoScanner] JADX disabled by env (CRYPTO_SCANNER_JADX_MAXMB=0)\n";
        return {};
    }
    const auto sz = getFileSizeSafe(filePath);
    if(sz > maxBytes){
        std::cerr<<"[CryptoScanner] Skip JADX for large JAR ("<<sz<<" bytes > "<<maxBytes<<")\n";
        return {};
    }

    if(!toolExists("jadx")){
        std::cerr<<"[CryptoScanner] jadx not found; skip decompile\n";
        return {};
    }
    const std::string tmpRoot = makeTempDir();
    if(tmpRoot.empty()){
        std::cerr<<"[CryptoScanner] mkdtemp failed; skip decompile\n";
        return {};
    }
    const std::string outDir = tmpRoot + "/jd";
    fs::create_directories(outDir);

    const std::string cmd = "jadx -d " + shellQuote(outDir) + " " + shellQuote(filePath) + " >/dev/null 2>&1";
    if(system(cmd.c_str()) != 0){
        std::cerr<<"[CryptoScanner] jadx failed; skip decompile\n";
        removeDirRecursive(tmpRoot);
        return {};
    }
    const fs::path srcRoot = fs::path(outDir) / "sources";
    std::vector<Detection> results;
    std::error_code ec;
    if(fs::exists(srcRoot, ec)){
        for(fs::recursive_directory_iterator it(srcRoot, fs::directory_options::skip_permission_denied, ec); it!=fs::recursive_directory_iterator(); ++it){
            if(!it->is_regular_file(ec)) continue;
            if(it->path().extension()==".java"){
                std::string code;
                if(readTextFile(it->path().string(), code)){
                    auto det = analyzers::JavaASTScanner::scanSource(filePath + "::" + it->path().lexically_relative(srcRoot).string(), code);
                    results.insert(results.end(), det.begin(), det.end());
                }
            }
        }
    }
    removeDirRecursive(tmpRoot);
    return results;
}

// Recursive scan
std::vector<Detection> CryptoScanner::scanPathRecursive(const std::string& rootPath){
    std::vector<Detection> all; std::error_code ec;
    if(fs::is_regular_file(rootPath, ec)){ auto v=scanFileDetailed(rootPath); all.insert(all.end(),v.begin(),v.end()); return all; }
    if(!fs::is_directory(rootPath, ec)){ std::cerr<<"[CryptoScanner] Not a file or directory: "<<rootPath<<"\n"; return all; }
    for(fs::recursive_directory_iterator it(rootPath, fs::directory_options::skip_permission_denied, ec), end; it!=end; ++it){
        const auto& de=*it; if(!de.is_regular_file(ec)) continue;
        try{ auto v=scanFileDetailed(de.path().string()); all.insert(all.end(),v.begin(),v.end()); } catch(...) {}
    }
    return all;
}
