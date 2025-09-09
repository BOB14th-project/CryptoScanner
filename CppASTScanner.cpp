#include "CppASTScanner.h"
#include "PatternLoader.h"

#include <regex>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <cctype>

namespace fs = std::filesystem;

namespace analyzers {

static void add(std::vector<Detection>& v, const std::string& path, size_t line,
                const std::string& alg, const std::string& ev, const std::string& sev){
    v.push_back({ path, line, alg, ev, "ast", sev.empty()? "med" : sev });
}
static bool readAll(const std::string& p, std::string& out){
    std::ifstream in(p, std::ios::binary); if(!in) return false;
    std::ostringstream oss; oss<<in.rdbuf(); out=oss.str(); return true;
}

static std::vector<Detection> tryClangAST(const std::string& path, const std::vector<pattern_loader::AstRule>& rules){
    std::vector<Detection> out;
    if(!CryptoScanner::toolExists("clang")) return out;

    std::string cmd = "clang -Xclang -ast-dump -fsyntax-only -w " + CryptoScanner::shellQuote(path) + " 2>/dev/null";
    std::string dump;
    if(!CryptoScanner::runCommandText(cmd, dump)) return out;

    std::vector<std::string> lines;
    { std::istringstream iss(dump); std::string L; while(std::getline(iss, L)) lines.push_back(L); }

    for(const auto& r: rules){
        if(r.lang!="cpp" || (r.kind!="call" && r.kind!="call_bits")) continue;

        std::regex argRx; bool chkArg = !r.arg_regex.empty();
        if(chkArg) argRx = std::regex(r.arg_regex, std::regex::ECMAScript|std::regex::icase);

        std::vector<std::string> callees = r.callees;
        if(callees.empty() && !r.callee.empty()) callees.push_back(r.callee);

        for(size_t i=0;i<lines.size();++i){
            for(const auto& fn : callees){
                if(lines[i].find("DeclRefExpr")!=std::string::npos && lines[i].find("'"+fn+"'")!=std::string::npos){
                    size_t start = i>5? i-5:0;
                    for(size_t j=start; j<=i; ++j){
                        if(lines[j].find("CallExpr")!=std::string::npos){
                            size_t pos = lines[j].find("line:");
                            size_t ln  = 0;
                            if(pos!=std::string::npos){
                                pos += 5;
                                ln = (size_t)std::strtoul(lines[j].c_str()+pos, nullptr, 10);
                            }
                            if(r.kind=="call_bits"){
                                size_t end = std::min(lines.size(), i+8);
                                std::regex intRx(R"(IntegerLiteral.*\s(\d{3,5}))");
                                std::string bits=""; 
                                for(size_t k=j;k<end;++k){
                                    std::smatch m; if(std::regex_search(lines[k], m, intRx)){ bits=m.str(1); break; }
                                }
                                add(out, path, ln?ln:1, r.message, bits.empty()? fn : bits, r.severity);
                            }else{
                                add(out, path, ln?ln:1, r.message, fn, r.severity);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    return out;
}

static std::vector<Detection> fallbackLexical(const std::string& path, const std::string& code,
                                              const std::vector<pattern_loader::AstRule>& rules){
    std::vector<Detection> out;
    std::istringstream iss(code);
    std::string line; size_t ln=0;

    struct R { std::regex call; std::regex arg; bool chkArg; std::string msg; std::string sev; };
    std::vector<R> RR;
    for(const auto& r: rules){
        if(r.lang!="cpp") continue;
        std::vector<std::string> callees = r.callees;
        if(callees.empty() && !r.callee.empty()) callees.push_back(r.callee);
        for(const auto& fn : callees){
            std::string patt = std::string("\\b") + fn + "\\s*\\(";
            R x{ std::regex(patt), std::regex(), false, r.message, r.severity.empty()? "med": r.severity };
            if(!r.arg_regex.empty()){
                x.chkArg = true; x.arg = std::regex(r.arg_regex, std::regex::ECMAScript|std::regex::icase);
            }
            RR.push_back(std::move(x));
        }
    }

    while(std::getline(iss, line)){
        ++ln;
        for(const auto& x: RR){
            if(std::regex_search(line, x.call)){
                if(!x.chkArg || std::regex_search(line, x.arg)){
                    add(out, path, ln, x.msg, "call", x.sev);
                }
            }
        }

        {
            std::smatch m;
            if(std::regex_search(line, m, std::regex(R"(RSA_generate_key_ex\s*\([^,]+,\s*(\d{3,5})\s*,)"))){
                add(out, path, ln, "RSA keygen bits", m.str(1), "med");
            }
            if(std::regex_search(line, m, std::regex(R"(EVP_PKEY_CTX_set_rsa_keygen_bits\s*\([^,]+,\s*(\d{3,5})\s*\))"))){
                add(out, path, ln, "RSA keygen bits", m.str(1), "med");
            }
            if(std::regex_search(line, m, std::regex(R"(EC_KEY_new_by_curve_name\s*\(\s*(NID_[A-Za-z0-9_]+)\s*\))"))){
                add(out, path, ln, "EC curve", m.str(1), "info");
            }
        }
    }
    return out;
}

std::vector<Detection> CppASTScanner::scanFile(const std::string& path){
    std::vector<Detection> out;
    auto LR = pattern_loader::loadFromJson();
    auto viaClang = tryClangAST(path, LR.astRules);
    out.insert(out.end(), viaClang.begin(), viaClang.end());
    std::string code;
    if(readAll(path, code)){
        auto viaLex = fallbackLexical(path, code, LR.astRules);
        out.insert(out.end(), viaLex.begin(), viaLex.end());
    }
    return out;
}

} // namespace analyzers
