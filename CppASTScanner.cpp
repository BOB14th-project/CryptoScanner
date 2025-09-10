#include "CppASTScanner.h"
#include "PatternLoader.h"

#include <fstream>
#include <sstream>
#include <regex>
#include <string>

static std::string strip_cpp_comments(const std::string& s){
    std::string out; out.reserve(s.size());
    bool in_str=false; char q=0; bool in_ml=false;
    for(size_t i=0;i<s.size();++i){
        char c=s[i]; char n=(i+1<s.size()?s[i+1]:'\0');
        if(in_ml){
            if(c=='*' && n=='/'){ in_ml=false; ++i; }
            else if(c=='\n'){ out.push_back('\n'); }
            continue;
        }
        if(!in_str){
            if(c=='"' || c=='\''){ in_str=true; q=c; out.push_back(c); continue; }
            if(c=='/' && n=='/'){ while(i<s.size() && s[i]!='\n') ++i; if(i<s.size()) out.push_back('\n'); continue; }
            if(c=='/' && n=='*'){ in_ml=true; ++i; continue; }
            if(c=='#'){
                while(i<s.size() && s[i]!='\n') ++i; if(i<s.size()) out.push_back('\n');
                continue;
            }
            out.push_back(c);
        }else{
            out.push_back(c);
            if(c=='\\' && i+1<s.size()){ out.push_back(s[i+1]); ++i; }
            else if(c==q){ in_str=false; q=0; }
        }
    }
    return out;
}

static size_t lineno_at(const std::string& s, size_t pos){
    size_t ln=1; for(size_t i=0;i<pos && i<s.size();++i) if(s[i]=='\n') ++ln; return ln;
}

static std::regex make_c_call_rx(const std::string& name){
    std::string rx = std::string("\\b") + name + "\\s*\\(";
    return std::regex(rx, std::regex::ECMAScript);
}

namespace analyzers {

static void add(std::vector<Detection>& v, const std::string& path, size_t line,
                const std::string& alg, const std::string& ev, const std::string& sev){
    v.push_back({ path, line, alg, ev, "ast", sev.empty()? "med" : sev });
}

std::vector<Detection> CppASTScanner::scanFile(const std::string& path){
    std::vector<Detection> out;
    std::ifstream in(path, std::ios::binary);
    if(!in) return out;
    std::ostringstream ss; ss<<in.rdbuf();
    std::string code = ss.str();
    std::string cleaned = strip_cpp_comments(code);

    auto LR = pattern_loader::loadFromJson();
    for(const auto& r : LR.astRules){
        if(r.lang!="cpp") continue;
        if(r.kind=="call"){
            for(const auto& fn: r.callees){
                std::regex rx = make_c_call_rx(fn);
                std::smatch m;
                std::string::const_iterator searchStart(cleaned.cbegin());
                while(std::regex_search(searchStart, cleaned.cend(), m, rx)){
                    size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                    size_t ln = lineno_at(cleaned, pos);
                    add(out, path, ln, r.message.empty()? r.id : r.message, fn, r.severity);
                    searchStart = m.suffix().first;
                }
            }
        } else if (r.kind=="call_fullname" || r.kind=="call_fullname+arg"){
            std::regex rx = make_c_call_rx(r.callee);
            std::smatch m;
            std::string::const_iterator searchStart(cleaned.cbegin());
            while(std::regex_search(searchStart, cleaned.cend(), m, rx)){
                size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                size_t ln = lineno_at(cleaned, pos);
                if(r.kind=="call_fullname"){
                    add(out, path, ln, r.message.empty()? r.id : r.message, r.callee, r.severity);
                } else {
                    std::smatch am;
                    std::string tail(cleaned.begin()+pos, cleaned.end());
                    std::regex argStrRx("\\G.*?\\(\\s*([\"'])((?:\\\\.|[^\"'\\\\])*)\\1", std::regex::ECMAScript);
                    if (std::regex_search(tail, am, argStrRx)) {
                        std::string arg = am[2].str();
                        try{
                            std::regex argRx(r.arg_regex, std::regex::ECMAScript|std::regex::icase);
                            if(std::regex_search(arg, argRx)){
                                add(out, path, ln, r.message.empty()? r.id : r.message, arg, r.severity);
                            }
                        }catch(...){}
                    } else {
                        std::regex argNumRx("\\G.*?\\(\\s*([0-9]+)", std::regex::ECMAScript);
                        if(std::regex_search(tail, am, argNumRx)){
                            std::string arg=am[1].str();
                            try{
                                std::regex argRx(r.arg_regex, std::regex::ECMAScript|std::regex::icase);
                                if(std::regex_search(arg, argRx)){
                                    add(out, path, ln, r.message.empty()? r.id : r.message, arg, r.severity);
                                }
                            }catch(...){}
                        }
                    }
                }
                searchStart = m.suffix().first;
            }
        }
    }

    return out;
}

} // namespace analyzers
