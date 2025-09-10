#include "PythonASTScanner.h"
#include "PatternLoader.h"

#include <fstream>
#include <sstream>
#include <regex>
#include <string>
#include <vector>

namespace {

std::string strip_py_comments(const std::string& s) {
    std::string out; out.reserve(s.size());
    bool in_str=false; char q=0; int triple=0;
    for (size_t i=0;i<s.size();) {
        char c=s[i];
        if (!in_str) {
            if ((c=='\'' || c=='"')) {
                size_t j=i; int cnt=0;
                while (j<s.size() && s[j]==c && cnt<3){ ++j; ++cnt; }
                if (cnt==3) { in_str=true; q=c; triple=1; out.append(3, c); i+=3; continue; }
                in_str=true; q=c; triple=0; out.push_back(c); ++i; continue;
            }
            if (c=='#') {
                while (i<s.size() && s[i]!='\n') ++i;
                if (i<s.size()) out.push_back('\n'), ++i;
                continue;
            }
            out.push_back(c); ++i;
        } else {
            if (c=='\\' && i+1<s.size()) { out.push_back(c); out.push_back(s[i+1]); i+=2; continue; }
            out.push_back(c); ++i;
            if (!triple) {
                if (c==q) { in_str=false; q=0; }
            } else {
                if (c==q && i+2<=s.size() && s[i]==q && s[i+1]==q) {
                    out.push_back(q); out.push_back(q); i+=2; in_str=false; q=0; triple=0;
                }
            }
        }
    }
    return out;
}

size_t lineno_at(const std::string& s, size_t pos){
    size_t ln=1; for(size_t i=0;i<pos && i<s.size();++i) if(s[i]=='\n') ++ln; return ln;
}

std::regex make_py_fullname_rx(const std::string& name) {
    std::string rx="\\b";
    for(char ch: name){
        if (ch=='.') rx += "\\s*\\.\\s*";
        else if (std::isalnum((unsigned char)ch) || ch=='_') rx.push_back(ch);
        else { rx.push_back('\\'); rx.push_back(ch); }
    }
    rx += "\\s*\\(";
    return std::regex(rx, std::regex::ECMAScript | std::regex::icase);
}

} // namespace

namespace analyzers {

static void add(std::vector<Detection>& v, const std::string& path, size_t line,
                const std::string& alg, const std::string& ev, const std::string& sev){
    v.push_back({ path, line, alg, ev, "ast", sev.empty()? "med" : sev });
}

std::vector<Detection> PythonASTScanner::scanFile(const std::string& path){
    std::vector<Detection> out;
    std::ifstream in(path, std::ios::binary);
    if(!in) return out;
    std::ostringstream ss; ss<<in.rdbuf();
    std::string code = ss.str();
    std::string cleaned = strip_py_comments(code);

    auto LR = pattern_loader::loadFromJson();
    for (const auto& r : LR.astRules) {
        if (r.lang != "python") continue;

        if (r.kind == "call_fullname") {
            std::regex rx = make_py_fullname_rx(r.callee);
            std::smatch m;
            std::string::const_iterator searchStart(cleaned.cbegin());
            while (std::regex_search(searchStart, cleaned.cend(), m, rx)) {
                size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                size_t ln = lineno_at(cleaned, pos);
                add(out, path, ln, r.message.empty()? r.id : r.message, r.callee, r.severity);
                searchStart = m.suffix().first;
            }
        } else if (r.kind == "call_fullname+arg") {
            std::regex rx = make_py_fullname_rx(r.callee);
            std::smatch m;
            std::string::const_iterator searchStart(cleaned.cbegin());
            while (std::regex_search(searchStart, cleaned.cend(), m, rx)) {
                size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                size_t ln = lineno_at(cleaned, pos);
                std::string tail(cleaned.begin()+pos, cleaned.end());

                std::smatch am;
                std::regex argStrRx("\\G.*?\\(\\s*([\"'])((?:\\\\.|[^\"'\\\\])*)\\1", std::regex::ECMAScript|std::regex::icase);
                if (std::regex_search(tail, am, argStrRx)) {
                    std::string arg = am[2].str();
                    try{
                        std::regex argRx(r.arg_regex, std::regex::ECMAScript|std::regex::icase);
                        if (std::regex_search(arg, argRx)) {
                            add(out, path, ln, r.message.empty()? r.id : r.message, arg, r.severity);
                        }
                    }catch(...){}
                }
                searchStart = m.suffix().first;
            }
        } else if (r.kind == "call") {
            for (const auto& fn : r.callees) {
                std::regex rx = make_py_fullname_rx(fn);
                std::smatch m;
                std::string::const_iterator searchStart(cleaned.cbegin());
                while (std::regex_search(searchStart, cleaned.cend(), m, rx)) {
                    size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                    size_t ln = lineno_at(cleaned, pos);
                    add(out, path, ln, r.message.empty()? r.id : r.message, fn, r.severity);
                    searchStart = m.suffix().first;
                }
            }
        }
    }

    return out;
}

} // namespace analyzers
