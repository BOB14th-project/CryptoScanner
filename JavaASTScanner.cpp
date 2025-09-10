#include "JavaASTScanner.h"
#include "PatternLoader.h"

#include <regex>
#include <string>
#include <vector>
#include <cctype>
#include <unordered_map>

namespace {

std::string strip_java_comments(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    bool in_str = false;
    char str_q = 0;
    bool in_sl_comment = false;
    bool in_ml_comment = false;
    for (size_t i=0; i<s.size(); ++i) {
        char c = s[i];
        char n = (i+1<s.size()? s[i+1] : '\0');
        if (in_sl_comment) {
            if (c == '\n') { in_sl_comment = false; out.push_back('\n'); }
            continue;
        }
        if (in_ml_comment) {
            if (c=='*' && n=='/') { in_ml_comment=false; ++i; }
            else if (c=='\n') out.push_back('\n');
            continue;
        }
        if (!in_str) {
            if (c=='"' || c=='\'') { in_str=true; str_q=c; out.push_back(c); continue; }
            if (c=='/' && n=='/') { in_sl_comment=true; ++i; continue; }
            if (c=='/' && n=='*') { in_ml_comment=true; ++i; continue; }
            out.push_back(c);
        } else {
            // in string
            out.push_back(c);
            if (c=='\\') { if (i+1<s.size()) { out.push_back(s[i+1]); ++i; } }
            else if (c==str_q) { in_str=false; str_q=0; }
        }
    }
    return out;
}

std::regex make_java_callee_regex(const std::string& callee) {
    std::string rx = "\\b";
    for (size_t i=0;i<callee.size();++i) {
        char ch = callee[i];
        if (ch=='.') rx += "\\s*\\.\\s*";
        else if (std::isalnum((unsigned char)ch) || ch=='_' || ch=='$') rx += ch;
        else { rx += '\\'; rx += ch; }
    }
    rx += "\\s*\\(";
    return std::regex(rx, std::regex::ECMAScript);
}

static std::pair<bool,std::string> extract_first_arg(const std::string& s, size_t pos){
    size_t p = s.find('(', pos);
    if (p==std::string::npos) return {false,{}};
    ++p;
    while (p<s.size() && std::isspace((unsigned char)s[p])) ++p;
    if (p>=s.size()) return {false,{}};
    if (s[p]=='"' || s[p]=='\''){
        char q=s[p++];
        std::string val;
        while (p<s.size()){
            char c=s[p++];
            if (c=='\\' && p<s.size()){ val.push_back(s[p++]); continue; }
            if (c==q){ return {true,val}; }
            val.push_back(c);
        }
        return {false,{}};
    }
    size_t start=p;
    while (p<s.size() && std::isdigit((unsigned char)s[p])) ++p;
    if (p>start) return {true,s.substr(start,p-start)};
    return {false,{}};
}

size_t lineno_at(const std::string& s, size_t pos) {
    size_t ln=1;
    for (size_t i=0;i<pos && i<s.size();++i) if (s[i]=='\n') ++ln;
    return ln;
}

} // namespace

namespace analyzers {

static void add(std::vector<Detection>& out, const std::string& path, size_t line,
                const std::string& alg, const std::string& ev, const std::string& sev){
    out.push_back({ path, line, alg, ev, "ast", sev.empty()? "med" : sev });
}

std::vector<Detection> JavaASTScanner::scanSource(const std::string& displayPath, const std::string& code){
    std::vector<Detection> out;
    auto LR = pattern_loader::loadFromJson();
    const std::string cleaned = strip_java_comments(code);

    for (const auto& r : LR.astRules) {
        if (r.lang != "java") continue;

        if (r.kind == "call_fullname" || r.kind == "call_fullname+arg") {
            std::regex rx = make_java_callee_regex(r.callee);

            std::smatch m;
            std::string::const_iterator searchStart(cleaned.cbegin());
            while (std::regex_search(searchStart, cleaned.cend(), m, rx)) {
                size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                size_t ln = lineno_at(cleaned, pos);

                if (r.kind == "call_fullname") {
                    add(out, displayPath, ln, r.message.empty()? r.id : r.message, r.callee, r.severity);
                } else {
                    auto pr = extract_first_arg(cleaned, pos);
                    if (pr.first) {
                        try {
                            std::regex argRx(r.arg_regex, std::regex::ECMAScript|std::regex::icase);
                            if (std::regex_search(pr.second, argRx)) {
                                add(out, displayPath, ln, r.message.empty()? r.id : r.message, pr.second, r.severity);
                            }
                        } catch (...) {}
                    }
                }

                searchStart = m.suffix().first;
            }
        } else if (r.kind == "call") {
            for (const auto& fn : r.callees) {
                std::regex rx = make_java_callee_regex(fn);
                std::smatch m;
                std::string::const_iterator searchStart(cleaned.cbegin());
                while (std::regex_search(searchStart, cleaned.cend(), m, rx)) {
                    size_t pos = (size_t)(m.position(0) + (searchStart - cleaned.cbegin()));
                    size_t ln = lineno_at(cleaned, pos);
                    add(out, displayPath, ln, r.message.empty()? r.id : r.message, fn, r.severity);
                    searchStart = m.suffix().first;
                }
            }
        }
    }

    return out;
}

} // namespace analyzers
