#include "JavaASTScanner.h"
#include "PatternLoader.h"

#include <regex>
#include <unordered_map>
#include <sstream>
#include <cctype>

#include <QtCore/QRegularExpression>
#include <QtCore/QString>

namespace analyzers {

static std::string trim(const std::string& s){
    size_t a=0,b=s.size();
    while(a<b && isspace((unsigned char)s[a])) ++a;
    while(b>a && isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}

static void gatherStringConstants(const std::string& code, std::unordered_map<std::string,std::string>& out){
    std::regex re(R"RX((?:final\s+)?String\s+([A-Za-z_]\w*)\s*=\s*"([^"]*)")RX");
    auto begin = std::sregex_iterator(code.begin(), code.end(), re);
    for(auto it=begin; it!=std::sregex_iterator(); ++it) {
        out[it->str(1)] = it->str(2);
    }
}

static std::string resolveArg(const std::string& token, const std::unordered_map<std::string,std::string>& C){
    if(token.size()>=2 && token.front()=='"' && token.back()=='"') return token.substr(1, token.size()-2);
    auto it=C.find(token); if(it!=C.end()) return it->second; return {};
}

static void add(std::vector<Detection>& v, const std::string& path, size_t line,
                const std::string& alg, const std::string& ev,
                const std::string& sev){
    v.push_back({ path, line, alg, ev, "ast", sev.empty()? "med": sev });
}

static std::string calleeToRegex(const std::string& callee){
    std::string r="\\b";
    for(char c: callee){
        if(c=='.') r += "\\s*\\.\\s*";
        else r.push_back(c);
    }
    r += "\\b";
    return r;
}

std::vector<Detection> JavaASTScanner::scanSource(const std::string& displayPath, const std::string& code){
    std::vector<Detection> out;
    std::unordered_map<std::string,std::string> C; 
    gatherStringConstants(code, C);

    auto LR = pattern_loader::loadFromJson();
    std::vector<pattern_loader::AstRule> rules = LR.astRules;

    std::istringstream iss(code);
    std::string line; 
    size_t ln=0;

    struct Comp {
        std::regex call;
        QRegularExpression arg;
        bool hasArg=false;
        bool isCtor=false;
        std::string msg;
        std::string sev;
    };

    std::vector<Comp> comps;
    comps.reserve(rules.size());

    for(const auto& r: rules){
        if(r.lang!="java") continue;

        Comp c;
        c.isCtor = (r.kind=="ctor_call" || r.kind=="ctor");
        c.msg    = r.message;
        c.sev    = r.severity.empty()? "med" : r.severity;

        if(!r.arg_regex.empty()){
            c.hasArg = true;
            c.arg = QRegularExpression(QString::fromStdString(r.arg_regex),
                                       QRegularExpression::CaseInsensitiveOption
                                     | QRegularExpression::UseUnicodePropertiesOption);
        }

        const std::string cal = calleeToRegex(r.callee);
        if(c.isCtor){
            c.call = std::regex(std::string("new\\s+") + cal + R"(\s*\(\s*(\"[^\"]+\"|[A-Za-z_]\w*)?)",
                                std::regex::ECMAScript);
        }else{
            c.call = std::regex(cal + R"(\s*\(\s*(\"[^\"]+\"|[A-Za-z_]\w*)?)",
                                std::regex::ECMAScript);
        }

        comps.push_back(std::move(c));
    }

    while(std::getline(iss, line)){
        ++ln;
        std::string L = trim(line);
        for(const auto& c : comps){
            std::smatch m;
            if(std::regex_search(L, m, c.call)){
                std::string tok = (m.size()>=2 ? m.str(1) : std::string());
                std::string val = resolveArg(tok, C);

                bool ok = true;
                if(c.hasArg){
                    const auto res = c.arg.match(QString::fromStdString(val));
                    ok = c.arg.isValid() && res.hasMatch();
                }
                if(ok){
                    add(out, displayPath, ln, c.msg, (!val.empty()? val : "call"), c.sev);
                }
            }
        }
    }
    return out;
}

} // namespace analyzers
