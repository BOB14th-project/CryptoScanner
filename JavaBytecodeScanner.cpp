#include "JavaBytecodeScanner.h"
#include "PatternLoader.h"

#include <regex>
#include <sstream>
#include <filesystem>

#include <QtCore/QRegularExpression>
#include <QtCore/QString>

namespace fs = std::filesystem;

namespace analyzers {

static void add(std::vector<Detection>& v, const std::string& path, size_t line,
                const std::string& alg, const std::string& ev, const std::string& sev){
    v.push_back({ path, line, alg, ev, "bytecode", sev.empty()? "med" : sev });
}
static std::string toJavapCallee(const std::string& callee){
    std::string cls, m; auto p=callee.find('.'); if(p==std::string::npos) return {};
    cls=callee.substr(0,p); m=callee.substr(p+1);
    std::string out;
    for(char ch: cls){ out.push_back(ch=='.'? '/' : ch); }
    out += R"(\s+)" + m;
    return out;
}

static void parseJavapVerbose(const std::string& displayName, const std::string& txt,
                              const std::vector<pattern_loader::AstRule>& rules,
                              std::vector<Detection>& out)
{
    std::vector<std::string> lines;
    { std::istringstream iss(txt); std::string L; while(std::getline(iss, L)) lines.push_back(L); }

    std::regex reStr(R"(String\s+(\S+))");
    std::regex reUtf8(R"(Utf8\s+([\w\-./+]+))");
    std::vector<std::pair<size_t,std::string>> strings;
    for(size_t i=0;i<lines.size();++i){
        std::smatch m;
        if(std::regex_search(lines[i], m, reStr) || std::regex_search(lines[i], m, reUtf8)){
            strings.emplace_back(i, m.str(1));
        }
    }
    auto nearString = [&](size_t idx)->std::string{
        size_t start = idx>8? idx-8:0, end = std::min(lines.size(), idx+9);
        for(size_t j=start; j<end; ++j)
            for(auto& kv: strings) if(kv.first==j) return kv.second;
        return {};
    };

    for(const auto& r: rules){
        if(r.lang!="java" || r.kind!="method_call") continue;

        std::regex reCall(toJavapCallee(r.callee));

        QRegularExpression reArg(QString::fromStdString(r.arg_regex),
                                 QRegularExpression::CaseInsensitiveOption
                               | QRegularExpression::UseUnicodePropertiesOption);
        const bool checkArg = !r.arg_regex.empty();

        for(size_t i=0;i<lines.size();++i){
            if(std::regex_search(lines[i], reCall)){
                std::string s = nearString(i);
                bool ok = true;
                if(checkArg){
                    ok = reArg.isValid() && reArg.match(QString::fromStdString(s)).hasMatch();
                }
                if(ok){
                    add(out, displayName, i+1, r.message, s.empty()? "bytecode":"bytecode:"+s, r.severity);
                }
            }
        }
    }

    std::regex reInitBits(R"(KeyPairGenerator\s+initialize\s+\(I\)V)");
    std::regex reLdcInt(R"(\bldc\s+(\d{3,5}))");
    for(size_t i=0;i<lines.size();++i){
        std::smatch m;
        if(std::regex_search(lines[i], m, reInitBits)){
            size_t start = i>6? i-6:0, end = std::min(lines.size(), i+7);
            for(size_t j=start;j<end;++j){
                std::smatch mb;
                if(std::regex_search(lines[j], mb, reLdcInt)){
                    add(out, displayName, i+1, "KeyPairGenerator.bits", mb.str(1), "med");
                    break;
                }
            }
        }
    }
}

std::vector<Detection> JavaBytecodeScanner::scanJar(const std::string& jarPath){
    std::vector<Detection> out;

    std::string listOut;
    if(!CryptoScanner::runCommandText("jar tf " + CryptoScanner::shellQuote(jarPath) + " 2>/dev/null", listOut)){
        return out;
    }
    auto LR = pattern_loader::loadFromJson();
    std::istringstream iss(listOut);
    std::string entry;
    while(std::getline(iss, entry)){
        if(entry.size()>6 && entry.substr(entry.size()-6)==".class"){
            std::string className = entry.substr(0, entry.size()-6);
            for(char& c: className) if(c=='/') c='.';
            std::string outTxt;
            std::string cmd = "javap -verbose -classpath " + CryptoScanner::shellQuote(jarPath)
                            + " " + CryptoScanner::shellQuote(className) + " 2>/dev/null";
            if(CryptoScanner::runCommandText(cmd, outTxt)){
                parseJavapVerbose(jarPath + "::" + className, outTxt, LR.astRules, out);
            }
        }
    }
    return out;
}

std::vector<Detection> JavaBytecodeScanner::scanSingleClass(const std::string& classFilePath){
    std::vector<Detection> out;
    std::string outTxt;
    std::string cmd = "javap -verbose " + CryptoScanner::shellQuote(classFilePath) + " 2>/dev/null";
    if(CryptoScanner::runCommandText(cmd, outTxt)){
        auto LR = pattern_loader::loadFromJson();
        parseJavapVerbose(classFilePath, outTxt, LR.astRules, out);
    }
    return out;
}

} // namespace analyzers
