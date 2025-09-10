#include "PatternLoader.h"

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QString>

#include <algorithm>
#include <cctype>
#include <iostream>
#include <optional>
#include <sstream>

using namespace pattern_loader;

namespace {

static std::string qs(const QString& s){ return s.toStdString(); }

static std::string getString(const QJsonObject& o, const char* key, const std::string& dflt = ""){
    auto it = o.find(key);
    if (it == o.end() || !it->isString()) return dflt;
    return qs(it->toString());
}

static bool getBool(const QJsonObject& o, const char* key, bool dflt=false){
    auto it = o.find(key);
    if (it == o.end() || !it->isBool()) return dflt;
    return it->toBool();
}

static std::optional<std::regex> compileRegexSafe(const std::string& pat,
                                                  bool icase,
                                                  bool literal,
                                                  const std::string& syntax,
                                                  std::string& whyFailed)
{
    std::regex_constants::syntax_option_type flags = std::regex_constants::ECMAScript;
    if (syntax == "extended") flags = std::regex_constants::extended;
    if (syntax == "basic")    flags = std::regex_constants::basic;
    if (icase) flags = static_cast<std::regex_constants::syntax_option_type>(flags | std::regex_constants::icase);

    std::string actual = pat;
    if (literal) {
        static const std::string metas = R"(\\.^$|()[]{}*+?!)";
        std::string esc; esc.reserve(actual.size()*2);
        for(char ch: actual){
            if (metas.find(ch) != std::string::npos) esc.push_back('\\');
            esc.push_back(ch);
        }
        actual.swap(esc);
    }

    try {
        return std::regex(actual, flags);
    } catch (const std::regex_error& e) {
        whyFailed = e.what();
    } catch (const std::exception& e) {
        whyFailed = e.what();
    } catch (...) {
        whyFailed = "unknown regex compile error";
    }
    return std::nullopt;
}

static std::vector<uint8_t> parseHexBytes(const std::string& s){
    std::vector<uint8_t> out;
    std::string tok;
    tok.reserve(2);
    auto ishex = [](char c){ return std::isxdigit(static_cast<unsigned char>(c)); };
    for(char c : s){
        if (ishex(c)){
            tok.push_back(c);
            if (tok.size()==2){
                out.push_back(static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
                tok.clear();
            }
        }else{
            if (c=='x' || c=='X') tok.clear();
        }
    }
    return out;
}

} // namespace

namespace pattern_loader {

LoadResult loadFromJson(){
    QString p;
    auto env = QProcessEnvironment::systemEnvironment();
    if (env.contains("CRYPTO_PATTERNS")) p = env.value("CRYPTO_PATTERNS");
    else                                 p = "patterns.json";
    return loadFromJsonFile(p.toStdString());
}

LoadResult loadFromJsonFile(const std::string& path){
    LoadResult R;
    R.sourcePath = path;

    QFile f(QString::fromStdString(path));
    if(!f.open(QIODevice::ReadOnly)){
        R.error = "Cannot open " + path;
        return R;
    }
    const QByteArray raw = f.readAll();
    f.close();

    QJsonParseError perr{};
    auto doc = QJsonDocument::fromJson(raw, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()){
        R.error = std::string("JSON parse error at offset ")
                + std::to_string(perr.offset) + ": "
                + qs(perr.errorString());
        return R;
    }

    const QJsonObject root = doc.object();
    std::ostringstream warn;

    if (root.contains("regex") && root["regex"].isArray()){
        for(const auto& v : root["regex"].toArray()){
            if(!v.isObject()) continue;
            const auto o = v.toObject();

            const std::string name   = getString(o, "name", "");
            const std::string pat    = getString(o, "pattern", "");
            const bool icase         = getBool(o, "icase", true);
            const bool literal       = getBool(o, "literal", false);
            const std::string syntax = getString(o, "syntax", "ECMAScript");

            if(name.empty() || pat.empty()) continue;

            std::string why;
            auto rx = compileRegexSafe(pat, icase, literal, syntax, why);
            if (rx){
                AlgorithmPattern ap;
                ap.name    = name;
                ap.pattern = std::move(*rx);
                R.regexPatterns.push_back(std::move(ap));
            }else{
                warn << "[regex] skip '" << name << "': " << why << "\n";
            }
        }
    }

    if (root.contains("bytes") && root["bytes"].isArray()){
        for(const auto& v : root["bytes"].toArray()){
            if(!v.isObject()) continue;
            const auto o = v.toObject();

            const std::string name = getString(o, "name", "");
            const std::string hex  = getString(o, "hex", "");
            const std::string type = getString(o, "type", "bytes");
            if(name.empty() || hex.empty()) continue;

            BytePattern bp;
            bp.name  = name;
            bp.bytes = parseHexBytes(hex);
            bp.type  = type;
            if(!bp.bytes.empty()){
                R.bytePatterns.push_back(std::move(bp));
            }else{
                warn << "[bytes] empty for '" << name << "'\n";
            }
        }
    }

    if (root.contains("ast_rules") && root["ast_rules"].isArray()){
        for(const auto& v : root["ast_rules"].toArray()){
            if(!v.isObject()) continue;
            const auto o = v.toObject();

            AstRule ar;
            ar.id        = getString(o, "id", "");
            ar.lang      = getString(o, "lang", "");
            ar.kind      = getString(o, "kind", "");
            ar.callee    = getString(o, "callee", "");
            if (o.contains("callees") && o["callees"].isArray()){
                for(const auto& vv : o["callees"].toArray()){
                    if(vv.isString()) ar.callees.push_back(qs(vv.toString()));
                }
            }
            ar.arg_index      = o.contains("arg_index") ? o["arg_index"].toInt(-1) : -1;
            ar.kw             = getString(o, "kw", "");
            ar.kw_value_regex = getString(o, "kw_value_regex", "");
            ar.arg_regex      = getString(o, "arg_regex", "");
            ar.message        = getString(o, "message", "");
            ar.severity       = getString(o, "severity", "");

            R.astRules.push_back(std::move(ar));
        }
    }

    R.error = warn.str();
    return R;
}

static std::string jescape(const std::string& s){
    std::string out; out.reserve(s.size()+8);
    for(unsigned char c: s){
        switch(c){
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if(c < 0x20){
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", (int)c);
                    out += buf;
                }else out.push_back((char)c);
        }
    }
    return out;
}

std::string AstRule::toJson() const {
    std::ostringstream os;
    os << "{"
       << "\"id\":\""        << jescape(id)        << "\","
       << "\"lang\":\""      << jescape(lang)      << "\","
       << "\"kind\":\""      << jescape(kind)      << "\","
       << "\"callee\":\""    << jescape(callee)    << "\","
       << "\"callees\":[";
    for(size_t i=0;i<callees.size();++i){
        if(i) os << ",";
        os << "\"" << jescape(callees[i]) << "\"";
    }
    os << "],"
       << "\"arg_index\":"   << arg_index << ","
       << "\"kw\":\""        << jescape(kw)        << "\","
       << "\"kw_value_regex\":\"" << jescape(kw_value_regex) << "\","
       << "\"arg_regex\":\"" << jescape(arg_regex) << "\","
       << "\"message\":\""   << jescape(message)   << "\","
       << "\"severity\":\""  << jescape(severity)  << "\""
       << "}";
    return os.str();
}

} // namespace pattern_loader
 