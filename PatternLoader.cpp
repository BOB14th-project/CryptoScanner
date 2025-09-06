#include "PatternLoader.h"

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QStringList>
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace {
static std::vector<uint8_t> encodeBase128(uint32_t v){
    std::vector<uint8_t> out;
    do { out.push_back(static_cast<uint8_t>(v & 0x7Fu)); v >>= 7; } while (v);
    std::reverse(out.begin(), out.end());
    for (size_t i = 0; i + 1 < out.size(); ++i) out[i] |= 0x80u;
    return out;
}

static std::vector<uint8_t> oidValueBytes(const std::string& dotted){
    std::vector<uint32_t> arcs; std::string tmp;
    for(char ch : dotted){
        if(ch == '.'){
            if(!tmp.empty()){
                arcs.push_back(static_cast<uint32_t>(std::stoul(tmp)));
                tmp.clear();
            }
        }else{
            tmp.push_back(ch);
        }
    }
    if(!tmp.empty()) arcs.push_back(static_cast<uint32_t>(std::stoul(tmp)));
    if(arcs.size() < 2) throw std::runtime_error("OID requires at least two arcs");
    std::vector<uint8_t> val;
    val.push_back(static_cast<uint8_t>(arcs[0]*40 + arcs[1]));
    for(size_t i=2;i<arcs.size();++i){
        auto enc = encodeBase128(arcs[i]);
        val.insert(val.end(), enc.begin(), enc.end());
    }
    return val;
}

static std::vector<uint8_t> oidDERBytes(const std::string& dotted){
    auto val = oidValueBytes(dotted);
    std::vector<uint8_t> out;
    out.push_back(0x06u);
    if(val.size() <= 127){
        out.push_back(static_cast<uint8_t>(val.size()));
    }else{
        std::vector<uint8_t> lenBytes;
        size_t n = val.size();
        while(n > 0){ lenBytes.push_back(static_cast<uint8_t>(n & 0xFFu)); n >>= 8; }
        std::reverse(lenBytes.begin(), lenBytes.end());
        out.push_back(static_cast<uint8_t>(0x80u | lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

// Parse hex string to bytes. Accepts spaces/colons/hyphens/commas and optional "0x".
static bool parseHex(const QString& s, std::vector<uint8_t>& out){
    QString c = s;
    c.replace("0x","",Qt::CaseInsensitive).remove(' ').remove(':').remove('-').remove(',');
    if(c.size() % 2) {
        return false;
    }
    out.clear();
    out.reserve(static_cast<size_t>(c.size()/2));
    for(int i=0;i<c.size(); i+=2){
        bool ok=false;
        uint8_t b = static_cast<uint8_t>(c.mid(i,2).toUInt(&ok,16));
        if(!ok) return false;
        out.push_back(b);
    }
    return true;
}
} // namespace

namespace pattern_loader {

static bool loadJsonObject(const QString& path, QJsonObject& root, std::string& err){
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)){
        err = "Failed to open " + path.toStdString();
        return false;
    }
    auto doc = QJsonDocument::fromJson(f.readAll());
    if(doc.isNull() || !doc.isObject()){
        err = "Invalid JSON in " + path.toStdString();
        return false;
    }
    root = doc.object();
    return true;
}

LoadResult loadFromJson(){
    LoadResult R;
    const auto env = QProcessEnvironment::systemEnvironment();
    const QString envPath = env.value("CRYPTO_SCANNER_PATTERNS");
    QStringList candidates;
    if(!envPath.isEmpty()) candidates << envPath;
    candidates << "patterns.json" << "config/patterns.json";

    for(const auto& c : candidates){
        QJsonObject root; std::string err;
        if(loadJsonObject(c, root, err)){
            return loadFromJsonFile(c.toStdString());
        }
    }
    R.error = "Pattern JSON not found. Tried ENV:CRYPTO_SCANNER_PATTERNS, ./patterns.json, ./config/patterns.json";
    return R;
}

LoadResult loadFromJsonFile(const std::string& path){
    LoadResult R;
    QJsonObject root;
    if(!loadJsonObject(QString::fromStdString(path), root, R.error)) return R;

    // regex
    if(root.contains("regex") && root["regex"].isArray()){
        const auto arr = root["regex"].toArray();
        for(const auto& v : arr){
            if(!v.isObject()){
                continue;
            }
            const auto o = v.toObject();
            const auto name = o.value("name").toString();
            const auto patt = o.value("pattern").toString();
            const bool icase = o.value("icase").toBool(true);
            if(name.isEmpty() || patt.isEmpty()){
                continue;
            }
            try{
                auto flags = std::regex_constants::ECMAScript;
                if(icase) flags = static_cast<std::regex_constants::syntax_option_type>(flags | std::regex_constants::icase);
                std::regex rx(patt.toStdString(), flags);
                R.regexPatterns.push_back({ name.toStdString(), rx });
            }catch(const std::exception& e){
                std::cerr << "[PatternLoader] Bad regex '" << name.toStdString() << "': " << e.what() << "\n";
            }
        }
    }

    // bytes
    if(root.contains("bytes") && root["bytes"].isArray()){
        const auto arr = root["bytes"].toArray();
        for(const auto& v : arr){
            if(!v.isObject()){
                continue;
            }
            const auto o = v.toObject();
            const auto name = o.value("name").toString();
            const auto hex  = o.value("hex").toString();
            if(name.isEmpty() || hex.isEmpty()){
                continue;
            }
            std::vector<uint8_t> b;
            if(!parseHex(hex, b)){
                std::cerr << "[PatternLoader] Bad hex for '" << name.toStdString() << "'\n";
                continue;
            }
            R.bytePatterns.push_back({ name.toStdString(), std::move(b) });
        }
    }

    // oids
    if(root.contains("oids") && root["oids"].isArray()){
        const auto arr = root["oids"].toArray();
        for(const auto& v : arr){
            if(!v.isObject()){
                continue;
            }
            const auto o = v.toObject();
            const auto name   = o.value("name").toString();
            const auto dotted = o.value("dotted").toString();
            QStringList emitList;
            if(o.contains("emit") && o["emit"].isArray()){
                for(const auto& e : o["emit"].toArray()){
                    emitList << e.toString();
                }
                if(emitList.isEmpty()){
                    emitList << "DER" << "VAL";
                }
            }else{
                emitList << "DER" << "VAL";
            }

            if(name.isEmpty() || dotted.isEmpty()){
                continue;
            }
            try{
                const std::string dot = dotted.toStdString();
                for(const auto& m : emitList){
                    if(m.compare("DER", Qt::CaseInsensitive) == 0){
                        auto der = oidDERBytes(dot);
                        R.bytePatterns.push_back({ "OID: " + name.toStdString() + " (" + dot + ") [DER]", std::move(der) });
                    }else if(m.compare("VAL", Qt::CaseInsensitive) == 0){
                        auto val = oidValueBytes(dot);
                        R.bytePatterns.push_back({ "OID: " + name.toStdString() + " (" + dot + ") [VAL]", std::move(val) });
                    }
                }
            }catch(const std::exception& e){
                std::cerr << "[PatternLoader] OID '" << name.toStdString()
                          << "' parse error: " << e.what() << "\n";
            }
        }
    }

    R.sourcePath = path;
    return R;
}

} // namespace pattern_loader
