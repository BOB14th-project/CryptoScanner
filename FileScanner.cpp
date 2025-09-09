#include "FileScanner.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iterator>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace {

std::string toHex(const std::vector<uint8_t>& v) {
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setfill('0');
    for (auto b : v) {
        os << std::setw(2) << static_cast<unsigned>(b);
    }
    return os.str();
}

bool isAllSameByte(const std::vector<uint8_t>& v, uint8_t& valOut){
    if(v.empty()) return false;
    uint8_t x = v[0];
    for(size_t i=1;i<v.size();++i) if(v[i]!=x) return false;
    valOut = x;
    return true;
}

bool isLowEntropyPattern(const std::vector<uint8_t>& v){
    if(v.size() < 16) return false;
    bool seen[256] = {false};
    size_t distinct = 0;
    for (auto b: v){
        if(!seen[b]){ seen[b] = true; ++distinct; if(distinct>2) break; }
    }
    return distinct <= 2;
}

} // namespace

std::vector<AsciiString> FileScanner::extractAsciiStrings(const std::vector<unsigned char>& data, std::size_t minLength){
    std::vector<AsciiString> out;
    std::string cur;
    std::size_t start = 0;
    for(std::size_t i=0;i<data.size();++i){
        unsigned char ch=data[i];
        if(ch>=0x20 && ch<=0x7E){
            if(cur.empty()) start=i;
            cur.push_back(static_cast<char>(ch));
        }else{
            if(cur.size()>=minLength) out.push_back({start, cur});
            cur.clear();
        }
    }
    if(cur.size()>=minLength) out.push_back({start, cur});
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
            }catch(const std::regex_error&){ /* ignore malformed regex */ }
        }
    }
    return res;
}

std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanBytesWithOffsets(const std::vector<unsigned char>& data, const std::vector<BytePattern>& patterns){
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> res;

    for(const auto& p: patterns){
        const auto& needle = p.bytes;
        if(needle.empty() || data.size() < needle.size()) continue;

        const bool lowEntropy = isLowEntropyPattern(needle);
        uint8_t sameVal = 0;
        const bool allSame = isAllSameByte(needle, sameVal);

        std::size_t pos = 0;
        while (pos <= data.size() - needle.size()){
            auto it = std::search(data.begin() + static_cast<std::ptrdiff_t>(pos),
                                  data.end(), needle.begin(), needle.end());
            if(it == data.end()) break;

            std::size_t off = static_cast<std::size_t>(std::distance(data.begin(), it));
            res[p.name].push_back({ toHex(needle), off });

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
