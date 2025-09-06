#include "FileScanner.h"

#include <cctype>
#include <regex>
#include <unordered_map>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <iomanip>

std::vector<AsciiString> FileScanner::extractAsciiStrings(const std::vector<unsigned char>& data, std::size_t minLength){
    std::vector<AsciiString> out; std::string cur; std::size_t start=0;
    for(std::size_t i=0;i<data.size();++i){
        unsigned char ch=data[i];
        if(ch>=0x20 && ch<=0x7E){
            if(cur.empty()) start=i;
            cur.push_back(static_cast<char>(ch));
        }else{
            if(cur.size()>=minLength) out.push_back({start,cur});
            cur.clear();
        }
    }
    if(cur.size()>=minLength){
        out.push_back({start,cur});
    }
    return out;
}

std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanStringsWithOffsets(const std::vector<AsciiString>& strings, const std::vector<AlgorithmPattern>& patterns){
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> res;
    for(const auto& s: strings){
        for(const auto& p: patterns){
            std::smatch m;
            if(std::regex_search(s.text, m, p.pattern)){
                std::size_t off = s.offset + static_cast<std::size_t>(m.position());
                res[p.name].push_back({ m.str(), off });
            }
        }
    }
    return res;
}

static std::string toHex(const std::vector<uint8_t>& bytes){
    std::ostringstream oss;
    for(auto b: bytes){
        oss << std::uppercase << std::hex << std::setw(2)
            << std::setfill('0') << static_cast<int>(b) << ' ';
    }
    std::string s = oss.str();
    if(!s.empty()) s.pop_back();
    return s;
}

std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>>
FileScanner::scanBytesWithOffsets(const std::vector<unsigned char>& data, const std::vector<BytePattern>& patterns){
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::size_t>>> res;
    for(const auto& p: patterns){
        const auto& needle = p.bytes;
        if(needle.empty() || data.size() < needle.size()) continue;
        auto it = data.begin();
        while(true){
            it = std::search(it, data.end(), needle.begin(), needle.end());
            if(it == data.end()) break;
            std::size_t off = static_cast<std::size_t>(std::distance(data.begin(), it));
            res[p.name].push_back({ toHex(needle), off });
            ++it;
        }
    }
    return res;
}
