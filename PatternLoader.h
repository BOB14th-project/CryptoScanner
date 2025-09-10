#pragma once

#include "PatternDefinitions.h"

#include <string>
#include <vector>
#include <regex>

namespace pattern_loader {

struct AstRule {
    std::string id;
    std::string lang;
    std::string kind;
    std::string callee;
    std::vector<std::string> callees;

    int         arg_index = -1;
    std::string kw;
    std::string kw_value_regex;
    std::string arg_regex;

    std::string message;
    std::string severity;

    std::string toJson() const;
};

struct LoadResult {
    std::vector<AlgorithmPattern> regexPatterns;
    std::vector<BytePattern>      bytePatterns;
    std::vector<AstRule>          astRules;
    std::string                   sourcePath;
    std::string                   error;
};

LoadResult loadFromJson();

LoadResult loadFromJsonFile(const std::string& path);

} // namespace pattern_loader
 