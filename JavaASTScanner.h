#pragma once

#include <vector>
#include <string>

#include "CryptoScanner.h"

namespace analyzers {

class JavaASTScanner {
public:
    static std::vector<Detection> scanSource(const std::string& displayPath, const std::string& code);
};

} // namespace analyzers
