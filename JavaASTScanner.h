#pragma once

#include "CryptoScanner.h"

#include <vector>
#include <string>

namespace analyzers {

class JavaASTScanner {
public:
    static std::vector<Detection> scanSource(const std::string& displayPath, const std::string& code);
};

} // namespace analyzers
