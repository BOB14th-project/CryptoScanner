#pragma once

#include <vector>
#include <string>

#include "CryptoScanner.h"

namespace analyzers {

class CppASTScanner {
public:
    static std::vector<Detection> scanFile(const std::string& path);
};

} // namespace analyzers
