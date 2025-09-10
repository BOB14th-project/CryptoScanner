#pragma once

#include "CryptoScanner.h"

#include <vector>
#include <string>

namespace analyzers {

class CppASTScanner {
public:
    static std::vector<Detection> scanFile(const std::string& path);
};

} // namespace analyzers
