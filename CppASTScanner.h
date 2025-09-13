#pragma once

#include "ASTSymbol.h"

#include <vector>
#include <string>

namespace analyzers {

class CppASTScanner {
public:
    static std::vector<AstSymbol> collectSymbols(const std::string& path);
};

}
