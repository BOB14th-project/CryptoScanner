#pragma once

#include "ASTSymbol.h"

#include <vector>
#include <string>

namespace analyzers {

class PythonASTScanner {
public:
    static std::vector<AstSymbol> collectSymbols(const std::string& path);
};

}
