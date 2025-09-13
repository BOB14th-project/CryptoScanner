#pragma once

#include "ASTSymbol.h"

#include <vector>
#include <string>

namespace analyzers {

class JavaASTScanner {
public:
    static std::vector<AstSymbol> collectSymbols(const std::string& displayPath, const std::string& code);
};

}
