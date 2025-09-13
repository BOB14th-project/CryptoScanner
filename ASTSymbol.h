#pragma once

#include <string>
#include <cstddef>

struct AstSymbol {
    std::string filePath;
    std::size_t line;
    std::string lang;
    std::string callee_full;
    std::string callee_base;
    std::string first_arg;
};
