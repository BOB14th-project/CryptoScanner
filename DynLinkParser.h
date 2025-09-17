#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace dyn {

struct Import {
    std::string lib;
    std::vector<std::string> funcs;
};

bool isELF(const std::vector<unsigned char>& buf);
bool isPE(const std::vector<unsigned char>& buf);
std::vector<Import> parseELF(const std::vector<unsigned char>& buf);
std::vector<Import> parsePE(const std::vector<unsigned char>& buf);

}
