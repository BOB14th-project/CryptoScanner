#pragma once

#include <vector>
#include <string>

#include "CryptoScanner.h"

namespace analyzers {

class JavaBytecodeScanner {
public:
    static std::vector<Detection> scanJar(const std::string& jarPath);

    static std::vector<Detection> scanSingleClass(const std::string& classFilePath);
};

} // namespace analyzers
