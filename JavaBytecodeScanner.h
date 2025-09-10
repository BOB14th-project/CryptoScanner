#pragma once

#include "CryptoScanner.h"

#include <string>
#include <vector>
#include <cstdint>

namespace analyzers {

class JavaBytecodeScanner {
public:
    static std::vector<Detection> scanClassBytes(const std::string& displayName,
                                                 const std::vector<unsigned char>& buf);
};

} // namespace analyzers
