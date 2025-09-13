#include "PatternDefinitions.h"
#include "PatternLoader.h"

#include <iostream>

namespace crypto_patterns {

std::vector<AlgorithmPattern> getDefaultPatterns() {
    auto r = pattern_loader::loadFromJson();
    if (!r.error.empty()) std::cerr << "[PatternDefinitions] " << r.error << "\n";
    else std::cerr << "[PatternDefinitions] Loaded regex from: " << r.sourcePath << "\n";
    return std::move(r.regexPatterns);
}

std::vector<BytePattern> getDefaultOIDBytePatterns() {
    auto r = pattern_loader::loadFromJson();
    if (!r.error.empty()) std::cerr << "[PatternDefinitions] " << r.error << "\n";
    else std::cerr << "[PatternDefinitions] Loaded bytes/OIDs from: " << r.sourcePath << "\n";
    return std::move(r.bytePatterns);
}

std::vector<pattern_loader::AstRule> getDefaultASTRules() {
    using pattern_loader::AstRule;
    std::vector<AstRule> v;

    {
        AstRule r; r.id="cpp_des_api"; r.lang="cpp"; r.kind="call"; r.callees={"DES_set_key","DES_ecb_encrypt"}; r.message="DES usage"; r.severity="high"; v.push_back(r);
    }
    {
        AstRule r; r.id="cpp_rc4_api"; r.lang="cpp"; r.kind="call"; r.callees={"RC4_set_key","EVP_rc4"}; r.message="RC4 usage"; r.severity="high"; v.push_back(r);
    }
    {
        AstRule r; r.id="cpp_md5_api"; r.lang="cpp"; r.kind="call"; r.callees={"MD5","MD5_Init","EVP_md5"}; r.message="MD5 usage"; r.severity="med"; v.push_back(r);
    }
    {
        AstRule r; r.id="cpp_sha1_api"; r.lang="cpp"; r.kind="call"; r.callees={"SHA1","SHA1_Init","EVP_sha1"}; r.message="SHA1 usage"; r.severity="med"; v.push_back(r);
    }

    {
        AstRule r; r.id="java_md_getInstance"; r.lang="java"; r.kind="call_fullname+arg"; r.callee="MessageDigest.getInstance"; r.arg_index=0; r.arg_regex="(?i)MD5|SHA-1|SHA1"; r.message="Weak hash (MD5/SHA1)"; r.severity="med"; v.push_back(r);
    }
    {
        AstRule r; r.id="java_cipher_getInstance_weak"; r.lang="java"; r.kind="call_fullname+arg"; r.callee="Cipher.getInstance"; r.arg_index=0; r.arg_regex="(?i)(AES/ECB|DES/ECB|DES$|DESede/ECB|RC4|ARCFOUR|ARC4)"; r.message="Weak/ECB cipher mode"; r.severity="high"; v.push_back(r);
    }
    {
        AstRule r; r.id="java_kpg_rsa_1024"; r.lang="java"; r.kind="call_fullname+arg"; r.callee="KeyPairGenerator.initialize"; r.arg_index=0; r.arg_regex="\\b1024\\b"; r.message="RSA 1024-bit"; r.severity="med"; v.push_back(r);
    }

    {
        AstRule r; r.id="py_hashlib_md5"; r.lang="python"; r.kind="call_fullname"; r.callee="hashlib.md5"; r.message="MD5 usage"; r.severity="med"; v.push_back(r);
    }
    {
        AstRule r; r.id="py_hashlib_sha1"; r.lang="python"; r.kind="call_fullname"; r.callee="hashlib.sha1"; r.message="SHA1 usage"; r.severity="med"; v.push_back(r);
    }
    {
        AstRule r; r.id="py_hashlib_new_weak"; r.lang="python"; r.kind="call_fullname+arg"; r.callee="hashlib.new"; r.arg_index=0; r.arg_regex="(?i)md5|sha1"; r.message="Weak hash via hashlib.new"; r.severity="med"; v.push_back(r);
    }
    {
        AstRule r; r.id="py_des_arc4"; r.lang="python"; r.kind="call"; r.callees={"DES.new","ARC4.new","Crypto.Cipher.DES.new","Cryptodome.Cipher.DES.new"}; r.message="DES/RC4 usage"; r.severity="high"; v.push_back(r);
    }

    return v;
}

} // namespace crypto_patterns
