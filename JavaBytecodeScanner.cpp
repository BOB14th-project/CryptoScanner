#include "JavaBytecodeScanner.h"

#include <cstdint>
#include <unordered_set>
#include <string>

namespace analyzers {

static uint16_t rd16(const unsigned char* p){ return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t rd32(const unsigned char* p){ return (uint32_t)((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]); }

static void add(std::vector<Detection>& out, const std::string& file, size_t line,
                const std::string& alg, const std::string& ev, const std::string& sev){
    out.push_back({ file, line, alg, ev, "bytecode", sev });
}

std::vector<Detection> JavaBytecodeScanner::scanClassBytes(const std::string& displayName,
                                                           const std::vector<unsigned char>& buf)
{
    std::vector<Detection> out;
    if(buf.size() < 16) return out;
    if(rd32(&buf[0]) != 0xCAFEBABE) return out;

    size_t off = 8;
    if(off+2 > buf.size()) return out;
    uint16_t cp_count = rd16(&buf[off]); off += 2;

    std::unordered_set<std::string> cp_utf8;
    std::unordered_set<int32_t> cp_ints;

    for(uint16_t i=1; i<cp_count; ++i){
        if(off >= buf.size()) break;
        uint8_t tag = buf[off++];

        switch(tag){
        case 1: {
            if(off+2 > buf.size()) return out;
            uint16_t len = rd16(&buf[off]); off+=2;
            if(off+len > buf.size()) return out;
            std::string s((const char*)&buf[off], (size_t)len);
            off += len;
            cp_utf8.insert(s);
            break;
        }
        case 3: {
            if(off+4 > buf.size()) return out;
            int32_t v = (int32_t)rd32(&buf[off]); off+=4;
            cp_ints.insert(v);
            break;
        }
        case 5:
        case 6:
        {
            if(off+8 > buf.size()) return out;
            off+=8;
            i++;
            break;
        }
        case 7:
        case 8:
        case 16:
        {
            if(off+2 > buf.size()) return out;
            off+=2;
            break;
        }
        case 9:
        case 10:
        case 11:
        case 12:
        case 18:
        {
            if(off+4 > buf.size()) return out;
            off+=4;
            break;
        }
        case 15:
        {
            if(off+3 > buf.size()) return out;
            off+=3;
            break;
        }
        default:
            return out;
        }
    }

    auto has = [&](const char* s){ return cp_utf8.find(s)!=cp_utf8.end(); };
    auto hasAlg = [&](std::initializer_list<const char*> alist){
        for(auto s: alist) if(has(s)) return true;
        return false;
    };

    if( (has("java/security/MessageDigest") || has("java.security.MessageDigest")) &&
        has("getInstance") &&
        hasAlg({"MD5","SHA1","SHA-1"}) )
    {
        add(out, displayName, 0, "Java: MessageDigest.getInstance(MD5|SHA-1)", "MD5|SHA1", "med");
    }

    if( (has("javax/crypto/Cipher") || has("javax.crypto.Cipher")) &&
        has("getInstance") &&
        hasAlg({"DES/ECB","RC4","AES/ECB"}) )
    {
        add(out, displayName, 0, "Java: Cipher.getInstance(DES/ECB|RC4|AES/ECB)", "modes", "high");
    }

    if( (has("java/security/Signature") || has("java.security.Signature")) &&
        has("getInstance") &&
        hasAlg({"MD5withRSA","SHA1withRSA","SHA-1withRSA"}) )
    {
        add(out, displayName, 0, "Java: Signature.getInstance(MD5withRSA|SHA1withRSA)", "MD5|SHA1", "med");
    }

    if( (has("java/security/KeyPairGenerator") || has("java.security.KeyPairGenerator")) &&
        ( has("initialize") || has("java/security/KeyPairGenerator.initialize") ) )
    {
        if(cp_ints.count(512) || cp_ints.count(768) || cp_ints.count(1024)){
            add(out, displayName, 0, "Java: KeyPairGenerator.initialize(weak key size)", "512|768|1024", "med");
        }
    }

    return out;
}

} // namespace analyzers
