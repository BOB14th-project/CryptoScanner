#include "DynLinkParser.h"
#include <cstring>

namespace dyn {

static inline bool rd(const std::vector<unsigned char>& b, size_t off, void* out, size_t n){
    if(off + n > b.size()) return false;
    std::memcpy(out, b.data() + off, n);
    return true;
}

static inline uint16_t r16le(const unsigned char* p){ return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static inline uint32_t r32le(const unsigned char* p){ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t r64le(const unsigned char* p){ return (uint64_t)r32le(p) | ((uint64_t)r32le(p+4) << 32); }

static inline uint16_t r16be(const unsigned char* p){ return ((uint16_t)p[0] << 8) | (uint16_t)p[1]; }
static inline uint32_t r32be(const unsigned char* p){ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]; }
static inline uint64_t r64be(const unsigned char* p){ return ((uint64_t)r32be(p) << 32) | (uint64_t)r32be(p+4); }

bool isELF(const std::vector<unsigned char>& buf){
    if(buf.size() < 4) return false;
    return buf[0]==0x7F && buf[1]=='E' && buf[2]=='L' && buf[3]=='F';
}

bool isPE(const std::vector<unsigned char>& buf){
    if(buf.size() < 0x40) return false;
    if(!(buf[0]=='M' && buf[1]=='Z')) return false;
    uint32_t e_lfanew = r32le(buf.data()+0x3C);
    if(e_lfanew + 4 > buf.size()) return false;
    const unsigned char* p = buf.data() + e_lfanew;
    return p[0]=='P' && p[1]=='E' && p[2]==0 && p[3]==0;
}

struct Phdr64 { uint32_t p_type; uint32_t p_flags; uint64_t p_offset; uint64_t p_vaddr; uint64_t p_paddr; uint64_t p_filesz; uint64_t p_memsz; uint64_t p_align; };
struct Phdr32 { uint32_t p_type; uint32_t p_offset; uint32_t p_vaddr; uint32_t p_paddr; uint32_t p_filesz; uint32_t p_memsz; uint32_t p_flags; uint32_t p_align; };

static size_t vaddr_to_off_64(const std::vector<unsigned char>& b, bool be, uint64_t va, uint64_t phoff, uint16_t phentsize, uint16_t phnum){
    for(uint16_t i=0;i<phnum;i++){
        size_t off = (size_t)phoff + (size_t)i * phentsize;
        if(off + sizeof(Phdr64) > b.size()) break;
        Phdr64 ph;
        if(be){
            ph.p_type  = r32be(b.data()+off+0);
            ph.p_flags = r32be(b.data()+off+4);
            ph.p_offset= r64be(b.data()+off+8);
            ph.p_vaddr = r64be(b.data()+off+16);
            ph.p_paddr = r64be(b.data()+off+24);
            ph.p_filesz= r64be(b.data()+off+32);
            ph.p_memsz = r64be(b.data()+off+40);
            ph.p_align = r64be(b.data()+off+48);
        }else{
            ph.p_type  = r32le(b.data()+off+0);
            ph.p_flags = r32le(b.data()+off+4);
            ph.p_offset= r64le(b.data()+off+8);
            ph.p_vaddr = r64le(b.data()+off+16);
            ph.p_paddr = r64le(b.data()+off+24);
            ph.p_filesz= r64le(b.data()+off+32);
            ph.p_memsz = r64le(b.data()+off+40);
            ph.p_align = r64le(b.data()+off+48);
        }
        if(ph.p_type==1){
            if(va >= ph.p_vaddr && va < ph.p_vaddr + ph.p_memsz){
                uint64_t delta = va - ph.p_vaddr;
                uint64_t foff = ph.p_offset + delta;
                if(foff < b.size()) return (size_t)foff;
            }
        }
    }
    return (size_t)0;
}

static size_t vaddr_to_off_32(const std::vector<unsigned char>& b, bool be, uint32_t va, uint32_t phoff, uint16_t phentsize, uint16_t phnum){
    for(uint16_t i=0;i<phnum;i++){
        size_t off = (size_t)phoff + (size_t)i * phentsize;
        if(off + sizeof(Phdr32) > b.size()) break;
        Phdr32 ph;
        if(be){
            ph.p_type  = r32be(b.data()+off+0);
            ph.p_offset= r32be(b.data()+off+4);
            ph.p_vaddr = r32be(b.data()+off+8);
            ph.p_paddr = r32be(b.data()+off+12);
            ph.p_filesz= r32be(b.data()+off+16);
            ph.p_memsz = r32be(b.data()+off+20);
            ph.p_flags = r32be(b.data()+off+24);
            ph.p_align = r32be(b.data()+off+28);
        }else{
            ph.p_type  = r32le(b.data()+off+0);
            ph.p_offset= r32le(b.data()+off+4);
            ph.p_vaddr = r32le(b.data()+off+8);
            ph.p_paddr = r32le(b.data()+off+12);
            ph.p_filesz= r32le(b.data()+off+16);
            ph.p_memsz = r32le(b.data()+off+20);
            ph.p_flags = r32le(b.data()+off+24);
            ph.p_align = r32le(b.data()+off+28);
        }
        if(ph.p_type==1){
            if(va >= ph.p_vaddr && va < ph.p_vaddr + ph.p_memsz){
                uint32_t delta = va - ph.p_vaddr;
                uint32_t foff = ph.p_offset + delta;
                if(foff < b.size()) return (size_t)foff;
            }
        }
    }
    return (size_t)0;
}

std::vector<Import> parseELF(const std::vector<unsigned char>& buf){
    std::vector<Import> out;
    if(!isELF(buf)) return out;
    if(buf.size() < 0x40) return out;
    unsigned char ei_class = buf[4];
    unsigned char ei_data  = buf[5];
    bool be = (ei_data == 2);
    if(ei_class == 2){
        uint64_t e_phoff = be ? r64be(buf.data()+0x20) : r64le(buf.data()+0x20);
        uint16_t e_phentsize = be ? r16be(buf.data()+0x36) : r16le(buf.data()+0x36);
        uint16_t e_phnum     = be ? r16be(buf.data()+0x38) : r16le(buf.data()+0x38);
        uint64_t dyn_off = 0, dyn_sz = 0;
        for(uint16_t i=0;i<e_phnum;i++){
            size_t off = (size_t)e_phoff + (size_t)i * e_phentsize;
            if(off + 56 > buf.size()) break;
            uint32_t p_type  = be ? r32be(buf.data()+off+0) : r32le(buf.data()+off+0);
            uint64_t p_offset= be ? r64be(buf.data()+off+8) : r64le(buf.data()+off+8);
            uint64_t p_filesz= be ? r64be(buf.data()+off+32): r64le(buf.data()+off+32);
            if(p_type==2){ dyn_off = p_offset; dyn_sz = p_filesz; }
        }
        if(dyn_off==0 || dyn_sz==0) return out;
        uint64_t strtab_va = 0; uint64_t strsz = 0;
        std::vector<uint64_t> needed;
        for(uint64_t i=0;i+16<=dyn_sz;i+=16){
            size_t off = (size_t)dyn_off + (size_t)i;
            if(off + 16 > buf.size()) break;
            uint64_t d_tag = be ? r64be(buf.data()+off+0) : r64le(buf.data()+off+0);
            uint64_t d_val = be ? r64be(buf.data()+off+8) : r64le(buf.data()+off+8);
            if(d_tag==0) break;
            if(d_tag==5) strtab_va = d_val;
            else if(d_tag==10) strsz = d_val;
            else if(d_tag==1) needed.push_back(d_val);
        }
        if(strtab_va==0) return out;
        size_t strtab_off = vaddr_to_off_64(buf, be, strtab_va, e_phoff, e_phentsize, e_phnum);
        if(strtab_off==0 || strtab_off >= buf.size()) return out;
        for(uint64_t noff : needed){
            size_t s = strtab_off + (size_t)noff;
            if(s >= buf.size()) continue;
            std::string name;
            for(size_t j=s;j<buf.size();++j){ unsigned char c = buf[j]; if(c==0) break; name.push_back((char)c); if(name.size()>4096) break; }
            if(!name.empty()) out.push_back({name, {}});
        }
        return out;
    }else if(ei_class == 1){
        uint32_t e_phoff = be ? r32be(buf.data()+0x1C) : r32le(buf.data()+0x1C);
        uint16_t e_phentsize = be ? r16be(buf.data()+0x2A) : r16le(buf.data()+0x2A);
        uint16_t e_phnum     = be ? r16be(buf.data()+0x2C) : r16le(buf.data()+0x2C);
        uint32_t dyn_off = 0, dyn_sz = 0;
        for(uint16_t i=0;i<e_phnum;i++){
            size_t off = (size_t)e_phoff + (size_t)i * e_phentsize;
            if(off + 32 > buf.size()) break;
            uint32_t p_type  = be ? r32be(buf.data()+off+0) : r32le(buf.data()+off+0);
            uint32_t p_offset= be ? r32be(buf.data()+off+4) : r32le(buf.data()+off+4);
            uint32_t p_filesz= be ? r32be(buf.data()+off+16): r32le(buf.data()+off+16);
            if(p_type==2){ dyn_off = p_offset; dyn_sz = p_filesz; }
        }
        if(dyn_off==0 || dyn_sz==0) return out;
        uint32_t strtab_va = 0; uint32_t strsz = 0;
        std::vector<uint32_t> needed;
        for(uint32_t i=0;i+8<=dyn_sz;i+=8){
            size_t off = (size_t)dyn_off + (size_t)i;
            if(off + 8 > buf.size()) break;
            uint32_t d_tag = be ? r32be(buf.data()+off+0) : r32le(buf.data()+off+0);
            uint32_t d_val = be ? r32be(buf.data()+off+4) : r32le(buf.data()+off+4);
            if(d_tag==0) break;
            if(d_tag==5) strtab_va = d_val;
            else if(d_tag==10) strsz = d_val;
            else if(d_tag==1) needed.push_back(d_val);
        }
        if(strtab_va==0) return out;
        size_t strtab_off = vaddr_to_off_32(buf, be, strtab_va, e_phoff, e_phentsize, e_phnum);
        if(strtab_off==0 || strtab_off >= buf.size()) return out;
        for(uint32_t noff : needed){
            size_t s = strtab_off + (size_t)noff;
            if(s >= buf.size()) continue;
            std::string name;
            for(size_t j=s;j<buf.size();++j){ unsigned char c = buf[j]; if(c==0) break; name.push_back((char)c); if(name.size()>4096) break; }
            if(!name.empty()) out.push_back({name, {}});
        }
        return out;
    }
    return out;
}

struct Sect {
    uint32_t va;
    uint32_t rawSize;
    uint32_t rawPtr;
};

static size_t rva_to_off(const std::vector<unsigned char>& b, uint32_t rva, const std::vector<Sect>& secs){
    for(const auto& s: secs){
        uint32_t start = s.va;
        uint32_t end = s.va + (s.rawSize ? s.rawSize : 1);
        if(rva >= start && rva < end){
            uint32_t delta = rva - start;
            size_t off = (size_t)s.rawPtr + (size_t)delta;
            if(off < b.size()) return off;
        }
    }
    return (size_t)0;
}

std::vector<Import> parsePE(const std::vector<unsigned char>& buf){
    std::vector<Import> out;
    if(!isPE(buf)) return out;
    uint32_t e_lfanew = r32le(buf.data()+0x3C);
    size_t nt = (size_t)e_lfanew;
    if(nt + 24 > buf.size()) return out;
    uint16_t numSecs = r16le(buf.data()+nt+6);
    uint16_t optSize = r16le(buf.data()+nt+20);
    size_t opt = nt + 24;
    if(opt + optSize > buf.size()) return out;
    uint16_t magic = r16le(buf.data()+opt+0);
    bool pePlus = (magic == 0x20B);
    size_t ddOff = pePlus ? 112 : 96;
    if(ddOff + 8*2 > optSize) return out;
    uint32_t impRVA = r32le(buf.data()+opt+ddOff+8);
    uint32_t impSize= r32le(buf.data()+opt+ddOff+12);
    size_t sectHdr = opt + optSize;
    std::vector<Sect> secs; secs.reserve(numSecs);
    for(uint16_t i=0;i<numSecs;i++){
        size_t sh = sectHdr + (size_t)i * 40;
        if(sh + 40 > buf.size()) break;
        uint32_t va       = r32le(buf.data()+sh+12);
        uint32_t rawSize  = r32le(buf.data()+sh+16);
        uint32_t rawPtr   = r32le(buf.data()+sh+20);
        secs.push_back({va, rawSize, rawPtr});
    }
    if(impRVA==0 || impSize==0) return out;
    size_t impOff = rva_to_off(buf, impRVA, secs);
    if(impOff==0 || impOff >= buf.size()) return out;
    size_t cur = impOff;
    for(;;){
        if(cur + 20 > buf.size()) break;
        uint32_t oft = r32le(buf.data()+cur+0);
        uint32_t tds = r32le(buf.data()+cur+4);
        uint32_t fwd = r32le(buf.data()+cur+8);
        uint32_t nameRVA = r32le(buf.data()+cur+12);
        uint32_t ft = r32le(buf.data()+cur+16);
        if(oft==0 && nameRVA==0 && ft==0) break;
        std::string dll;
        if(nameRVA){
            size_t nameOff = rva_to_off(buf, nameRVA, secs);
            if(nameOff && nameOff < buf.size()){
                for(size_t j=nameOff;j<buf.size();++j){ unsigned char c = buf[j]; if(c==0) break; dll.push_back((char)c); if(dll.size()>1024) break; }
            }
        }
        std::vector<std::string> funcs;
        uint32_t thunkRVA = oft ? oft : ft;
        if(thunkRVA){
            size_t thunkOff = rva_to_off(buf, thunkRVA, secs);
            if(thunkOff){
                for(;;){
                    if(pePlus){
                        if(thunkOff + 8 > buf.size()) break;
                        uint64_t ent = r64le(buf.data()+thunkOff);
                        if(ent==0) break;
                        bool isOrd = (ent >> 63) != 0;
                        if(!isOrd){
                            uint32_t ibnRVA = (uint32_t)(ent & 0x7FFFFFFF);
                            size_t ibnOff = rva_to_off(buf, ibnRVA, secs);
                            if(ibnOff && ibnOff + 2 < buf.size()){
                                size_t nm = ibnOff + 2;
                                std::string fn;
                                for(size_t k=nm;k<buf.size();++k){ unsigned char c = buf[k]; if(c==0) break; fn.push_back((char)c); if(fn.size()>2048) break; }
                                if(!fn.empty()) funcs.push_back(fn);
                            }
                        }
                        thunkOff += 8;
                    }else{
                        if(thunkOff + 4 > buf.size()) break;
                        uint32_t ent = r32le(buf.data()+thunkOff);
                        if(ent==0) break;
                        bool isOrd = (ent >> 31) != 0;
                        if(!isOrd){
                            uint32_t ibnRVA = ent & 0x7FFFFFFF;
                            size_t ibnOff = rva_to_off(buf, ibnRVA, secs);
                            if(ibnOff && ibnOff + 2 < buf.size()){
                                size_t nm = ibnOff + 2;
                                std::string fn;
                                for(size_t k=nm;k<buf.size();++k){ unsigned char c = buf[k]; if(c==0) break; fn.push_back((char)c); if(fn.size()>2048) break; }
                                if(!fn.empty()) funcs.push_back(fn);
                            }
                        }
                        thunkOff += 4;
                    }
                }
            }
        }
        if(!dll.empty()) out.push_back({dll, funcs});
        cur += 20;
    }
    return out;
}

}
