#include "XorFilter.h"
#include <fstream>
#include "Logger.h"
#include "util.h"

namespace XorFilter {

static inline uint32_t read32(std::ifstream &f) { uint32_t v; f.read((char*)&v,4); return v; }
static inline uint64_t read64(std::ifstream &f) { uint64_t v; f.read((char*)&v,8); return v; }

bool Reader::load(const std::string &path) {
    _loaded = false; _fp.clear(); _fbits=0; _seed=0; _count=0; _arrlen=0; _mask=0;
    std::ifstream in(path.c_str(), std::ios::binary);
    if(!in.is_open()) {
        Logger::log(LogLevel::Error, "XorFilter::Reader: cannot open '" + path + "'");
        return false;
    }
    uint32_t magic = read32(in); uint32_t version = read32(in);
    if(magic != 0x584F5246 || version != 1) {
        Logger::log(LogLevel::Error, "XorFilter::Reader: bad header magic/version");
        return false;
    }
    _fbits = read32(in);
    _seed  = read64(in);
    _count = read64(in);
    _arrlen= read64(in);
    if(_fbits == 0 || _fbits > 16) {
        Logger::log(LogLevel::Error, "XorFilter::Reader: unsupported fbits");
        return false;
    }
    _mask = (_fbits >= 16) ? 0xFFFFu : (uint16_t)((1u<<_fbits)-1u);
    _fp.resize((size_t)_arrlen);
    if(_fbits <= 8) {
        for(uint64_t i=0;i<_arrlen;i++) {
            uint8_t b; in.read((char*)&b,1);
            _fp[(size_t)i] = (uint16_t)b;
        }
    } else {
        for(uint64_t i=0;i<_arrlen;i++) {
            uint16_t w; in.read((char*)&w,2);
            _fp[(size_t)i] = (uint16_t)(w & _mask);
        }
    }
    if(!in.good()) {
        Logger::log(LogLevel::Error, "XorFilter::Reader: truncated file");
        return false;
    }
    _loaded = true;
    Logger::log(LogLevel::Info, "XorFilter::Reader loaded (fbits=" + util::format((int)_fbits) + ", seed=" + util::format((uint64_t)_seed) + ", len=" + util::format((uint64_t)_arrlen) + ")");
    return true;
}

} // namespace XorFilter