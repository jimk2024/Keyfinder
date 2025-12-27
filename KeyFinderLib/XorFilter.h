#ifndef KEYFINDERLIB_XORFILTER_H
#define KEYFINDERLIB_XORFILTER_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include "KeySearchTypes.h"

namespace XorFilter {

class Reader {
public:
    Reader() = default;

    bool load(const std::string &path);
    bool isLoaded() const { return _loaded; }

    // Query by 5-word hash160
    inline bool mightContain(const unsigned int h[5]) const {
        if(!_loaded || _arrlen == 0) return false;
        uint32_t idx[3];
        getIdx3(h, _seed, _arrlen, idx);
        uint16_t f = _fp[idx[0]] ^ _fp[idx[1]] ^ _fp[idx[2]];
        return (f & _mask) == fingerprint(h, _seed, _mask);
    }

    // Query by KeyFinder's hash160 struct
    inline bool mightContain(const hash160 &x) const { return mightContain(x.h); }

    // Meta
    uint32_t fbits() const { return _fbits; }
    uint64_t seed()  const { return _seed; }
    uint64_t count() const { return _count; }
    uint64_t arrlen() const { return _arrlen; }
    // Expose mask and fingerprint array for device-side upload
    inline uint16_t mask() const { return _mask; }
    inline const std::vector<uint16_t>& fp() const { return _fp; }

private:
    // hashing identical to XorFilterBuilder/main.cpp
    static inline uint64_t mix64(uint64_t x) {
        x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27; x *= 0x94d049bb133111ebULL;
        x ^= x >> 31; return x;
    }
    static inline uint64_t hashKey64(const unsigned int h[5], uint64_t seed) {
        uint64_t x = seed ^ 0x9e3779b97f4a7c15ULL;
        x = mix64(x ^ ((((uint64_t)h[0]) << 32) | h[1]));
        x = mix64(x ^ ((((uint64_t)h[2]) << 32) | h[3]));
        x = mix64(x ^ ((((uint64_t)h[4]) << 32) | (h[0] ^ h[2])));
        return x;
    }
    static inline void getIdx3(const unsigned int h[5], uint64_t seed, uint32_t m, uint32_t idx[3]) {
        uint64_t base = hashKey64(h, seed);
        uint64_t a = mix64(base + 0x9e3779b97f4a7c15ULL);
        uint64_t b = mix64(base + 0x3c6ef372fe94f82aULL);
        uint64_t c = mix64(base + 0xdaa66d2c7ddef7bULL);
        idx[0] = (uint32_t)(a % m);
        idx[1] = (uint32_t)(b % m);
        idx[2] = (uint32_t)(c % m);
    }
    static inline uint16_t fingerprint(const unsigned int h[5], uint64_t seed, uint16_t mask) {
        uint64_t t = mix64(hashKey64(h, seed) ^ 0xD6E8FEB86659FD93ULL);
        return (uint16_t)(t & mask);
    }

private:
    bool _loaded = false;
    uint32_t _fbits = 0;
    uint64_t _seed = 0;
    uint64_t _count = 0;
    uint64_t _arrlen = 0;
    uint16_t _mask = 0;
    std::vector<uint16_t> _fp; // 8/12/16 bits stored in 16-bit slots
};

} // namespace XorFilter

#endif // KEYFINDERLIB_XORFILTER_H