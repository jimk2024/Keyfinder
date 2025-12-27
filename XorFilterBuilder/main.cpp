#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <string>
#include <cstdint>
#include <algorithm>
#include <queue>
#include <cmath>
#include <limits>

#include "CmdParse.h"
#include "Logger.h"
#include "util.h"
#include "AddressUtil.h"

// Local helpers copied from KeyFinderLib/KeyFinder.cpp outline
namespace {
    bool isHexChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    bool isHexStr(const std::string &s) {
        for(char c : s) if(!isHexChar(c)) return false; return true;
    }
    bool parseHexToBytes(const std::string &hex, std::vector<unsigned char> &out) {
        std::string s = hex;
        if(s.size() % 2 != 0) return false;
        out.resize(s.size()/2);
        for(size_t i = 0; i < s.size(); i+=2) {
            auto hexByte = s.substr(i,2);
            unsigned int v;
            if(sscanf(hexByte.c_str(), "%02x", &v) != 1) return false;
            out[i/2] = (unsigned char)v;
        }
        return true;
    }
    void bytes20ToWords5(const unsigned char *bytes, unsigned int words[5]) {
        for(int i=0;i<5;i++) {
            words[i] = ((unsigned int)bytes[i*4+0] << 24) | ((unsigned int)bytes[i*4+1] << 16) | ((unsigned int)bytes[i*4+2] << 8) | (unsigned int)bytes[i*4+3];
        }
    }
    void bytes32ToWords8(const unsigned char *bytes, unsigned int words[8]) {
        for(int i=0;i<8;i++) {
            words[i] = ((unsigned int)bytes[i*4+0] << 24) | ((unsigned int)bytes[i*4+1] << 16) | ((unsigned int)bytes[i*4+2] << 8) | (unsigned int)bytes[i*4+3];
        }
    }
}

struct Hash160 {
    unsigned int v[5];
    bool operator==(const Hash160 &o) const {
        return v[0]==o.v[0] && v[1]==o.v[1] && v[2]==o.v[2] && v[3]==o.v[3] && v[4]==o.v[4];
    }
};
struct Hash160Hasher {
    size_t operator()(const Hash160 &h) const {
        uint64_t x = ((uint64_t)h.v[0] << 32) ^ h.v[1];
        uint64_t y = ((uint64_t)h.v[2] << 32) ^ h.v[3];
        uint64_t z = h.v[4];
        return (size_t)(x ^ (y<<1) ^ (z<<2));
    }
};

static void words5ToBytes20(const unsigned int w[5], unsigned char out[20]) {
    for(int i=0;i<5;i++) {
        out[i*4+0] = (unsigned char)((w[i] >> 24) & 0xFF);
        out[i*4+1] = (unsigned char)((w[i] >> 16) & 0xFF);
        out[i*4+2] = (unsigned char)((w[i] >> 8) & 0xFF);
        out[i*4+3] = (unsigned char)(w[i] & 0xFF);
    }
}

// XOR filter (xor8/xor12/xor16) builder with peeling and reverse assignment
namespace xorfilter {
    struct BuildConfig { uint32_t fbits = 8; uint64_t seed = 1469598103934665603ULL; };
    struct BuildResult {
        bool success = false;
        uint32_t fbits = 8;
        uint64_t seed = 0;
        uint64_t arrayLength = 0;
        std::vector<uint16_t> fp; // 16-bit container; 8/12/16 bits supported
    };

    static inline uint64_t mix64(uint64_t x) {
        x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27; x *= 0x94d049bb133111ebULL;
        x ^= x >> 31; return x;
    }

    static inline uint64_t hashKey64(const Hash160 &h, uint64_t seed) {
        uint64_t x = seed ^ 0x9e3779b97f4a7c15ULL;
        x = mix64(x ^ (((uint64_t)h.v[0] << 32) | h.v[1]));
        x = mix64(x ^ (((uint64_t)h.v[2] << 32) | h.v[3]));
        x = mix64(x ^ (((uint64_t)h.v[4] << 32) | (h.v[0] ^ h.v[2])));
        return x;
    }

    static inline void getIdx3(const Hash160 &key, uint64_t seed, uint32_t m, uint32_t idx[3]) {
        uint64_t base = hashKey64(key, seed);
        uint64_t a = mix64(base + 0x9e3779b97f4a7c15ULL);
        uint64_t b = mix64(base + 0x3c6ef372fe94f82aULL);
        uint64_t c = mix64(base + 0xdaa66d2c7ddef7bULL);
        idx[0] = (uint32_t)(a % m);
        idx[1] = (uint32_t)(b % m);
        idx[2] = (uint32_t)(c % m);
    }

    static inline uint16_t fingerprint(const Hash160 &key, uint64_t seed, uint32_t fbits) {
        uint64_t h = mix64(hashKey64(key, seed) ^ 0xD6E8FEB86659FD93ULL);
        uint32_t mask = (fbits >= 16) ? 0xFFFFu : ((1u << fbits) - 1u);
        return (uint16_t)(h & mask);
    }

    static bool buildOnce(const std::vector<Hash160> &keys, uint32_t fbits, uint64_t seed, uint32_t m, BuildResult &out) {
        const uint32_t n = (uint32_t)keys.size();
        if(n == 0 || m == 0) return false;
        std::vector<uint32_t> counts(m, 0);
        std::vector<uint32_t> xored(m, 0);
        uint32_t idx[3];
        for(uint32_t i=0;i<n;i++) {
            getIdx3(keys[i], seed, m, idx);
            counts[idx[0]]++; xored[idx[0]] ^= i;
            counts[idx[1]]++; xored[idx[1]] ^= i;
            counts[idx[2]]++; xored[idx[2]] ^= i;
        }
        std::queue<uint32_t> q; for(uint32_t v=0; v<m; v++) if(counts[v] == 1) q.push(v);
        std::vector<std::pair<uint32_t,uint32_t>> stack; stack.reserve(n);
        while(!q.empty()) {
            uint32_t v = q.front(); q.pop();
            if(counts[v] == 0) continue;
            uint32_t i = xored[v];
            stack.emplace_back(i, v);
            getIdx3(keys[i], seed, m, idx);
            for(int t=0;t<3;t++) {
                uint32_t u = idx[t];
                if(counts[u] == 0) continue;
                counts[u]--; xored[u] ^= i;
                if(counts[u] == 1) q.push(u);
            }
        }
        if(stack.size() != n) return false;
        std::vector<uint16_t> fp(m, 0);
        std::vector<uint16_t> phis(n);
        for(uint32_t i=0;i<n;i++) phis[i] = fingerprint(keys[i], seed, fbits);
        for(int64_t k=(int64_t)stack.size()-1; k>=0; --k) {
            uint32_t i = stack[(size_t)k].first;
            uint32_t v = stack[(size_t)k].second;
            getIdx3(keys[i], seed, m, idx);
            uint16_t val = phis[i];
            for(int t=0;t<3;t++) if(idx[t] != v) val ^= fp[idx[t]];
            fp[v] = (uint16_t)val;
        }
        out.success = true; out.fbits = fbits; out.seed = seed; out.arrayLength = m; out.fp.swap(fp);
        return true;
    }

    static BuildResult buildAuto(const std::vector<Hash160> &keys, uint32_t fbits, uint64_t seed) {
        BuildResult res; const uint64_t n = keys.size();
        if(n == 0) { res.success = true; res.fbits = fbits; res.seed = seed; res.arrayLength = 0; return res; }
        double factor = 1.23; const int maxGrowSteps = 8; const int maxSeedTriesPerSize = 24; uint64_t attempt=0;
        for(int grow=0; grow<=maxGrowSteps; ++grow) {
            uint64_t m64 = (uint64_t)std::ceil(n * factor); if(m64 < n) m64 = n; if(m64 > std::numeric_limits<uint32_t>::max()) break; uint32_t m=(uint32_t)m64;
            Logger::log(LogLevel::Info, "XOR build: size=" + util::format((uint64_t)m) + " (factor=" + util::format("%.3f", factor) + ") fbits=" + util::format((int)fbits));
            for(int t=0; t<maxSeedTriesPerSize; ++t, ++attempt) {
                uint64_t curSeed = mix64(seed + 0x9e3779b97f4a7c15ULL * (attempt+1));
                BuildResult tmp; if(buildOnce(keys, fbits, curSeed, m, tmp)) { Logger::log(LogLevel::Info, "XOR build success with seed=" + util::format((uint64_t)curSeed) + ", arrayLength=" + util::format((uint64_t)m)); return tmp; }
                if((t % 4) == 3) Logger::log(LogLevel::Info, "  retry seeds... tried " + util::format(t+1) + " seeds at this size");
            }
            factor *= 1.10; Logger::log(LogLevel::Info, "XOR build: increasing size factor to " + util::format("%.3f", factor));
        }
        Logger::log(LogLevel::Error, "XOR build failed: exhausted seed and growth attempts");
        return res;
    }
}

int main(int argc, char **argv) {
    CmdParse parser;
    parser.add("-i", "--in", true);
    parser.add("",  "--out", true);
    parser.add("",  "--sorted-out", true);
    parser.add("",  "--fbits", true);
    parser.add("",  "--seed", true);

    parser.parse(argc, argv);
    std::vector<OptArg> args = parser.getArgs();

    std::string inFile;
    std::string outFile = "targets.xorflt";
    std::string sortedOut;
    uint32_t fbits = 8;
    uint64_t seed = 0xcbf29ce484222325ULL; // FNV offset basis as default

    for(auto &a: args) {
        if(a.equals("-i","--in")) inFile = a.arg;
        else if(a.equals("","--out")) outFile = a.arg;
        else if(a.equals("","--sorted-out")) sortedOut = a.arg;
        else if(a.equals("","--fbits")) fbits = util::parseUInt32(a.arg);
        else if(a.equals("","--seed")) seed = util::parseUInt64(a.arg);
    }

    if(inFile.empty()) {
        Logger::log(LogLevel::Error, "Usage: xorfilterbuilder -i targets.txt [--out targets.xorflt] [--sorted-out targets.h160s] [--fbits 8|12|16] [--seed N]");
        return 1;
    }

    std::ifstream in(inFile.c_str());
    if(!in.is_open()) {
        Logger::log(LogLevel::Error, "Unable to open '" + inFile + "'");
        return 1;
    }

    std::unordered_set<Hash160, Hash160Hasher> set;
    std::string line;
    Logger::log(LogLevel::Info, "Loading targets from '" + inFile + "' (Base58/hash160/pk hex)");
    while(std::getline(in, line)) {
        util::removeNewline(line);
        line = util::trim(line);
        if(line.empty() || line[0]=='#') continue;
        bool added=false;
        if(Address::verifyAddress(line)) {
            unsigned int h[5];
            Base58::toHash160(line, h);
            Hash160 t; std::copy(h,h+5,t.v); set.insert(t); added=true;
        } else {
            std::string s = util::toLower(line);
            if(s.size()==40 && isHexStr(s)) {
                std::vector<unsigned char> bytes; if(!parseHexToBytes(s, bytes)) { Logger::log(LogLevel::Error, "Bad hash160: "+line); return 1; }
                unsigned int h[5]; bytes20ToWords5(bytes.data(), h); Hash160 t; std::copy(h,h+5,t.v); set.insert(t); added=true;
            } else if(s.size()==66 && isHexStr(s) && (s.rfind("02",0)==0 || s.rfind("03",0)==0)) {
                std::vector<unsigned char> bytes; if(!parseHexToBytes(s, bytes) || bytes.size()!=33) { Logger::log(LogLevel::Error, "Bad compressed pubkey: "+line); return 1; }
                unsigned int x[8]={0}, y[8]={0}; bytes32ToWords8(&bytes[1], x); y[7] = (bytes[0]==0x03)?1:0; unsigned int d[5]; Hash::hashPublicKeyCompressed(x,y,d); Hash160 t; std::copy(d,d+5,t.v); set.insert(t); added=true;
            } else if(s.size()==130 && isHexStr(s) && s.rfind("04",0)==0) {
                std::vector<unsigned char> bytes; if(!parseHexToBytes(s, bytes) || bytes.size()!=65) { Logger::log(LogLevel::Error, "Bad uncompressed pubkey: "+line); return 1; }
                unsigned int x[8]={0}, y[8]={0}; bytes32ToWords8(&bytes[1], x); bytes32ToWords8(&bytes[33], y); unsigned int d[5]; Hash::hashPublicKey(x,y,d); Hash160 t; std::copy(d,d+5,t.v); set.insert(t); added=true;
            }
        }
        if(!added) { Logger::log(LogLevel::Error, "Invalid entry: '"+line+"'"); return 1; }
    }
    Logger::log(LogLevel::Info, util::formatThousands(set.size()) + " unique targets loaded");

    // For Phase 1 PoC: we only write sorted .h160s if requested, and a placeholder .xorflt header
    if(!sortedOut.empty()) {
        std::vector<Hash160> v; v.reserve(set.size()); for(auto &h: set) v.push_back(h);
        std::sort(v.begin(), v.end(), [](const Hash160&a,const Hash160&b){ for(int i=0;i<5;i++){ if(a.v[i]!=b.v[i]) return a.v[i]<b.v[i]; } return false; });
        std::ofstream bout(sortedOut.c_str(), std::ios::binary);
        if(!bout.is_open()) { Logger::log(LogLevel::Error, "Unable to open sorted-out file"); return 1; }
        for(auto &h : v) {
            unsigned char bytes[20]; words5ToBytes20(h.v, bytes); bout.write((const char*)bytes, 20);
        }
        bout.close();
        Logger::log(LogLevel::Info, "Wrote sorted hash160s to '"+sortedOut+"'");
    }

    // Build XOR filter
    std::vector<Hash160> keys; keys.reserve(set.size()); for(const auto &h : set) keys.push_back(h);
    Logger::log(LogLevel::Info, "Building XOR filter (keys=" + util::formatThousands(keys.size()) + ", fbits=" + util::format((int)fbits) + ")...");
    auto buildRes = xorfilter::buildAuto(keys, fbits, seed);
    if(!buildRes.success) { return 2; }

    // Write .xorflt with header + fingerprint array
    std::ofstream xf(outFile.c_str(), std::ios::binary);
    if(!xf.is_open()) { Logger::log(LogLevel::Error, "Unable to open out file"); return 1; }
    uint32_t magic = 0x584F5246; // 'XORF'
    uint32_t version = 1;
    uint32_t fbits_le = buildRes.fbits;
    uint64_t seed_le = buildRes.seed;
    uint64_t count = (uint64_t)keys.size();
    uint64_t arrlen = (uint64_t)buildRes.arrayLength;
    xf.write((const char*)&magic, sizeof(magic));
    xf.write((const char*)&version, sizeof(version));
    xf.write((const char*)&fbits_le, sizeof(fbits_le));
    xf.write((const char*)&seed_le, sizeof(seed_le));
    xf.write((const char*)&count, sizeof(count));
    xf.write((const char*)&arrlen, sizeof(arrlen));
    if(fbits <= 8) {
        for(uint64_t i=0;i<arrlen;i++) {
            uint8_t b = (uint8_t)(buildRes.fp[(size_t)i] & 0xFFu);
            xf.write((const char*)&b, 1);
        }
    } else {
        uint16_t mask = (uint16_t)((fbits >= 16) ? 0xFFFFu : ((1u<<fbits)-1u));
        for(uint64_t i=0;i<arrlen;i++) {
            uint16_t w = (uint16_t)(buildRes.fp[(size_t)i] & mask);
            xf.write((const char*)&w, sizeof(uint16_t));
        }
    }
    xf.close();
    Logger::log(LogLevel::Info, "Wrote XOR filter to '"+outFile+"' (fbits="+util::format((int)fbits)+", seed="+util::format((uint64_t)buildRes.seed)+", len="+util::format((uint64_t)arrlen)+")");

    return 0;
}