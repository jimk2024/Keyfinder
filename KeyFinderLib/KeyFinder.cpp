#include <fstream>
#include <iostream>

#include "KeyFinder.h"
#include "util.h"
#include "AddressUtil.h"

#include "Logger.h"

#include <cctype>

namespace {
    // Return true if all characters are hex digits
    bool isHexStr(const std::string &s) {
        if(s.empty()) return false;
        for(char c : s) {
            if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    // Parse hex string to bytes (big-endian order as written), returns false on error
    bool parseHexToBytes(const std::string &hex, std::vector<unsigned char> &out) {
        if(hex.size() % 2 != 0) return false;
        if(!isHexStr(hex)) return false;
        out.resize(hex.size() / 2);
        auto hexVal = [](char c) -> int {
            if(c >= '0' && c <= '9') return c - '0';
            if(c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if(c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };
        for(size_t i = 0; i < out.size(); ++i) {
            int hi = hexVal(hex[2*i]);
            int lo = hexVal(hex[2*i+1]);
            if(hi < 0 || lo < 0) return false;
            out[i] = static_cast<unsigned char>((hi << 4) | lo);
        }
        return true;
    }

    // Convert 20-byte array to 5 big-endian 32-bit words
    void bytes20ToWords5(const unsigned char *bytes, unsigned int words[5]) {
        for(int i = 0; i < 5; ++i) {
            int o = i * 4;
            words[i] = ((unsigned int)bytes[o] << 24) |
                       ((unsigned int)bytes[o+1] << 16) |
                       ((unsigned int)bytes[o+2] << 8) |
                       ((unsigned int)bytes[o+3]);
        }
    }

    // Convert 32-byte array to 8 big-endian 32-bit words
    void bytes32ToWords8(const unsigned char *bytes, unsigned int words[8]) {
        for(int i = 0; i < 8; ++i) {
            int o = i * 4;
            words[i] = ((unsigned int)bytes[o] << 24) |
                       ((unsigned int)bytes[o+1] << 16) |
                       ((unsigned int)bytes[o+2] << 8) |
                       ((unsigned int)bytes[o+3]);
        }
    }
}


void KeyFinder::defaultResultCallback(KeySearchResult result)
{
	(void)result; // keep default minimal; advanced logging occurs in CLI main resultCallback
}

void KeyFinder::defaultStatusCallback(KeySearchStatus status)
{
	// Do nothing
}

KeyFinder::KeyFinder(const secp256k1::uint256 &startKey, const secp256k1::uint256 &endKey, int compression, KeySearchDevice* device, const secp256k1::uint256 &stride)
{
	_total = 0;
	_statusInterval = 1000;
	_device = device;

	_compression = compression;

    _startKey = startKey;

    _endKey = endKey;

	_statusCallback = NULL;

	_resultCallback = NULL;

    _iterCount = 0;

    _stride = stride;
}

KeyFinder::~KeyFinder()
{
}

void KeyFinder::setTargets(std::vector<std::string> &targets)
{
	if(targets.size() == 0) {
		// In XOR-filter-only mode, allow empty explicit targets without throwing
		if(_ignoreEmptyTargets) {
			_targets.clear();
			_device->setTargets(_targets);
			return;
		}
		throw KeySearchException("Requires at least 1 target");
	}

	_targets.clear();

	// Convert each address from base58 encoded form to a 160-bit integer
	for(unsigned int i = 0; i < targets.size(); i++) {

		if(!Address::verifyAddress(targets[i])) {
			throw KeySearchException("Invalid address '" + targets[i] + "'");
		}

		KeySearchTarget t;

		Base58::toHash160(targets[i], t.value);

		_targets.insert(t);
	}

    _device->setTargets(_targets);
}

void KeyFinder::setTargets(std::string targetsFile)
{
	std::ifstream inFile(targetsFile.c_str());

	if(!inFile.is_open()) {
		Logger::log(LogLevel::Error, "Unable to open '" + targetsFile + "'");
		throw KeySearchException();
	}

	_targets.clear();

	std::string line;
	Logger::log(LogLevel::Info, "Loading targets from '" + targetsFile + "' (supports Base58 address, hash160 hex, or pubkey hex 02/03/04)");
	while(std::getline(inFile, line)) {
		util::removeNewline(line);
        line = util::trim(line);

        if(line.empty()) continue;
        // Allow comments starting with '#'
        if(!line.empty() && line[0] == '#') continue;

        bool added = false;

        // 1) Try Base58 address (legacy behavior)
        if(Address::verifyAddress(line)) {
            KeySearchTarget t;
            Base58::toHash160(line, t.value);
            _targets.insert(t);
            added = true;
        } else {
            // Normalize to lowercase for hex parsing (not strictly required)
            std::string s = util::toLower(line);

            // 2) Try raw hash160: exactly 40 hex chars
            if(s.size() == 40 && isHexStr(s)) {
                std::vector<unsigned char> bytes;
                if(!parseHexToBytes(s, bytes)) {
                    Logger::log(LogLevel::Error, "Invalid hash160 hex '" + line + "'");
                    throw KeySearchException();
                }
                unsigned int h[5];
                bytes20ToWords5(bytes.data(), h);
                KeySearchTarget t(h);
                _targets.insert(t);
                added = true;
            }
            // 3) Try compressed pubkey hex: 33 bytes (66 hex), prefix 02/03
            else if(s.size() == 66 && isHexStr(s) && (s.rfind("02", 0) == 0 || s.rfind("03", 0) == 0)) {
                std::vector<unsigned char> bytes;
                if(!parseHexToBytes(s, bytes) || bytes.size() != 33) {
                    Logger::log(LogLevel::Error, "Invalid compressed pubkey hex '" + line + "'");
                    throw KeySearchException();
                }
                unsigned int xWords[8] = {0};
                unsigned int yWords[8] = {0};
                // x is the remaining 32 bytes
                bytes32ToWords8(&bytes[1], xWords);
                // parity from prefix 0x02 (even) / 0x03 (odd) -> reflect in yWords[7] LSB
                if(bytes[0] == 0x03) {
                    yWords[7] = 1; // odd
                } else {
                    yWords[7] = 0; // even
                }
                unsigned int digest[5] = {0};
                Hash::hashPublicKeyCompressed(xWords, yWords, digest);
                KeySearchTarget t(digest);
                _targets.insert(t);
                added = true;
            }
            // 4) Try uncompressed pubkey hex: 65 bytes (130 hex), prefix 04
            else if(s.size() == 130 && isHexStr(s) && s.rfind("04", 0) == 0) {
                std::vector<unsigned char> bytes;
                if(!parseHexToBytes(s, bytes) || bytes.size() != 65) {
                    Logger::log(LogLevel::Error, "Invalid uncompressed pubkey hex '" + line + "'");
                    throw KeySearchException();
                }
                unsigned int xWords[8] = {0};
                unsigned int yWords[8] = {0};
                bytes32ToWords8(&bytes[1], xWords);
                bytes32ToWords8(&bytes[33], yWords);
                unsigned int digest[5] = {0};
                Hash::hashPublicKey(xWords, yWords, digest);
                KeySearchTarget t(digest);
                _targets.insert(t);
                added = true;
            }
        }

        if(!added) {
            Logger::log(LogLevel::Error, "Invalid target entry '" + line + "' (expected Base58 address, 40-hex hash160, 66-hex 02/03 pubkey, or 130-hex 04 pubkey)");
            throw KeySearchException();
        }
	}
	Logger::log(LogLevel::Info, util::formatThousands(_targets.size()) + " targets loaded ("
		+ util::format("%.1f", (double)(sizeof(KeySearchTarget) * _targets.size()) / (double)(1024 * 1024)) + "MB)");

    _device->setTargets(_targets);
}


void KeyFinder::setResultCallback(void(*callback)(KeySearchResult))
{
	_resultCallback = callback;
}

void KeyFinder::setStatusCallback(void(*callback)(KeySearchStatus))
{
	_statusCallback = callback;
}

void KeyFinder::setStatusInterval(uint64_t interval)
{
	_statusInterval = interval;
}

void KeyFinder::setTargetsOnDevice()
{
	// Set the target in constant memory
	std::vector<struct hash160> targets;

	for(std::set<KeySearchTarget>::iterator i = _targets.begin(); i != _targets.end(); ++i) {
		targets.push_back(hash160((*i).value));
	}

    _device->setTargets(_targets);
}

void KeyFinder::init()
{
	Logger::log(LogLevel::Info, "Initializing " + _device->getDeviceName());

    _device->init(_startKey, _compression, _stride);
}


void KeyFinder::stop()
{
	_running = false;
}

void KeyFinder::removeTargetFromList(const unsigned int hash[5])
{
	KeySearchTarget t(hash);

	_targets.erase(t);
}

bool KeyFinder::isTargetInList(const unsigned int hash[5])
{
	KeySearchTarget t(hash);
	return _targets.find(t) != _targets.end();
}


void KeyFinder::run()
{
    uint64_t pointsPerIteration = _device->keysPerStep();

    _running = true;

    util::Timer timer;

    timer.start();

    uint64_t prevIterCount = 0;

    _totalTime = 0;

    while(_running) {

        _device->doStep();
        _iterCount++;

        // Update status
        uint64_t t = timer.getTime();

        if(t >= _statusInterval) {

            KeySearchStatus info;

            uint64_t count = (_iterCount - prevIterCount) * pointsPerIteration;

            _total += count;

            double seconds = (double)t / 1000.0;

            info.speed = (double)((double)count / seconds) / 1000000.0;

            info.total = _total;

            info.totalTime = _totalTime;

            uint64_t freeMem = 0;

            uint64_t totalMem = 0;

            _device->getMemoryInfo(freeMem, totalMem);

            info.freeMemory = freeMem;
            info.deviceMemory = totalMem;
            info.deviceName = _device->getDeviceName();
            info.targets = _targets.size();
            info.nextKey = getNextKey();

            if(_statusCallback != NULL) {
                _statusCallback(info);
            }

            timer.start();
            prevIterCount = _iterCount;
            _totalTime += t;
        }

        // Fetch any results from the device
        std::vector<KeySearchResult> results;
        if(_device->getResults(results) > 0) {
            for(unsigned int i = 0; i < results.size(); i++) {
                KeySearchResult info;
                info.privateKey = results[i].privateKey;
                info.publicKey = results[i].publicKey;
                info.compressed = results[i].compressed;
                info.toggled = results[i].toggled;
                info.address = Address::fromPublicKey(results[i].publicKey, results[i].compressed);
                if(_resultCallback != NULL) {
                    _resultCallback(info);
                }
            }

            // Remove the hashes that were found
            for(unsigned int i = 0; i < results.size(); i++) {
                removeTargetFromList(results[i].hash);
            }
        }

        // Stop if there are no keys left
        if(!_ignoreEmptyTargets && _targets.size() == 0) {
            Logger::log(LogLevel::Info, "No targets remaining");
            _running = false;
        }

        // Stop if we searched the entire range
        if(_device->getNextKey().cmp(_endKey) >= 0 || _device->getNextKey().cmp(_startKey) < 0) {
            Logger::log(LogLevel::Info, "Reached end of keyspace");
            _running = false;
        }
    }
}

secp256k1::uint256 KeyFinder::getNextKey()
{
    return _device->getNextKey();
}