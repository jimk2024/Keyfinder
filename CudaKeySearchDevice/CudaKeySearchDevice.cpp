#include "CudaKeySearchDevice.h"
#include "Logger.h"
#include "util.h"
#include "cudabridge.h"
#include "AddressUtil.h"

void CudaKeySearchDevice::cudaCall(cudaError_t err)
{
	if(err) {
		throw KeySearchException(cudaGetErrorString(err));
	}
}

CudaKeySearchDevice::CudaKeySearchDevice(int device, int threads, int pointsPerThread, int blocks)
{
	_device = device;
	_threads = threads;
	_pointsPerThread = pointsPerThread;
	_blocks = blocks;
	_iterations = 0;
}

void CudaKeySearchDevice::init(const secp256k1::uint256 &start, int compression, const secp256k1::uint256 &stride)
{
	cudaCall(cudaSetDevice(_device));

	// Use cudaUtil API to fetch device name
	_deviceName = cuda::getDeviceInfo(_device).name;

	_compression = compression;

	_stride = stride;

	// Init list
	cudaCall(_resultList.init(sizeof(CudaDeviceResult), 16));

	_startExponent = start;

	// Upload table
	generateStartingPoints();

	_iterations = 0;
}

void CudaKeySearchDevice::generateStartingPoints()
{
	std::vector<secp256k1::uint256> exponents;

	secp256k1::uint256 privKey = _startExponent;

	// We need one starting private key per (block, thread, idx) triplet.
	// CudaDeviceKeys::init indexes privateKeys using: index = idx * (blocks*threads) + threadId
	// Therefore the vector must have size blocks*threads*pointsPerThread and be ordered sequentially.
	int total = _threads * _blocks * _pointsPerThread;
	for(int i = 0; i < total; i++) {
		exponents.push_back(privKey);
		privKey = secp256k1::addModN(privKey, _stride);
	}

	_deviceKeys.init(_blocks, _threads, _pointsPerThread, exponents);
}

void CudaKeySearchDevice::setTargets(const std::set<KeySearchTarget> &targets)
{
	_targets.clear();

	for(auto i = targets.begin(); i != targets.end(); i++) {
		_targets.push_back(i->value);
	}

	cudaCall(_targetLookup.setTargets(_targets));
}

void CudaKeySearchDevice::doStep()
{
	// Clear the result list and run one iteration
	_resultList.clear();

	// Always use the double-add kernel variant via bridge selector
	bool useDouble = true;
	callKeyFinderKernel(_blocks, _threads, _pointsPerThread, useDouble, _compression);

	_iterations++;

	// Copy results from device
	getResultsInternal();

	// When using explicit targets, reload bloom/constant tables after hits removed.
	if(!_xorEnabled && _results.size() > 0) {
		cudaCall(_targetLookup.setTargets(_targets));
	}
}

uint64_t CudaKeySearchDevice::keysPerStep()
{
	return (uint64_t)_pointsPerThread * _threads * _blocks;
}

std::string CudaKeySearchDevice::getDeviceName()
{
	return _deviceName;
}

void CudaKeySearchDevice::getMemoryInfo(uint64_t &freeMem, uint64_t &totalMem)
{
	cudaCall(cudaMemGetInfo(&freeMem, &totalMem));
}

void CudaKeySearchDevice::removeTargetFromList(const unsigned int hash[5])
{
	for(unsigned int i = 0; i < _targets.size(); i++) {
		bool x = true;
		for(int j = 0; j < 5; j++) {
			if(_targets[i].h[j] != hash[j]) {
				x = false;
				break;
			}
		}
		if(x) {
			_targets.erase(_targets.begin() + i);
			break;
		}
	}
}

bool CudaKeySearchDevice::isTargetInList(const unsigned int hash[5])
{
	for(unsigned int i = 0; i < _targets.size(); i++) {
		bool x = true;
		for(int j = 0; j < 5; j++) {
			if(_targets[i].h[j] != hash[j]) {
				x = false;
				break;
			}
		}
		if(x) {
			return true;
		}
	}
	return false;
}

uint32_t CudaKeySearchDevice::getPrivateKeyOffset(int thread, int block, int idx)
{
	return (uint32_t)(thread + (block * _threads) + (idx * (_threads * _blocks)));
}

void CudaKeySearchDevice::getResultsInternal()
{
	unsigned int count = _resultList.size();

	if(count == 0) {
		return;
	}

	unsigned char *ptr = new unsigned char[count * sizeof(CudaDeviceResult)];

	unsigned int actualCount = _resultList.read(ptr, count);

	CudaDeviceResult *rPtr = (CudaDeviceResult *)ptr;

	for(unsigned int i = 0; i < actualCount; i++) {
		CudaDeviceResult *r = rPtr + i;

		if(!_xorEnabled) {
			if(!isTargetInList(r->digest)) {
				continue;
			}
		}

		secp256k1::uint256 offset = (secp256k1::uint256((uint64_t)_blocks * _threads * _pointsPerThread * _iterations) + secp256k1::uint256(getPrivateKeyOffset(r->thread, r->block, r->idx))) * _stride;
		secp256k1::uint256 privateKey = secp256k1::addModN(_startExponent, offset);

		KeySearchResult minerResult;
		minerResult.publicKey = secp256k1::ecpoint(secp256k1::uint256(r->x, secp256k1::uint256::BigEndian), secp256k1::uint256(r->y, secp256k1::uint256::BigEndian));
		minerResult.privateKey = privateKey;
		minerResult.compressed = r->compressed;
		minerResult.toggled = r->toggled;
		memcpy(minerResult.hash, r->digest, 20);

        if(verifyKey(privateKey, minerResult.publicKey, minerResult.hash, minerResult.compressed, r->toggled)) {
            _results.push_back(minerResult);
        }
	}

	delete[] ptr;

	// When using explicit targets, reload bloom/constant tables after hits removed.
	if(!_xorEnabled && actualCount) {
		cudaCall(_targetLookup.setTargets(_targets));
	}
}

// Verify a private key produces the public key and hash
bool CudaKeySearchDevice::verifyKey(const secp256k1::uint256 &privateKey, const secp256k1::ecpoint &publicKey, const unsigned int hash[5], bool compressed, bool toggled)
{
	secp256k1::ecpoint g = secp256k1::G();

	secp256k1::ecpoint p = secp256k1::multiplyPoint(privateKey, g);

	if(!(p == publicKey)) {
		return false;
	}

	unsigned int xWords[8];
	unsigned int yWords[8];

	p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
	p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

	unsigned int digest[5];
	if(compressed) {
		if(!toggled) {
			Hash::hashPublicKeyCompressed(xWords, yWords, digest);
		} else {
			// flip parity when verifying toggled compressed hit
			Hash::hashPublicKeyCompressedFlipped(xWords, yWords, digest);
		}
	} else {
		Hash::hashPublicKey(xWords, yWords, digest);
	}

	for(int i = 0; i < 5; i++) {
		if(digest[i] != hash[i]) {
			return false;
		}
	}

	return true;
}

size_t CudaKeySearchDevice::getResults(std::vector<KeySearchResult> &resultsOut)
{
	for(int i = 0; i < _results.size(); i++) {
		resultsOut.push_back(_results[i]);
	}
	_results.clear();

	return resultsOut.size();
}

secp256k1::uint256 CudaKeySearchDevice::getNextKey()
{
	uint64_t totalPoints = (uint64_t)_pointsPerThread * _threads * _blocks;

	return _startExponent + secp256k1::uint256(totalPoints) * _iterations * _stride;
}

// Rebase current cached public keys by deltaPriv*G and shift the base start exponent accordingly
void CudaKeySearchDevice::rebaseTo(const secp256k1::uint256 &deltaPriv)
{
	if(deltaPriv.isZero()) {
		return; // nothing to do
	}

	// Compute rebase point = deltaPriv * G
	secp256k1::ecpoint g = secp256k1::G();
	secp256k1::ecpoint d = secp256k1::multiplyPoint(deltaPriv, g);

	// Push the constant rebase point to device and launch the rebase kernel to add it to all cached points
	cudaCall(setRebasePoint(d.x, d.y));
	callRebaseKernel(_blocks, _threads, _pointsPerThread);

	// Adjust the logical starting exponent so that getNextKey() reflects the rebased window base
	_startExponent = secp256k1::addModN(_startExponent, deltaPriv);

	// Clear any pending device results to avoid cross-window leakage
	_resultList.clear();
}