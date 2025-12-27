#ifndef _HASH_LOOKUP_HOST_H
#define _HASH_LOOKUP_HOST_H

#include <cuda_runtime.h>

class CudaHashLookup {

private:
	unsigned int *_bloomFilterPtr;
	// XOR filter device storage
	unsigned short *_xorFpPtr = NULL; // fingerprint array in device global memory (16-bit each)
	unsigned int _xorArrLen = 0;
	unsigned short _xorMask = 0;
	unsigned long long _xorSeed = 0ULL;

	cudaError_t setTargetBloomFilter(const std::vector<struct hash160> &targets);
	
	cudaError_t setTargetConstantMemory(const std::vector<struct hash160> &targets);
	
	unsigned int getOptimalBloomFilterBits(double p, size_t n);

	void cleanup();

	void initializeBloomFilter(const std::vector<struct hash160> &targets, unsigned int *filter, unsigned int mask);
	
	void initializeBloomFilter64(const std::vector<struct hash160> &targets, unsigned int *filter, unsigned long long mask);

	// XOR filter upload helper
	cudaError_t setXorFilter(const unsigned short *fp, unsigned int arrlen, unsigned short mask, unsigned long long seed);

public:

	CudaHashLookup()
	{
		_bloomFilterPtr = NULL;
	}

	~CudaHashLookup()
	{
		cleanup();
	}

	cudaError_t setTargets(const std::vector<struct hash160> &targets);
	// Public entry to enable XOR filter mode
	cudaError_t enableXorFilter(const unsigned short *fp, unsigned int arrlen, unsigned short mask, unsigned long long seed);
};

#endif