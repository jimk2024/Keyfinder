#include "cudabridge.h"


__global__ void keyFinderKernel(int points, int compression);
__global__ void keyFinderKernelWithDouble(int points, int compression);
// New rebase kernel
__global__ void rebaseKernel(int points);

void callKeyFinderKernel(int blocks, int threads, int points, bool useDouble, int compression)
{
	if(useDouble) {
		keyFinderKernelWithDouble <<<blocks, threads >>>(points, compression);
	} else {
		keyFinderKernel <<<blocks, threads>>> (points, compression);
	}
	waitForKernel();
}


void waitForKernel()
{
    // Check for kernel launch error
    cudaError_t err = cudaGetLastError();

    if(err != cudaSuccess) {
        throw cuda::CudaException(err);
    }
 
    // Wait for kernel to complete
    err = cudaDeviceSynchronize();
	fflush(stdout);
	if(err != cudaSuccess) {
		throw cuda::CudaException(err);
	}
}

// Declarations implemented in CudaKeySearchDevice.cu
cudaError_t setIncrementorPoint(const secp256k1::uint256 &x, const secp256k1::uint256 &y);

// New: set rebase point constants on device
cudaError_t setRebasePoint(const secp256k1::uint256 &x, const secp256k1::uint256 &y);

// New: launch rebase kernel
void callRebaseKernel(int blocks, int threads, int points)
{
    rebaseKernel<<<blocks, threads>>>(points);
    waitForKernel();
}