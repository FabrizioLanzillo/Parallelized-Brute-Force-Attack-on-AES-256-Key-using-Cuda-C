#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cuda.h>

cudaError_t addWithCuda(int *c, const int *a, const int *b, unsigned int size);

__global__ void addKernel(int *c, const int *a, const int *b)
{
    int i = threadIdx.x;
    c[i] = a[i] + b[i];
}

unsigned char AES_Sbox[] =
{   /*0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, /*0*/
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, /*1*/
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, /*2*/
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, /*3*/
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, /*4*/
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, /*5*/
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, /*6*/
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, /*7*/
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, /*8*/
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, /*9*/
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, /*a*/
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, /*b*/
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, /*c*/
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, /*d*/
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, /*e*/
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  /*f*/
};

//Constant matrix
//ConstMat[i] contains the value given by the power of x (i-1), the power of x in the field GF(2^8) (x is represented as {02})
static const uint8_t ConstMat[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


/** FEDE **/
//Multiply x times
#define xtimes(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))

//Needed to multiply numbers in Galois-Field (2^8) 
#define mul(x,y)                                        \
    (((y & 1) * x) ^                                    \
    ((y >> 1 & 1) * xtimes(x)) ^                        \
    ((y >> 2 & 1) * xtimes(xtimes(x))) ^                \
    ((y >> 3 & 1) * xtimes(xtimes(xtimes(x)))) ^        \
    ((y >> 4 & 1) * xtimes(xtimes(xtimes(xtimes(x)))))  \

/** SubBytes: Non-linear replacement of all bytes that are replaced according to a specific table
 * unsigned char state[]: Bytes to be substituted
 * unsigned char sbox[]: Replacement table
*/
__device__ void SubBytes(unsigned char state[], unsigned char sbox[]) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j)
            state[j * 4 + i] = sbox[state[j * 4 + i]]
    }
}

/** Expand_Key: Perform the expansion of the key needed in AES
 * unsigned char sbox[]: Replacement table
 * const uint8_t* key: Original key
 * uint8_t* rounded_key: result of the expansion
*/
__device__ void Expand_Key(unsigned char sbox[], const uint8_t* key, uint8_t* rounded_key) {
    //Cycle for each 32-bit word, for the first round the key is rounded starting from the original key
    for (unsigned i = 0; i < 8; i++)
        for (unsigned j = 0; j < 4; j++)
            rounded_key[(i * 4) + j] = key[(i * 4) + j];

    // The other keys are derived from the previous rounding session
    unsigned index;
    uint8_t tmp[4];
    for (unsigned i = 8; i < 4 * (15); i++) {
        index = (i - 1) * 4;
        tmp[0] = rounded_key[index + 0];
        tmp[1] = rounded_key[index + 1];
        tmp[2] = rounded_key[index + 2];
        tmp[3] = rounded_key[index + 3];

        if (i % 8 == 0) {
            //Shift operation
            const uint8_t tmp_ui8 = tmp[0];
            tmp[0] = tmp[1];
            tmp[1] = tmp[2];
            tmp[2] = tmp[3];
            tmp[3] = tmp_ui8;

            //Byte substitution from sbox
            tmp[0] = sbox[tmp[0]];
            tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]];
            tmp[3] = sbox[tmp[3]];

            tmp[0] = tmp[0] ^ ConstMat[i / 8];

        }

        // Extra expansion, needed only for 256 bit key
        if (i % 8 == 4) {
            tmp[0] = sbox[tmp[0]];
            tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]];
            tmp[3] = sbox[tmp[3]];
        }

        unsigned j = i * 4, k = (i - 8) * 4;
        rounded_key[j + 0] = rounded_key[k + 0] ^ tmp[0];
        rounded_key[j + 1] = rounded_key[k + 1] ^ tmp[1];
        rounded_key[j + 2] = rounded_key[k + 2] ^ tmp[2];
        rounded_key[j + 3] = rounded_key[k + 3] ^ tmp[3];

    }

}

/** MixColumns_Inv: takes the four bytes of each column and combines them using an invertible linear transformation.
 *  Used in conjunction, ShiftRows and MixColumns ensure that the criterion of confusion and diffusion is respected
 *
 *  unsigned char state: Bytes to be inverted
*/
__device__ void MixColumns_Inv(unsigned char state[]) {
    uint8_t vect[4];

    for (uint8_t i = 0; i < 4; i++) {

        for (uint8_t j = 0; j < 4; j++)
            vect[j] = state[i][j];

        state[i][0] = mul(vect[0], 0x0e) ^ mul(vect[1], 0x0b) ^ mul(vect[2], 0x0d) ^ mul(vect[3], 0x09);
        state[i][1] = mul(vect[0], 0x09) ^ mul(vect[1], 0x0e) ^ mul(vect[2], 0x0b) ^ mul(vect[3], 0x0d);
        state[i][2] = mul(vect[0], 0x0d) ^ mul(vect[1], 0x09) ^ mul(vect[2], 0x0e) ^ mul(vect[3], 0x0b);
        state[i][3] = mul(vect[0], 0x0b) ^ mul(vect[1], 0x0d) ^ mul(vect[2], 0x09) ^ mul(vect[3], 0x0e);
    }
}

/** TOMMY **/

/** FABRI **/


int main() {


}

/****************************************************************************************************************************/

/* STUFF INSIDE MAIN*/

/*
int main()
{
    const int arraySize = 5;
    const int a[arraySize] = { 1, 2, 3, 4, 5 };
    const int b[arraySize] = { 10, 20, 30, 40, 50 };
    int c[arraySize] = { 0 };

    // Add vectors in parallel.
    cudaError_t cudaStatus = addWithCuda(c, a, b, arraySize);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "addWithCuda failed!");
        return 1;
    }

    printf("{1,2,3,4,5} + {10,20,30,40,50} = {%d,%d,%d,%d,%d}\n",
        c[0], c[1], c[2], c[3], c[4]);

    // cudaDeviceReset must be called before exiting in order for profiling and
    // tracing tools such as Nsight and Visual Profiler to show complete traces.
    cudaStatus = cudaDeviceReset();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaDeviceReset failed!");
        return 1;
    }

    return 0;
}

// Helper function for using CUDA to add vectors in parallel.
cudaError_t addWithCuda(int *c, const int *a, const int *b, unsigned int size)
{
    int *dev_a = 0;
    int *dev_b = 0;
    int *dev_c = 0;
    cudaError_t cudaStatus;

    // Choose which GPU to run on, change this on a multi-GPU system.
    cudaStatus = cudaSetDevice(0);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
        goto Error;
    }

    // Allocate GPU buffers for three vectors (two input, one output)    .
    cudaStatus = cudaMalloc((void**)&dev_c, size * sizeof(int));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    cudaStatus = cudaMalloc((void**)&dev_a, size * sizeof(int));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    cudaStatus = cudaMalloc((void**)&dev_b, size * sizeof(int));
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMalloc failed!");
        goto Error;
    }

    // Copy input vectors from host memory to GPU buffers.
    cudaStatus = cudaMemcpy(dev_a, a, size * sizeof(int), cudaMemcpyHostToDevice);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMemcpy failed!");
        goto Error;
    }

    cudaStatus = cudaMemcpy(dev_b, b, size * sizeof(int), cudaMemcpyHostToDevice);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMemcpy failed!");
        goto Error;
    }

    // Launch a kernel on the GPU with one thread for each element.
    addKernel<<<1, size>>>(dev_c, dev_a, dev_b);

    // Check for any errors launching the kernel
    cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "addKernel launch failed: %s\n", cudaGetErrorString(cudaStatus));
        goto Error;
    }
    
    // cudaDeviceSynchronize waits for the kernel to finish, and returns
    // any errors encountered during the launch.
    cudaStatus = cudaDeviceSynchronize();
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaDeviceSynchronize returned error code %d after launching addKernel!\n", cudaStatus);
        goto Error;
    }

    // Copy output vector from GPU buffer to host memory.
    cudaStatus = cudaMemcpy(c, dev_c, size * sizeof(int), cudaMemcpyDeviceToHost);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaMemcpy failed!");
        goto Error;
    }

Error:
    cudaFree(dev_c);
    cudaFree(dev_a);
    cudaFree(dev_b);
    
    return cudaStatus;
}

*/