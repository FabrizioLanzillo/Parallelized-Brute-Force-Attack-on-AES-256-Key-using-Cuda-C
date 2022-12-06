#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <cuda.h>
#include "header.cuh"

using namespace std;

/******************************************* PARALLEL DEVICE DECRYPTION ******************************************/

__device__ void AES_CBC_decrypt(uint8_t *state_matrix) {


    AES_round_secret AES_secret;
    uint8_t storeNextIv[AES_BLOCK_LENGTH];

    //Initialize the context
    initialize_AES_round_secret(&AES_secret, key_aes, iv_aes);

    struct AES_round_secret* rs = &AES_secret;
    
    // decrypt for each aes block
    for (int i = 0; i < CIPHERTEXT_LENGTH; i += AES_BLOCK_LENGTH){

        memcpy(storeNextIv, state_matrix, AES_BLOCK_LENGTH);
        // use of AES 256
        decryption_rounds((state_t*)state_matrix, rs->expanded_key);
        // use of the Cipher Block Chaining (CBC)
        xor_with_iv(state_matrix, rs->round_iv);
        memcpy(rs->round_iv, storeNextIv, AES_BLOCK_LENGTH);
        state_matrix += AES_BLOCK_LENGTH;
    }

    return;
}

__global__ void kernel_decrypt(uint8_t* device_chipertext){

    //create_state_matrix(device_chipertext);
    //int x = threadIdx.x + blockDim.x * blockIdx.x;
    //if(x < message_num_block){
    AES_CBC_decrypt(device_chipertext);
    //}

    printf("[DEVICE]: Risultato pari a: %s\n",device_chipertext);
}


/**
 * function that read from file
 * 
 * @param file in input to read
 */
__host__ string read_data_from_file(string file) {

    fstream getFile;
    string str;
    string file_contents;
    getFile.open(file, ios::in | ios::binary);

    while (getline(getFile, str)) {
        file_contents += str;
        file_contents.push_back('\n');
    }

    file_contents.pop_back();

    getFile.close();

    return file_contents;
}

int main() {


    /******************************************** SET GPU PROPERTIES **************************************************/

    // inizialize of a struct with all the gpu properties 
    cudaDeviceProp prop;                   
    // we define the field of the previous struct with the properties of the specified device
    // prop is the struct and the second paramether is the device number
    cudaGetDeviceProperties(&prop, 0);  

    /************************************** GET THE PLAINTEXT AND CIPHERTEXT ******************************************/

    unsigned char* decrypted_plaintext = (unsigned char*)malloc(CIPHERTEXT_LENGTH);
    //host receive data: device => host
    memset(decrypted_plaintext, 0, CIPHERTEXT_LENGTH);

    //Allocating pt space
    unsigned char plaintext[448] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.  ";

    unsigned char ciphertext[CIPHERTEXT_LENGTH] = {
    0x73, 0xF8, 0x42, 0x09, 0x89, 0x89, 0xD4, 0x8F, 0x95, 0xFA, 0x1C, 0x88, 0xF6, 0x98, 0x6C, 0x49,
    0x10, 0x35, 0xCE, 0x48, 0x4B, 0x41, 0x41, 0xFE, 0xFF, 0x06, 0x40, 0x0E, 0x0A, 0xCF, 0x2C, 0x28,
    0x29, 0xD2, 0x9C, 0xCD, 0xC0, 0xED, 0x6C, 0x06, 0x9D, 0x99, 0xE1, 0x60, 0x85, 0xF3, 0xEA, 0x19,
    0xA2, 0x9A, 0x15, 0x1D, 0x59, 0x07, 0xB7, 0xC4, 0x5A, 0xB2, 0xE9, 0xF1, 0x56, 0xF2, 0xDF, 0xBE,
    0xF6, 0x94, 0xD4, 0xFC, 0xF9, 0xE6, 0x1E, 0xCE, 0xB5, 0x4E, 0x3B, 0x1D, 0xEA, 0x9B, 0x7C, 0x53,
    0xB9, 0xA8, 0x64, 0x88, 0xBC, 0xF8, 0x78, 0xE8, 0x0A, 0xDE, 0x48, 0x54, 0x7E, 0xE2, 0x35, 0x98,
    0xC5, 0xAB, 0x99, 0x32, 0x83, 0x51, 0xF8, 0x4F, 0xF6, 0xA4, 0x72, 0xAC, 0xF0, 0x7E, 0xF8, 0x3D,
    0x32, 0x95, 0x06, 0x7E, 0x7A, 0xD8, 0xD2, 0xF1, 0xC8, 0x3A, 0x85, 0x3D, 0x2A, 0xB6, 0x29, 0x68,
    0x37, 0x3B, 0x6A, 0x18, 0x8E, 0x97, 0xAB, 0x2E, 0x2C, 0x62, 0x9E, 0x14, 0x6C, 0x10, 0x78, 0xA9,
    0x87, 0x02, 0x18, 0xFD, 0x12, 0xE7, 0x3D, 0xCB, 0xB5, 0x25, 0xE0, 0x23, 0xDC, 0xEF, 0x8A, 0xA8,
    0x49, 0x2E, 0x5E, 0x46, 0xF2, 0xFC, 0x8A, 0x39, 0xEF, 0x2C, 0x3D, 0x97, 0xD1, 0xA7, 0x0B, 0x49,
    0xC2, 0x83, 0xC7, 0x60, 0x93, 0x5C, 0x8E, 0x8C, 0x0E, 0xCE, 0x63, 0xEF, 0x6C, 0xEB, 0x54, 0x32,
    0x76, 0xFA, 0x87, 0xA4, 0xB5, 0x48, 0x48, 0x83, 0x8A, 0xFF, 0x4B, 0xE6, 0x0D, 0x45, 0x1A, 0x70,
    0x67, 0xEA, 0x8A, 0x26, 0xFB, 0xD5, 0x4F, 0x39, 0xE5, 0x64, 0xCD, 0xD2, 0xD8, 0xA9, 0x07, 0xE5,
    0xC9, 0xC3, 0xB8, 0x2F, 0xDA, 0xBF, 0xD2, 0x07, 0x69, 0x58, 0x9A, 0x07, 0x4B, 0x76, 0x16, 0x92,
    0xC0, 0x7B, 0x0C, 0x6F, 0x04, 0xE2, 0xD5, 0x1D, 0x67, 0xE4, 0xF7, 0xDA, 0x45, 0xD8, 0x66, 0xC3,
    0x96, 0xF3, 0xF8, 0x4E, 0x31, 0xA0, 0x2F, 0x28, 0xD5, 0xF8, 0x1C, 0x7F, 0x17, 0x98, 0x5C, 0xD5,
    0x71, 0x26, 0x87, 0x44, 0x08, 0x24, 0x6C, 0x9E, 0x0E, 0xD6, 0xD8, 0x35, 0x22, 0x55, 0xF6, 0xA6,
    0x3A, 0x4B, 0xDA, 0xB2, 0xAE, 0xEB, 0xBE, 0xCB, 0x15, 0x82, 0xD8, 0xCD, 0xB7, 0xCC, 0x6D, 0xB8,
    0xF1, 0x89, 0x71, 0x81, 0x7C, 0xDF, 0x13, 0x3E, 0xCC, 0x87, 0x53, 0x3D, 0x1B, 0xA3, 0x1B, 0x18,
    0xE7, 0x20, 0xFF, 0x71, 0xEA, 0x51, 0xC1, 0x51, 0x69, 0xF1, 0x42, 0x94, 0xA9, 0x00, 0x30, 0xD9,
    0xEA, 0x14, 0x79, 0x5E, 0xB2, 0x90, 0x84, 0x2D, 0xEB, 0xC2, 0xF3, 0x88, 0x88, 0x69, 0x8D, 0x5F,
    0x67, 0x50, 0xD8, 0x2B, 0x46, 0xF9, 0x09, 0x38, 0x5F, 0x66, 0x47, 0x29, 0x28, 0x63, 0x9D, 0xC9,
    0x01, 0x7B, 0xDA, 0xBE, 0xE6, 0x9E, 0x8A, 0x18, 0x32, 0xB9, 0x49, 0xA7, 0xAE, 0x9D, 0x30, 0xE1,
    0x64, 0xEE, 0x71, 0x5F, 0x89, 0xFB, 0x8F, 0xFF, 0xBA, 0x19, 0x76, 0xC8, 0xB6, 0xFA, 0x46, 0xBB,
    0x0F, 0x60, 0xE5, 0x85, 0x3B, 0x98, 0x83, 0x6C, 0x3B, 0x3D, 0x88, 0x29, 0x1E, 0x30, 0x40, 0x35,
    0xE6, 0xD4, 0xEB, 0xEC, 0x2C, 0x88, 0xE4, 0x9A, 0x9C, 0x7E, 0xFC, 0x9B, 0x82, 0x44, 0x9F, 0x1F,
    0xA8, 0x29, 0xE4, 0xA2, 0x43, 0x5A, 0x5C, 0x1A, 0x71, 0xFA, 0x7A, 0x34, 0x77, 0x9E, 0x69, 0xA2
    };

    printf("CT:%s\n", ciphertext);

    /************************************* ALLOCATE AND COPY ON THE DEVICE ********************************************/

    // declaration of the device variable
    uint8_t* device_chipertext;
    uint8_t* device_plaintext;
    
    printf("\n\nMemory allocation on device -->");

    cudaError_t cudaerr;

    // allocate device memory
    cudaerr = cudaMalloc((void**)&device_chipertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMalloc((void**)&device_plaintext, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }

    printf("\t completed!\n");

    printf("copying data on device -->");

    cudaerr = cudaMemcpy(device_chipertext, ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMemcpy(device_plaintext, plaintext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }

    printf("\t completed! \n");

    /********************************************* LAUNCH OF THE KERNEL ***********************************************/

    printf("launch the kernel\n");

    // AES_BLOCKLEN = 16
    // si calcolano i blocchi totali del messaggio 
    size_t message_num_block = 150000 / AES_BLOCK_LENGTH;
    // maxThreadsPerBlock is the maximum number of threads per block per la gpu con cui si lavora
    size_t thread_per_block = min(message_num_block, (size_t)prop.maxThreadsPerBlock);
    // qui si sta trovando il numero dei blocchi ma non so bene che sta facendo 
    printf("message_num_block: %lu\n", message_num_block);
    printf("(size_t)prop.maxThreadsPerBlock: %lu\n", (size_t)prop.maxThreadsPerBlock);
    size_t device_setted_block_number = (message_num_block + thread_per_block - 1) / thread_per_block;

    printf("device_setted_block_number: %lu\n", device_setted_block_number);
    printf("thread_per_block: %lu\n", thread_per_block);

    kernel_decrypt <<<1, 2>>> (device_chipertext);
    cudaerr = cudaDeviceSynchronize();
    if (cudaerr != cudaSuccess){
       printf("kernel launch failed with error \"%s\".\n",cudaGetErrorString(cudaerr));
    }
    
    // host receive data: device => host
    cudaMemcpy(decrypted_plaintext, device_chipertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyDeviceToHost);

    
    string s((char*)decrypted_plaintext);
    printf("[HOST]:Risultato con lunghezza %lu pari a: %s\n",s.length(), s.c_str());

    /**************************************** RELEASE OF THE DEVICE ALLOCATION ****************************************/
    // release device memory
    cudaFree(device_chipertext);
    cudaFree(device_plaintext);
}