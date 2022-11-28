#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <cuda.h>

using namespace std;

#define AES_BLOCK_LENGTH 16
#define IV_BYTES_LENGTH 16
#define AES_KEY_BYTES_LENGTH 32
#define AES_KEY_EXPANDED_BYTES_LENGTH 240
#define NUMBER_OF_ROUNDS 14
#define CHIPHERTEXT_LENGTH 448

//Multiply x times
#define xtimes(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))

//Needed to multiply numbers in Galois-Field (2^8) 
#define mul(x,y)                                          \
    ( ((y & 1) * x) ^                                     \
    ((y >> 1 & 1) * xtimes(x)) ^                          \
    ((y >> 2 & 1) * xtimes(xtimes(x))) ^                  \
    ((y >> 3 & 1) * xtimes(xtimes(xtimes(x)))) ^          \
    ((y >> 4 & 1) * xtimes(xtimes(xtimes(xtimes(x))))))   \

static const uint8_t AES_inverse_Sbox[256] ={
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

uint8_t state_round_matrix[4][4];

// 85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC
uint8_t key[AES_KEY_BYTES_LENGTH] = { 0x85, 0x92, 0x6b, 0xe3, 0xda, 0x73, 0x6f, 0x47, 0x54, 0x93, 0xc4, 0x92, 0x76, 0xed, 0x17,
                    0xd4, 0x18, 0xa5, 0x5a, 0x2c, 0xfd, 0x07, 0x7d, 0x12, 0x15, 0xed, 0x25, 0x1c, 0x4a, 0x57, 0xd8, 0xec};

// D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96
uint8_t iv[IV_BYTES_LENGTH] = { 0xd8, 0x59, 0x6b, 0x73, 0x9e, 0xfa, 0xc0, 0x46, 0x0e, 0x86, 0x1f, 0x9b, 0x77, 0x90, 0xf9, 0x96};


uint8_t round_key[AES_KEY_EXPANDED_BYTES_LENGTH];

uint8_t round_iv[IV_BYTES_LENGTH];


//Constant matrix
//const_mat[i] contains the value given by the power of x (i-1), the power of x in the field GF(2^8) (x is represented as {02})
static const uint8_t const_mat[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


/** SubBytes: Non-linear replacement of all bytes that are replaced according to a specific table
 * unsigned char state[]: Bytes to be substituted
 * unsigned char sbox[]: Replacement table
*/
__device__  void sub_bytes_decryption(uint8_t* state[], const uint8_t AES_inverse_Sbox[]) {
    
    unsigned int i, j;
    char state_byte_value;
    //Two cycles of 4 iteration for a max of 16 bytes (the block length)
    for (i = 0; i < 4; ++i) {                                   
        for (j = 0; j < 4; ++j)
            state_byte_value = state[j][i];
            state[j][i] = AES_inverse_Sbox[state_byte_value];
    }
}

/** Expand_Key: Perform the expansion of the key needed in AES
 * unsigned char sbox[]: Replacement table
 * const uint8_t* key: Original key
 * uint8_t* rounded_key: result of the expansion
*/
void expand_key_decryption(const uint8_t AES_inverse_Sbox[], const uint8_t* key, uint8_t* rounded_key) {
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
            tmp[0] = AES_inverse_Sbox[tmp[0]];
            tmp[1] = AES_inverse_Sbox[tmp[1]];
            tmp[2] = AES_inverse_Sbox[tmp[2]];
            tmp[3] = AES_inverse_Sbox[tmp[3]];

            tmp[0] = tmp[0] ^ const_mat[i / 8];

        }

        // Extra expansion, needed only for 256 bit key
        if (i % 8 == 4) {
            tmp[0] = AES_inverse_Sbox[tmp[0]];
            tmp[1] = AES_inverse_Sbox[tmp[1]];
            tmp[2] = AES_inverse_Sbox[tmp[2]];
            tmp[3] = AES_inverse_Sbox[tmp[3]];
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
__device__ void inv_mix_columns_decryption(uint8_t* state[]) {
    uint8_t vect[4];

    for (uint8_t i = 0; i < 4; i++) {

        for (uint8_t j = 0; j < 4; j++){
            vect[j] = state[i][j];
        }
            

        state[i][0] = mul(vect[0], 0x0e) ^ mul(vect[1], 0x0b) ^ mul(vect[2], 0x0d) ^ mul(vect[3], 0x09);
        state[i][1] = mul(vect[0], 0x09) ^ mul(vect[1], 0x0e) ^ mul(vect[2], 0x0b) ^ mul(vect[3], 0x0d);
        state[i][2] = mul(vect[0], 0x0d) ^ mul(vect[1], 0x09) ^ mul(vect[2], 0x0e) ^ mul(vect[3], 0x0b);
        state[i][3] = mul(vect[0], 0x0b) ^ mul(vect[1], 0x0d) ^ mul(vect[2], 0x09) ^ mul(vect[3], 0x0e);
    }
}


/** ShiftRows: shifts the rows in the state matrix to the left
 *  Each row unless the 1st one is moved by a different offset of columns
*/ 
__device__ void inv_shift_rows_decryption(uint8_t* state[]) {
    uint8_t tmp;
    
    tmp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = tmp;


    tmp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = tmp;

    tmp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = tmp;

    // shift row4 by 3
    tmp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = tmp;
}

/* AddRoundKey:  Add the round key to the state matrix, using XOR operation
*/
__device__ void add_round_key(uint8_t round, uint8_t *state[], const uint8_t* roundKey) {
    for (uint8_t i = 0; i < 4; ++i) {
        for (uint8_t j = 0; j < 4; ++j) {
            state[i][j] ^= roundKey[(round * 4 * 4) + (i * 4) + j];
        }
    }
}

// function that is called by the device
void initialize_AES_secret_data(const uint8_t* AES_inverse_Sbox, uint8_t* round_key, uint8_t* round_iv, uint8_t* key, uint8_t* iv) {

    expand_key_decryption(AES_inverse_Sbox, key, round_key);
    memcpy(round_iv, iv, IV_BYTES_LENGTH);

}

// function that is called by the device
void initialize_AES_secret_data(const uint8_t* AES_inverse_Sbox, uint8_t* round_key, uint8_t* round_iv,  uint8_t* key) {

    expand_key_decryption(AES_inverse_Sbox, key, round_key);

}


// TODO:
//  creare una funzione __host__ __device__ per decifrare il cipher
__device__ void decryption(const uint8_t*AES_inverse_Sbox, uint8_t *state_matrix[], const uint8_t* round_key) {

    uint8_t current_round = NUMBER_OF_ROUNDS;

    // Add the initial key to the state matrix before the first round of decryption
    add_round_key(NUMBER_OF_ROUNDS, state_matrix, round_key);

    current_round--;

    // Perform Nr rounds of decryption, the decryption process is the same for the first Nr-1 rounds, and the last round of decryption does not require inverse column mixing
    for (; current_round > 0; current_round--){

        inv_shift_rows_decryption(state_matrix);
        sub_bytes_decryption(state_matrix, AES_inverse_Sbox);
        add_round_key(current_round, state_matrix, round_key);
        inv_mix_columns_decryption(state_matrix);
    }

    inv_shift_rows_decryption(state_matrix);
    sub_bytes_decryption(state_matrix, AES_inverse_Sbox);
    add_round_key(current_round, state_matrix, round_key);

}

//  creare una funzione che viene invocata dal kernel __global__ per decrifrare il cipher che chiama la funzione sopra
// in cui gestiamo x 
__global__ void kernel_decrypt(const unsigned char* device_inverse_sbox, uint8_t* round_key, uint8_t* round_iv, uint8_t* device_chipertext, size_t message_num_block){

    int x = threadIdx.x + blockDim.x * blockIdx.x;
    if(x < message_num_block){
        decryption(device_inverse_sbox, (unsigned char**)device_chipertext + x, round_key);
    }
}


int main() {

    // qui instanzia una struttura di cuda in cui ci sono le properties della gpu
    cudaDeviceProp prop;                    //cudaDeviceProp of an object
    // qui invece serve per definire tutti i campi della struttura instanziata prima con le caratteristiche della gpu corrente
    /*
    Parameters
    prop
        - Properties for the specified device 
    device
        - Device number to get properties for
    */
    cudaGetDeviceProperties(&prop, 0);  //The second parameter is that gpu

    uint8_t* buf;

    // declaration of the device variable
    uint8_t* device_chipertext;
    uint8_t* device_inverse_sbox;
    uint8_t* device_round_key;
    uint8_t* device_round_iv;
    

    // allocate device memory
    cudaMalloc((void**)&device_chipertext, sizeof(uint8_t) * CHIPHERTEXT_LENGTH);
    cudaMalloc((void**)&device_round_key, sizeof(uint8_t) * AES_KEY_BYTES_LENGTH);
    cudaMalloc((void**)&device_round_iv, sizeof(uint8_t) * IV_BYTES_LENGTH);
    cudaMalloc((void**)&device_inverse_sbox, sizeof(uint8_t) * 256);
    // host send data: host => device

    // TODO
    // host send data: host => device
    cudaMemcpy(device_chipertext, buf, sizeof(uint8_t) * CHIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    cudaMemcpy(device_round_key, device_round_key, sizeof(uint8_t) * AES_KEY_BYTES_LENGTH, cudaMemcpyHostToDevice);
    cudaMemcpy(device_round_iv, device_round_iv, sizeof(uint8_t) * IV_BYTES_LENGTH, cudaMemcpyHostToDevice);
    cudaMemcpy(device_inverse_sbox, AES_inverse_Sbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);

    // AES_BLOCKLEN = 16
    // si calcolano i blocchi totali del messaggio 
    size_t message_num_block = CHIPHERTEXT_LENGTH / AES_BLOCK_LENGTH;
    // maxThreadsPerBlock is the maximum number of threads per block per la gpu con cui si lavora
    size_t thread_per_block = min(message_num_block, (size_t)prop.maxThreadsPerBlock);
    // qui si sta trovando il numero dei blocchi ma non so bene che sta facendo 
    size_t device_setted_block_number = (message_num_block + thread_per_block - 1) / thread_per_block;

    kernel_decrypt <<<device_setted_block_number, thread_per_block>>> (device_inverse_sbox, device_round_key, device_round_iv, device_chipertext, message_num_block);
    // host receive data: device => host
    cudaMemcpy(buf, device_chipertext, sizeof(uint8_t) * CHIPHERTEXT_LENGTH, cudaMemcpyDeviceToHost);
    // release device memory
    cudaFree(device_chipertext);
    cudaFree(device_round_key);
    cudaFree(device_round_iv);
    cudaFree(device_inverse_sbox);
}