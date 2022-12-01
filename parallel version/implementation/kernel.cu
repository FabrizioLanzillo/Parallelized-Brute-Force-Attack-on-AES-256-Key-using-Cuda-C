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
#define PLAINTEXT_LENGTH 445
#define CIPHERTEXT_LENGTH 448
#define DEBUG true

#define CUDADEBUG(cudaError)      \
    if (cudaError != cudaSuccess) \
        DEBUG(cudaGetErrorString(cudaError));

//Multiply x times
#define xtimes(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))

//Needed to multiply numbers in Galois-Field (2^8) 
#define mul(x,y)                                          \
    ( ((y & 1) * x) ^                                     \
    ((y >> 1 & 1) * xtimes(x)) ^                          \
    ((y >> 2 & 1) * xtimes(xtimes(x))) ^                  \
    ((y >> 3 & 1) * xtimes(xtimes(xtimes(x)))) ^          \
    ((y >> 4 & 1) * xtimes(xtimes(xtimes(xtimes(x))))))   \

const string plaintext_file = "./../../files/text_files/plaintext.txt";
const string ciphertext_file = "./../../files/text_files/ciphertext.txt";
const string key_aes_file = "./../../files/secret_files/key_aes.txt";
const string iv_file = "./../../files/secret_files/iv.txt";

__device__ uint8_t AES_inverse_Sbox[256] ={
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

//Constant matrix
//const_mat[i] contains the value given by the power of x (i-1), the power of x in the field GF(2^8) (x is represented as {02})
__device__ __host__ const uint8_t const_mat[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


 struct AES_round_secret{

    unsigned char round_key[AES_KEY_EXPANDED_BYTES_LENGTH];
    unsigned char round_iv[IV_BYTES_LENGTH];
};

/** Expand_Key: Perform the expansion of the key needed in AES
 * unsigned char sbox[]: Replacement table
 * const uint8_t* key: Original key
 * uint8_t* rounded_key: result of the expansion
*/
__device__ __host__ void expand_key_decryption(const uint8_t AES_inverse_Sbox[], const uint8_t* key, uint8_t* rounded_key) {
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


__device__ AES_round_secret * initialize_AES_round_secret(uint8_t* inverse_sbox, struct AES_round_secret* rs, unsigned char* key, unsigned char* iv){
  
    expand_key_decryption(inverse_sbox, rs->round_key, key);
    memcpy (rs->round_iv, iv, IV_BYTES_LENGTH); 

    return rs;
}


// 85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC
__device__ unsigned char key[AES_KEY_BYTES_LENGTH] = { 0x85, 0x92, 0x6b, 0xe3, 0xda, 0x73, 0x6f, 0x47, 0x54, 0x93, 0xc4, 0x92, 0x76, 0xed, 0x17,
                    0xd4, 0x18, 0xa5, 0x5a, 0x2c, 0xfd, 0x07, 0x7d, 0x12, 0x15, 0xed, 0x25, 0x1c, 0x4a, 0x57, 0xd8, 0xec};

// D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96
__device__ unsigned char iv[IV_BYTES_LENGTH] = { 0xd8, 0x59, 0x6b, 0x73, 0x9e, 0xfa, 0xc0, 0x46, 0x0e, 0x86, 0x1f, 0x9b, 0x77, 0x90, 0xf9, 0x96};




/** SubBytes: Non-linear replacement of all bytes that are replaced according to a specific table
 * unsigned char state[]: Bytes to be substituted
 * unsigned char sbox[]: Replacement table
*/
__device__  void sub_bytes_decryption(uint8_t* state, const uint8_t AES_inverse_Sbox[]) {
    
    unsigned int i, j;
    char state_byte_value;
    //Two cycles of 4 iteration for a max of 16 bytes (the block length)
    for (i = 0; i < 4; ++i) {                                   
        for (j = 0; j < 4; ++j)
            state_byte_value = state[j * 4 + i];
            state[j * 4 + i] = AES_inverse_Sbox[state_byte_value];
    }
}


/** MixColumns_Inv: takes the four bytes of each column and combines them using an invertible linear transformation.
 *  Used in conjunction, ShiftRows and MixColumns ensure that the criterion of confusion and diffusion is respected
 *
 *  unsigned char state: Bytes to be inverted
*/
__device__ void inv_mix_columns_decryption(uint8_t* state) {
    uint8_t vect[4];

    for (uint8_t i = 0; i < 4; i++) {

        for (uint8_t j = 0; j < 4; j++){
            vect[j] = state[i * 4 + j];
        }
            

        state[i * 4 + 0] = mul(vect[0], 0x0e) ^ mul(vect[1], 0x0b) ^ mul(vect[2], 0x0d) ^ mul(vect[3], 0x09);
        state[i * 4 + 1] = mul(vect[0], 0x09) ^ mul(vect[1], 0x0e) ^ mul(vect[2], 0x0b) ^ mul(vect[3], 0x0d);
        state[i * 4 + 2] = mul(vect[0], 0x0d) ^ mul(vect[1], 0x09) ^ mul(vect[2], 0x0e) ^ mul(vect[3], 0x0b);
        state[i * 4 + 3] = mul(vect[0], 0x0b) ^ mul(vect[1], 0x0d) ^ mul(vect[2], 0x09) ^ mul(vect[3], 0x0e);
    }
}


/** ShiftRows: shifts the rows in the state matrix to the left
 *  Each row unless the 1st one is moved by a different offset of columns
*/ 
__device__ void inv_shift_rows_decryption(uint8_t* state) {
    uint8_t tmp;
    
    tmp = state[3 * 4 + 1];
    state[3*4 + 1] = state[2 * 4 + 1];
    state[2 * 4 + 1] = state[1 * 4 + 1];
    state[1 * 4 + 1] = state[0 * 4 + 1];
    state[0 * 4 + 1] = tmp;


    tmp = state[0 * 4 + 2];
    state[0 * 4 + 2] = state[2 * 4 + 2];
    state[2 * 4 + 2] = tmp;

    tmp = state[1 * 4 + 2];
    state[1 * 4 + 2] = state[3 * 4 + 2];
    state[3 * 4 + 2] = tmp;

    // shift row4 by 3
    tmp = state[0 * 4 + 3];
    state[0 * 4 + 3] = state[1 * 4 + 3];
    state[1 * 4 + 3] = state[2 * 4 + 3];
    state[2 * 4 + 3] = state[3 * 4 + 3];
    state[3 * 4 + 3] = tmp;
}

/* AddRoundKey:  Add the round key to the state matrix, using XOR operation
*/
__device__ void add_round_key(uint8_t round, uint8_t *state, const uint8_t* roundKey) {
    for (uint8_t i = 0; i < 4; ++i) {
        for (uint8_t j = 0; j < 4; ++j) {
            state[i * 4 + j] ^= roundKey[(round * 4 * 4) + (i * 4) + j];
        }
    }
}

/*__device__ void create_state_matrix(unsigned char *ciphertext){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state_matrix[i][j] = ciphertext[i * 4 + j];
        }
    }
}*/

__device__ void xor_with_iv(uint8_t* state_matrix, uint8_t* iv) {
    uint8_t i,j;
    for (i = 0; i < 4; ++i) { // The block in AES is always 128bit no matter the key size
        for(j = 0; j < 4; ++j)
        state_matrix[i * 4 + j] ^= iv[i * 4 + j];
    }
}

// TODO:
//  creare una funzione __host__ __device__ per decifrare il cipher
__device__ void decryption(const uint8_t*AES_inverse_Sbox, uint8_t *state_matrix, struct AES_round_secret *rs) {

    uint8_t current_round = NUMBER_OF_ROUNDS;

    // Add the initial key to the state matrix before the first round of decryption
    add_round_key(NUMBER_OF_ROUNDS, state_matrix, rs->round_key);

    current_round--;

    // Perform Nr rounds of decryption, the decryption process is the same for the first Nr-1 rounds, and the last round of decryption does not require inverse column mixing
    for (; current_round > 0; current_round--){

        inv_shift_rows_decryption(state_matrix);
        sub_bytes_decryption(state_matrix, AES_inverse_Sbox);
        add_round_key(current_round, state_matrix, rs->round_key);
        inv_mix_columns_decryption(state_matrix);
    }

    inv_shift_rows_decryption(state_matrix);
    sub_bytes_decryption(state_matrix, AES_inverse_Sbox);
    add_round_key(current_round, state_matrix, rs->round_key);
    xor_with_iv(state_matrix, rs->round_iv);
    
}

//  creare una funzione che viene invocata dal kernel __global__ per decrifrare il cipher che chiama la funzione sopra
// in cui gestiamo x 
__global__ void kernel_decrypt(const unsigned char* device_inverse_sbox, uint8_t* device_chipertext, size_t message_num_block){

    struct AES_round_secret AES_rs;

    struct AES_round_secret *rs = initialize_AES_round_secret(AES_inverse_Sbox, &AES_rs, key, iv);

    //create_state_matrix(device_chipertext);
    //int x = threadIdx.x + blockDim.x * blockIdx.x;
    //if(x < message_num_block){
        decryption(device_inverse_sbox, device_chipertext, rs);
    //}

    printf("[DEVICE]: Risultato pari a: %s\n",device_chipertext);
}

/** Perfrom a read from a file
 * file: name of the file to read
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

    unsigned char* decrypted_plaintext = (unsigned char*)malloc(CIPHERTEXT_LENGTH);
    //host receive data: device => host
    memset(decrypted_plaintext, 0, CIPHERTEXT_LENGTH);

    //Allocating pt space
    unsigned char* plaintext = (unsigned char*)malloc(PLAINTEXT_LENGTH);
    if (!plaintext) {
        cerr << "ERROR: plaintext space allocation went wrong" << endl;
        return -1;
    }
    memset(plaintext, 0, PLAINTEXT_LENGTH);
    strcpy((char*)plaintext, (char*)read_data_from_file(plaintext_file).c_str());

    if (DEBUG) {
        printf("DEBUG: The Plaintext is: %s\n", plaintext);
    }

     //Allocating pt space
    unsigned char ciphertext [448] = {
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
        0xC9, 0xE6, 0x6F, 0xD9, 0x0A, 0x98, 0xA7, 0x63, 0x68, 0x47, 0x29, 0x31, 0xD2, 0x42, 0xDC, 0xFD
    };

    printf("CT:%s\n", ciphertext);


    // declaration of the device variable
    uint8_t* device_chipertext;
    uint8_t* device_inverse_sbox;
    uint8_t* device_plaintext;
    
    printf("\n\nMemory allocation on device -->");

    cudaError_t cudaerr;

    // allocate device memory
    cudaerr = cudaMalloc((void**)&device_chipertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMalloc((void**)&device_plaintext, sizeof(uint8_t) * PLAINTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMalloc((void**)&device_inverse_sbox, sizeof(uint8_t) * 256);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }


    printf("\t completed!\n");

    // host send data: host => device

    // TODO
    // host send data: host => device

    printf("copying data on device -->");

    cudaerr = cudaMemcpy(device_chipertext, ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMemcpy(device_plaintext, plaintext, sizeof(uint8_t) * PLAINTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMemcpy(device_inverse_sbox, AES_inverse_Sbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }


    printf("\t completed! \n");

    printf("launch the kernel\n");

    // AES_BLOCKLEN = 16
    // si calcolano i blocchi totali del messaggio 
    size_t message_num_block = CIPHERTEXT_LENGTH / AES_BLOCK_LENGTH;
    // maxThreadsPerBlock is the maximum number of threads per block per la gpu con cui si lavora
    size_t thread_per_block = min(message_num_block, (size_t)prop.maxThreadsPerBlock);
    // qui si sta trovando il numero dei blocchi ma non so bene che sta facendo 
    size_t device_setted_block_number = (message_num_block + thread_per_block - 1) / thread_per_block;

    kernel_decrypt <<<1, 1>>> (device_inverse_sbox, device_chipertext, message_num_block);
    cudaerr = cudaDeviceSynchronize();
    if (cudaerr != cudaSuccess){
       printf("kernel launch failed with error \"%s\".\n",cudaGetErrorString(cudaerr));
    }
    
    // host receive data: device => host
    cudaMemcpy(decrypted_plaintext, device_chipertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyDeviceToHost);

    
    string s((char*)decrypted_plaintext);
    printf("[HOST]:Risultato con lunghezza %lu pari a: %s\n",s.length(), s);

    // release device memory
    cudaFree(device_chipertext);
    cudaFree(device_plaintext);
    cudaFree(device_inverse_sbox);
}