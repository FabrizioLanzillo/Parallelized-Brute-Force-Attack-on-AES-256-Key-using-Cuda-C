 #include <stdlib.h>
#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <fstream>
#include <math.h> 
#include <sstream>
#include <time.h>
#include <chrono>
#include <thread>
#include <mutex>

using namespace std;

#define NUM_THREADS 16
#define AES_BLOCK_LENGTH 16 
#define IV_BYTES_LENGTH 16
#define AES_KEY_BYTES_LENGTH 32
#define AES_KEY_EXPANDED_BYTES_LENGTH 240
#define NUMBER_OF_ROUNDS 14
#define COLUMN_NUMBER_STATE_MATRIX 4
#define ROW_NUMBER_STATE_MATRIX 4
#define AES_KEY_WORD_LENGTH 8
#define PLAINTEXT_LENGTH 448
#define CIPHERTEXT_LENGTH 448
#define DEBUG false
#define plaintext_file "./../../files/text_files/plaintext.txt"
#define ciphertext_file "./../../files/text_files/ciphertext.txt"

//Brute Force configuration
#define BASE_NUMBER 2

#define xtimes(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))

//Needed to multiply numbers in Galois-Field (2^8) 
#define mul(x,y)                                          \
    ( ((y & 1) * x) ^                                     \
    ((y >> 1 & 1) * xtimes(x)) ^                          \
    ((y >> 2 & 1) * xtimes(xtimes(x))) ^                  \
    ((y >> 3 & 1) * xtimes(xtimes(xtimes(x)))) ^          \
    ((y >> 4 & 1) * xtimes(xtimes(xtimes(xtimes(x))))))   \


#define getSBoxValue(num) (AES_Sbox[(num)])
#define getSBoxInvert(num) (AES_inverse_Sbox[(num)])

typedef uint8_t state_t[ROW_NUMBER_STATE_MATRIX][COLUMN_NUMBER_STATE_MATRIX];

struct bf_data{
    unsigned char* plaintext; 
    unsigned char* ciphertext; 
    int num_bits_to_hack; 
    unsigned char* hacked_key; 
    unsigned char* key; 
    unsigned char* iv_aes;
    uintmax_t starting_point;
    uintmax_t step;
    uintmax_t num_of_threads;
};

mutex s;


/*********************************************** DATA STRUCTURES **************************************************/

/***
 * struct that cointains the key and the iv for each round, since we use aes cbc, 
 * starting from the decryption of the second ciphertext block 
 * the value of iv is replaced with the ciphertext of the previous block 
 * when we decrypt the current block 
 */
struct AES_round_secret{

    uint8_t expanded_key[AES_KEY_EXPANDED_BYTES_LENGTH];
    uint8_t round_iv[IV_BYTES_LENGTH];
};

/***
 * The S-box is necessary for the expand_key_decryption function of the aes
 */
const uint8_t AES_Sbox[256] = {

    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

/***
 * The inverted S-box is s S-box performed in reverse necessary for the decryption of the aes
 */
const uint8_t AES_inverse_Sbox[256] = {

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

/***
 * const_matrix contains the power of x in the GF(2^8) 
*/
const uint8_t const_matrix[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/***
 * simmetric key for aes decryption
 * 85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC
 */
unsigned char key_aes[AES_KEY_BYTES_LENGTH] = {
    0x85, 0x92, 0x6b, 0xe3, 0xda, 0x73, 0x6f, 0x47, 0x54, 0x93, 0xc4, 0x92, 0x76, 0xed, 0x17, 0xd4,
    0x18, 0xa5, 0x5a, 0x2c, 0xfd, 0x07, 0x7d, 0x12, 0x15, 0xed, 0x25, 0x1c, 0x4a, 0x57, 0xd8, 0xec
};

/***
 * IV for aes decryption
 * D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96
 */
unsigned char iv_aes[IV_BYTES_LENGTH] = {
    0xd8, 0x59, 0x6b, 0x73, 0x9e, 0xfa, 0xc0, 0x46, 0x0e, 0x86, 0x1f, 0x9b, 0x77, 0x90, 0xf9, 0x96
};

/***************************************** INITIALIZATION FUNCTION *****************************************/

/**
 * function that expand the key from the simmetric aes key of 256 bit 
 * the key now is 240 byte long
 * 
 * @param rounded_key is the key for the initial round, after the expansion
 * @param key is the simmetric aes key
 */
void expand_key_decryption(uint8_t* rounded_key, const uint8_t* key){

    unsigned int j, k;
    uint8_t temporary[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (unsigned int i = 0; i < AES_KEY_WORD_LENGTH; i++){

        rounded_key[(i * 4) + 0] = key[(i * 4) + 0];
        rounded_key[(i * 4) + 1] = key[(i * 4) + 1];
        rounded_key[(i * 4) + 2] = key[(i * 4) + 2];
        rounded_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (unsigned int i = AES_KEY_WORD_LENGTH; i < COLUMN_NUMBER_STATE_MATRIX * (NUMBER_OF_ROUNDS + 1); i++){
        
        k = (i - 1) * 4;
        temporary[0] = rounded_key[k + 0];
        temporary[1] = rounded_key[k + 1];
        temporary[2] = rounded_key[k + 2];
        temporary[3] = rounded_key[k + 3];


        if (i % AES_KEY_WORD_LENGTH == 0){

            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()

            const uint8_t u8tmp = temporary[0];
            temporary[0] = temporary[1];
            temporary[1] = temporary[2];
            temporary[2] = temporary[3];
            temporary[3] = u8tmp;

            // SubWord() is a function that takes a four-byte input word and 
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
        
            temporary[0] = getSBoxValue(temporary[0]);
            temporary[1] = getSBoxValue(temporary[1]);
            temporary[2] = getSBoxValue(temporary[2]);
            temporary[3] = getSBoxValue(temporary[3]);


            temporary[0] = temporary[0] ^ const_matrix[i / AES_KEY_WORD_LENGTH];
        }

        if (i % AES_KEY_WORD_LENGTH == 4){

            // Function Subword()
            temporary[0] = getSBoxValue(temporary[0]);
            temporary[1] = getSBoxValue(temporary[1]);
            temporary[2] = getSBoxValue(temporary[2]);
            temporary[3] = getSBoxValue(temporary[3]);

        }
        
        j = i * 4; k = (i - AES_KEY_WORD_LENGTH) * 4;
        rounded_key[j + 0] = rounded_key[k + 0] ^ temporary[0];
        rounded_key[j + 1] = rounded_key[k + 1] ^ temporary[1];
        rounded_key[j + 2] = rounded_key[k + 2] ^ temporary[2];
        rounded_key[j + 3] = rounded_key[k + 3] ^ temporary[3];
    }
}

/**
 * this function initialize the struct AES_round_secret that contains the key and the iv for each round
 * 
 * @param rs is the pointer to the struct
 * @param key is the simmetric aes key
 * @param iv is the iv for the aes-cbc
 */
void initialize_AES_round_secret(struct AES_round_secret* rs, const uint8_t* key, const uint8_t* iv){
    
    expand_key_decryption(rs->expanded_key, key);
    memcpy(rs->round_iv, iv, IV_BYTES_LENGTH);
}

/***************************************** PHASE OPERATIONS AES DECRYPTION ****************************************/

/**
 * every byte of the state matrix is put in xor with the byte of the local key, taken from the expanded key
 * every local key is generated from the expanded key, in particular every local key is 16 byte long
 * and the add_round_key function is called 15 times.
 * 
 * @param round is the number of the current round
 * @param state is the state matrix which element are trasnformed through all the phases
 * @param expanded_key is the the expanded key
 */
void add_round_key(uint8_t round, state_t* state, const uint8_t* expanded_key){
    
    for (unsigned int i = 0; i < ROW_NUMBER_STATE_MATRIX; i++){
        for (unsigned int j = 0; j < COLUMN_NUMBER_STATE_MATRIX; j++){
            (*state)[i][j] ^= expanded_key[(round * COLUMN_NUMBER_STATE_MATRIX * 4) + (i * COLUMN_NUMBER_STATE_MATRIX) + j];
        }
    }
}

/**
 * shifts the rows in the state matrix to the left according to the number of the relative row
 * this function with inv_mix_columns_decryption ensure the confusion and diffusion criterion 
 * 
 * @param state is the state matrix
 */
void inv_shift_rows_decryption(state_t* state){
    
    uint8_t temporary;

    // Rotate first row 1 columns to right  
    temporary = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temporary;

    // Rotate second row 2 columns to right 
    temporary = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temporary;

    temporary = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temporary;

    // Rotate third row 3 columns to right
    temporary = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temporary;
}

/**
 * Non-linear operation that replace where evry byte of the state matrix is replaced 
 * using the Inverse S-Box 
 * 
 * @param state is the state matrix 
 */
void sub_bytes_decryption(state_t* state){

    for (unsigned int i = 0; i < ROW_NUMBER_STATE_MATRIX; i++){
        for (unsigned int j = 0; j < COLUMN_NUMBER_STATE_MATRIX; j++){

            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
        }
    }
}

/**
 * in this function the four bytes of a column are combined using an invertible linear transformation
 * this function with inv_shift_rows_decryption ensure the confusion and diffusion criterion 
 * 
 * @param state is the state matrix
 */
void inv_mix_columns_decryption(state_t* state){
    
    uint8_t a, b, c, d;

    for (unsigned int i = 0; i < 4; i++){
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = mul(a, 0x0e) ^ mul(b, 0x0b) ^ mul(c, 0x0d) ^ mul(d, 0x09);
        (*state)[i][1] = mul(a, 0x09) ^ mul(b, 0x0e) ^ mul(c, 0x0b) ^ mul(d, 0x0d);
        (*state)[i][2] = mul(a, 0x0d) ^ mul(b, 0x09) ^ mul(c, 0x0e) ^ mul(d, 0x0b);
        (*state)[i][3] = mul(a, 0x0b) ^ mul(b, 0x0d) ^ mul(c, 0x09) ^ mul(d, 0x0e);
    }
}

/************************************************ CBC DECRYPTION **************************************************/
/**
 * this function put in xor the byte of the iv with the block decrypted after all the aes decryption phases 
 * the iv for the first block is the aes iv, and then after the first block is the previous ciphertext block
 * 
 * @param state_matrix is the state matrix is the result of the aes encryption algorithm after all the phases
 * @param iv is long 16 bytes and is put in xor with the state matrix
 */
void xor_with_iv(uint8_t* state_matrix, const uint8_t* iv){

    for (unsigned int i = 0; i < AES_BLOCK_LENGTH; i++){

        state_matrix[i] ^= iv[i];
    }
}

/********************************************* AES DECRYPTION *****************************************************/

/**
 * function that decrypts the single aes block through the NUMBER_OF_ROUNDS aes number of rounds
 * 
 * @param state_matrix is the state matrix is the result of the aes encryption algorithm after all the phases
 * @param expanded_key is the the expanded key
 */
void decryption_rounds(state_t* state_matrix, const uint8_t* expanded_key){

    uint8_t current_round = NUMBER_OF_ROUNDS;

    // Add the initial key to the state matrix before the first round of decryption
    add_round_key(NUMBER_OF_ROUNDS, state_matrix, expanded_key);

    current_round--;

    // Perform the NUMBER_OF_ROUNDS rounds of decryption
    // the decryption process is the same for the first NUMBER_OF_ROUNDS-1 rounds
    // the last round of decryption does not require inverse column mixing

    /******************** NUMBER_OF_ROUNDS - 1 ***************************/
    for (; current_round > 0; current_round--){

        inv_shift_rows_decryption(state_matrix);
        sub_bytes_decryption(state_matrix);
        add_round_key(current_round, state_matrix, expanded_key);
        inv_mix_columns_decryption(state_matrix);
    }

    /************************** LAST ROUND *******************************/
    inv_shift_rows_decryption(state_matrix);
    sub_bytes_decryption(state_matrix);
    add_round_key(current_round, state_matrix, expanded_key);
}

/**
 * function that read text from file
 * 
 * @param file in input to read
 */
string read_data_from_file(string file, int length) {

    fstream getFile;
    string str;
    string file_contents;
    getFile.open(file, ios::in | ios::binary);

    while (getline(getFile, str) && length != 0) {
        file_contents += str;
        file_contents.push_back('\n');
        length--;
    }

    file_contents.pop_back();

    getFile.close();

    return file_contents;
}

/**
 * function that convert hex characters into a string
 * 
 * @param hex is a string parameter with the hexs character
 */
string hexToASCII(string hex){

    // initialize the ASCII code string as empty.
    string ascii = "";
    for (size_t i = 0; i < hex.length(); i += 2)    
    {
        // extract two characters from hex string
        string part = hex.substr(i, 2);
 
        // change it into base 16 and
        // typecast as the character
        char ch = stoul(part, nullptr, 16);
        // add this char to final ASCII string
        ascii += ch;
    }
    return ascii;
}

/**
 * function that implement the AES_CBC algorithm and that call the single aes operation
 * 
 * @param state_matrix is the state matrix which element are trasnformed through all the phases
 */
 void AES_CBC_decrypt(unsigned char* state_matrix, AES_round_secret* AES_secret) {

    
    uint8_t storeNextIv[AES_BLOCK_LENGTH];

    //Initialize the context
    initialize_AES_round_secret(AES_secret, key_aes, iv_aes);
    
    
    // decrypt for each aes block
    for (int i = 0; i < CIPHERTEXT_LENGTH; i += AES_BLOCK_LENGTH){

        memcpy(storeNextIv, state_matrix, AES_BLOCK_LENGTH);
        // use of AES 256
        decryption_rounds((state_t*)state_matrix, AES_secret->expanded_key);
        // use of the Cipher Block Chaining (CBC)
        xor_with_iv(state_matrix, AES_secret->round_iv);
        memcpy(AES_secret->round_iv, storeNextIv, AES_BLOCK_LENGTH);
        state_matrix += AES_BLOCK_LENGTH;
    }

    return;
}
 
/**
 * function that implement the AES_CBC algorithm and that call the single aes operation
 * 
 * @param state_matrix is the state matrix which element are trasnformed through all the phases
 */
void AES_CBC_decrypt_BF(unsigned char* state_matrix, AES_round_secret* AES_secret) {


    uint8_t storeNextIv[AES_BLOCK_LENGTH];

    //Initialize the context
    initialize_AES_round_secret(AES_secret, key_aes, iv_aes);

    
    // decrypt for one aes block
    memcpy(storeNextIv, state_matrix, AES_BLOCK_LENGTH);
    // use of AES 256
    decryption_rounds((state_t*)state_matrix, AES_secret->expanded_key);
    // use of the Cipher Block Chaining (CBC)
    xor_with_iv(state_matrix, AES_secret->round_iv);
    memcpy(AES_secret->round_iv, storeNextIv, AES_BLOCK_LENGTH);
    state_matrix += AES_BLOCK_LENGTH;

    return;
}

/** Function that perform the bruteforcing of AES-256
 * hacked_key: key with an amount of bits that we suppose to know
 * knowed_plaintext: original plaintext needed to compare the one obtained from decryption
 * ciphertext: the cipher to decrypt
 * plaintext: variable on which we have to return the decrypted PT (with padding)
 * plaintext_no_pad: variable on which we have to return the decrypted PT (without padding)
 * plainlen: length of the expected plaintext
 * iv: variable needed to perform decryption, usually sent in clear with ciphertext size
 */
void* decryption_brute_force(void* data){
    //Structure initialization
    struct bf_data *my_data;
    my_data = (struct bf_data *) data;

    printf("starting_point: %ld\n",my_data->starting_point);
    printf("step: %ld\n",my_data->step);

	unsigned char ascii_character;
	//Calculate the number of cycles before the cycle to optimize
	uintmax_t index = pow (BASE_NUMBER, my_data->num_bits_to_hack);

    //Allocate the local copy for the ciphertext
    unsigned char* ciphertext = my_data->ciphertext;

    //Allocate the local copy for the hacked key
    unsigned char hacked_key[AES_KEY_BYTES_LENGTH];
	memset(hacked_key,0,AES_KEY_BYTES_LENGTH);
    memcpy(hacked_key, my_data->hacked_key, AES_KEY_BYTES_LENGTH);

	// array containg de character of the key that has to be hacked (i.e. 20 bits = 3 Bytes)
	unsigned char bytes_to_hack [my_data->num_bits_to_hack/8 + 1];

	unsigned char ct_temp[PLAINTEXT_LENGTH];
	memset(ct_temp, 0, PLAINTEXT_LENGTH);
	memcpy(ct_temp, ciphertext, PLAINTEXT_LENGTH);

	/* ---------------------------------------------------------------------------------------------------------------------------------------- */
	//This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
	uint8_t tmp, rem_bits = my_data->num_bits_to_hack % 8;

	//Use the shift to clean up the part that we don't know of the last byte (like 4 bits in case of 20 bits to discover)
	if(my_data->num_bits_to_hack % 8 != 0){
		//With 20 bits -> 2
		bytes_to_hack[my_data->num_bits_to_hack / 8 ] = hacked_key[AES_KEY_BYTES_LENGTH - 1 - (my_data->num_bits_to_hack / 8)] >> rem_bits;
		tmp = bytes_to_hack[my_data->num_bits_to_hack / 8] << rem_bits;
	}

	/* ---------------------------------------------------------------------------------------------------------------------------------------- */
	/* START THE BRUTEFORCE - INITIATE TIME COUNTING */
	auto begin = chrono::high_resolution_clock::now();
	for(uintmax_t i = my_data->starting_point; i < (my_data->starting_point + my_data->step) ; i++){	//2^NUM_BITES_TO_HACK Cycles

		AES_round_secret new_ctx;
		//Get the index address in order to extract and manage one byte at a time
		uint8_t *pointer = (uint8_t*)&i;

		//cout<< "-------------------------------------------- Attempt #"<<i+1<<" ----------------------------------------------"<<endl;
		
		// clean of the array (only the bytes that have to be completely cleaned, i.e. last two bytes)
		memset(bytes_to_hack,0,my_data->num_bits_to_hack/8);

		memset(my_data->plaintext,0,PLAINTEXT_LENGTH);

		uint8_t numcycles = my_data->num_bits_to_hack/8 + 1;

		// First copy the bytes that are whole
		for(int j=0;j <  numcycles; j++){
			//This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
			if(my_data->num_bits_to_hack % 8 != 0 && j == my_data->num_bits_to_hack/8){
				//The addition of unsigned number perform the append correctly until the value inside pointer[j] overcome the capacity of the bit to be copied, 
				//but this will never happen since we stop the cycle before it happen
				bytes_to_hack[j] = tmp + pointer[j];
				continue;
			}
			ascii_character = char(i >> (8*j));
			sprintf((char*)&bytes_to_hack[j],"%c",ascii_character);
		}

		// we assemble the key with the new character, cycle needed to order the bytes in the correct way, otherwise it will result in a swap of the
		// cycled bytes
		for (int j = 0; j < (my_data->num_bits_to_hack/8) + 1; j++){
			if(my_data->num_bits_to_hack % 8 != 0){
				memcpy(&hacked_key[AES_KEY_BYTES_LENGTH - j - 1], &bytes_to_hack[j], 1);
			}
			else if(j < (my_data->num_bits_to_hack/8)){
				memcpy(&hacked_key[AES_KEY_BYTES_LENGTH - j -1], &bytes_to_hack[j],  1);
			}
		}

		//Initialize the context with the new key and the iv
        initialize_AES_round_secret(&new_ctx, hacked_key, my_data->iv_aes);

		AES_CBC_decrypt_BF(ct_temp, &new_ctx);
		
        if(!memcmp(hacked_key, my_data->key,AES_KEY_BYTES_LENGTH)){
			
			auto end = chrono::high_resolution_clock::now();
			auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - begin);

            
            printf("-- ---- key found! ---- --\n\n");
			printf("# of Bits: %d, # of Attempt: %ld, Elapsed Time in ms: %ld\n", my_data->num_bits_to_hack, i, elapsed.count());

			char filename[60];
            sprintf(filename,"./../results/sequential_result_multithread_%d_%ld.txt",my_data->num_bits_to_hack, my_data->num_of_threads);
            if(DEBUG)
			    printf("%s\n\n",filename);

			
			ofstream outdata;
			outdata.open(filename, std::ios_base::app); // opens the file
			if( !outdata ) { // file couldn't be opened
				cerr << "Error: file could not be opened" << endl;
				return NULL;
			}
            outdata << elapsed.count()<< endl;
			outdata.close();
			cout << "Save results on file" << endl;

            s.unlock();
			return NULL;
		}
        else{
			memcpy(ct_temp,ciphertext,PLAINTEXT_LENGTH);
			continue;
		}
	}
	cout<< "************************** CYCLE ENDED WITHOUT FINDING THE KEY *********************"<<endl;
	return NULL;
}

int main(int argc, char **argv) {

    /************************************** GET THE PLAINTEXT AND CIPHERTEXT ******************************************/
    unsigned char decrypted_plaintext[CIPHERTEXT_LENGTH];
    memset(decrypted_plaintext, 0, CIPHERTEXT_LENGTH);

    // allocate of the plaintext space and read it from file
    unsigned char plaintext[PLAINTEXT_LENGTH];
	memset(plaintext,0,PLAINTEXT_LENGTH);
	strncpy((char*)plaintext, (char*)read_data_from_file(plaintext_file, PLAINTEXT_LENGTH).c_str(),PLAINTEXT_LENGTH);

    // allocate of the ciphertext space and read it from file
    unsigned char ciphertext[CIPHERTEXT_LENGTH];
	memset(ciphertext,0,CIPHERTEXT_LENGTH);

    string file_contents = hexToASCII(read_data_from_file(ciphertext_file, CIPHERTEXT_LENGTH));
	// convert to unsigned char
	for(int i=0; i<CIPHERTEXT_LENGTH; i++){
		ciphertext[i] = file_contents[i];
	}

    if(DEBUG)
        printf("Ciphertext:\n%s\n\n", ciphertext);

    //TEST COMPLETED - PROCEED TO EXECUTE THE BRUTEFORCING
	printf("--------------------------------- PROCEED WITH BRUTEFORCING ----------------------------------------------\n");
    int num_bits_to_hack = atoi(argv[1]);
    int num_of_threads = atoi(argv[2]);

    //Copy the amount of known bits, ex. if 20 bits has to be discovered we copy all the key except the last two bytes, the last for bits will be removed using the shift later
    unsigned char hacked_key[AES_KEY_BYTES_LENGTH];
	memset(hacked_key,0,AES_KEY_BYTES_LENGTH);
	memcpy(hacked_key, key_aes, AES_KEY_BYTES_LENGTH);

	if(DEBUG){
		printf("DEBUG: ** Start Bruteforcing **\n");
	}

    /**************************************** ADDITIONS FOR MULTI THREADING ************************************************/
    pthread_t threads[num_of_threads];
    struct bf_data td [num_of_threads];
    int rc;
    uintmax_t index = pow (BASE_NUMBER, num_bits_to_hack);
    uintmax_t step = index/num_of_threads;

    for(int i = 0; i < num_of_threads; i++){
        //Structure initialization
        td[i].ciphertext = ciphertext;
        td[i].hacked_key = hacked_key;
        td[i].iv_aes = iv_aes;
        td[i].key = key_aes;
        td[i].num_bits_to_hack = num_bits_to_hack;
        td[i].plaintext = plaintext;
        td[i].starting_point = step*i;
        td[i].step = step;
        td[i].num_of_threads = num_of_threads;
        if(DEBUG)
            printf("Starting point for thread %d is: %lu, using step: %lu\n", i , td[i].starting_point, td[i].step);

        rc = pthread_create(&threads[i], NULL, decryption_brute_force, (void*)&td[i]);

        if (rc){
            cout << "Error:unable to create thread," << rc << endl;
            exit(-1);
        }
    }
    s.lock();
    s.lock();
    for(int i = 0; i < num_of_threads; i++){
        pthread_cancel(threads[i]);
    }

    /************************************************** END ADDITIONS ******************************************************/

	if(DEBUG){
		printf("DEBUG: Brute Force completed and key obtained:\n");
		for(int i=0;i<32;i++)
			printf("%d|", hacked_key[i]);
		printf("\n");
	}

    printf("----------------------------------------------------------------------------------------------------------\n");

    printf("Decryption...\n");    
    
    // allocate AES_secret
    AES_round_secret AES_secret;
    initialize_AES_round_secret(&AES_secret, hacked_key, iv_aes);

    AES_CBC_decrypt(ciphertext, &AES_secret);
    printf("Result:%-10.448s\n", ciphertext);
	
    return 0;
}