#define AES_BLOCK_LENGTH 16 
#define IV_BYTES_LENGTH 16
#define AES_KEY_BYTES_LENGTH 32
#define AES_KEY_EXPANDED_BYTES_LENGTH 240
#define NUMBER_OF_ROUNDS 14
#define COLUMN_NUMBER_STATE_MATRIX 4
#define ROW_NUMBER_STATE_MATRIX 4
#define AES_KEY_WORD_LENGTH 8

#define PLAINTEXT_LENGTH 28208
#define CIPHERTEXT_LENGTH 28208

#define NUMBER_BITS_TO_HACK 30
#define NUMBER_BITS_IN_A_BYTE 8

#define NUMBER_OF_KEY_FOR_THREAD 2048

#define THREADS_PER_BLOCK          256
#if __CUDA_ARCH__ >= 200
#define MY_KERNEL_MAX_THREADS  (2 * THREADS_PER_BLOCK)
#define MY_KERNEL_MIN_BLOCKS   3
#else
#define MY_KERNEL_MAX_THREADS  THREADS_PER_BLOCK
#define MY_KERNEL_MIN_BLOCKS   2
#endif

#define DEBUG true
#define plaintext_file "./../../files/text_files/plaintext.txt"
#define ciphertext_file "./../../files/text_files/ciphertext.txt"

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

__device__ bool hack_over = false;

/***
 * The S-box is necessary for the expand_key_decryption function of the aes
 */
__device__  const uint8_t AES_Sbox[256] = {

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
__device__  const uint8_t AES_inverse_Sbox[256] = {

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
__device__  const uint8_t const_matrix[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/***
 * simmetric key for aes decryption
 * 85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC
 */
__device__ unsigned char key_aes[AES_KEY_BYTES_LENGTH] = {
    0x85, 0x92, 0x6b, 0xe3, 0xda, 0x73, 0x6f, 0x47, 0x54, 0x93, 0xc4, 0x92, 0x76, 0xed, 0x17, 0xd4,
    0x18, 0xa5, 0x5a, 0x2c, 0xfd, 0x07, 0x7d, 0x12, 0x15, 0xed, 0x25, 0x1c, 0x4a, 0x57, 0xd8, 0xec
};

unsigned char key_aes_host[AES_KEY_BYTES_LENGTH] = {
    0x85, 0x92, 0x6b, 0xe3, 0xda, 0x73, 0x6f, 0x47, 0x54, 0x93, 0xc4, 0x92, 0x76, 0xed, 0x17, 0xd4,
    0x18, 0xa5, 0x5a, 0x2c, 0xfd, 0x07, 0x7d, 0x12, 0x15, 0xed, 0x25, 0x1c, 0x4a, 0x57, 0xd8, 0xec
};

/***
 * IV for aes decryption
 * D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96
 */
__device__ unsigned char iv_aes[IV_BYTES_LENGTH] = {
    0xd8, 0x59, 0x6b, 0x73, 0x9e, 0xfa, 0xc0, 0x46, 0x0e, 0x86, 0x1f, 0x9b, 0x77, 0x90, 0xf9, 0x96
};

/***************************************** INITIALIZATION DEVICE FUNCTION *****************************************/

/**
 * function that expand the key from the simmetric aes key of 256 bit 
 * the key now is 240 byte long
 * 
 * @param rounded_key is the key for the initial round, after the expansion
 * @param key is the simmetric aes key
 */
__device__  void expand_key_decryption(uint8_t* rounded_key, const uint8_t* key){

    unsigned int __align__(16) j, k;
    uint8_t __align__(16) temporary[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (unsigned int __align__(16) i = 0; i < AES_KEY_WORD_LENGTH; i++){

        rounded_key[(i * 4) + 0] = key[(i * 4) + 0];
        rounded_key[(i * 4) + 1] = key[(i * 4) + 1];
        rounded_key[(i * 4) + 2] = key[(i * 4) + 2];
        rounded_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (unsigned int __align__(16) i = AES_KEY_WORD_LENGTH; i < COLUMN_NUMBER_STATE_MATRIX * (NUMBER_OF_ROUNDS + 1); i++){
        
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
__device__ void initialize_AES_round_secret(struct AES_round_secret* rs, const uint8_t* key, const uint8_t* iv){
    
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
__device__  void add_round_key(uint8_t round, state_t* state, const uint8_t* expanded_key){
    
    for (unsigned int __align__(16) i = 0; i < ROW_NUMBER_STATE_MATRIX; i++){
        for (unsigned int __align__(16) j = 0; j < COLUMN_NUMBER_STATE_MATRIX; j++){
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
__device__  void inv_shift_rows_decryption(state_t* state){
    
    uint8_t __align__(16) temporary;

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
__device__  void sub_bytes_decryption(state_t* state){

    for (unsigned int __align__(16) i = 0; i < ROW_NUMBER_STATE_MATRIX; i++){
        for (unsigned int __align__(16) j = 0; j < COLUMN_NUMBER_STATE_MATRIX; j++){

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
__device__  void inv_mix_columns_decryption(state_t* state){
    
    uint8_t __align__(16) a, b, c, d;

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
__device__  void xor_with_iv(uint8_t* state_matrix, const uint8_t* iv){

    for (unsigned int __align__(16) i = 0; i < AES_BLOCK_LENGTH; i++){

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
__device__  void decryption_rounds(state_t* state_matrix, const uint8_t* expanded_key){

    uint8_t __align__(16) current_round = NUMBER_OF_ROUNDS;

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


