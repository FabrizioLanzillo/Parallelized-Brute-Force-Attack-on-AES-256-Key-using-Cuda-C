#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <algorithm>
#include <cuda.h>
#include "header.cuh"

using namespace std;

/******************************************* HOST UTILITY FUNCTION ******************************************/

/**
 * function that read text from file
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

/**
 * function that convert hex characters into a string
 * 
 * @param hex is a string parameter with the hexs character
 */
__host__ string hexToASCII(string hex){

    // initialize the ASCII string
    string ascii = "";
    for (size_t i = 0; i < hex.length(); i += 2){
        
        // two characters from hex string
        string part = hex.substr(i, 2);
        // change into base 16 and cast to char
        char ch = stoul(part, nullptr, 16);
        // add to the ASCII string
        ascii += ch;
    }
    return ascii;
}


/******************************************* PARALLEL DEVICE DECRYPTION ******************************************/

/**
 * function that implement the AES_CBC algorithm and that call the single aes operation
 * 
 * @param state_matrix is the state matrix which element are trasnformed through all the phases
 */
__device__ void single_block_decrypt(uint8_t *state_matrix, uint8_t *iv,const uint8_t* key) {

    AES_round_secret AES_secret;

    //Initialize the secret elements i.e. simmetric key and IV
    initialize_AES_round_secret(&AES_secret, key, iv);
    struct AES_round_secret* rs = &AES_secret;
    // use of AES 256
    decryption_rounds((state_t*)state_matrix, rs->expanded_key);
    // use of the Cipher Block Chaining (CBC)
    xor_with_iv(state_matrix, rs->round_iv); 

    return;
}


/******************************************* PARALLEL DEVICE HACK ******************************************/


/**
 * function that is called from host and executed on the device 
 * 
 * @param device_ciphertext is the ciphertext allocated on the device and that is going to be decrypted
 */
__global__ void kernel_hack(uint8_t* device_ciphertext, uint8_t* device_plaintext, uint8_t* device_cbc_iv, size_t message_num_block, uint8_t* device_key_to_hack, uint8_t* device_return_key){
    
    uint32_t index = threadIdx.x + (blockIdx.x * blockDim.x);

    if (index < message_num_block) {

        // declaration of the data structure to implement the hack
        unsigned char bytes_to_hack[(NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE) + 1];
        uint8_t hacked_key[AES_KEY_BYTES_LENGTH];
        uint8_t state_matrix[AES_BLOCK_LENGTH];
        char ascii_character;
        uint8_t* current_index_to_try = (uint8_t*)&index;
        uint8_t numcycles = NUMBER_BITS_TO_HACK + 1;

        // allocation of the current element for the hacked key
        memcpy(state_matrix, device_ciphertext, AES_BLOCK_LENGTH);
        memcpy(hacked_key, device_key_to_hack, AES_KEY_BYTES_LENGTH); 
        memset(bytes_to_hack,0, (NUMBER_BITS_TO_HACK/NUMBER_BITS_IN_A_BYTE) + 1);

        uint8_t bits_to_maintain = device_key_to_hack[AES_KEY_BYTES_LENGTH - 1 - (NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE)];

        // First copy the bytes that are multiple of 8 bits
        for ( uint32_t j = 0; j <  numcycles; j++ ){
            
            // code that will be executed only if there are remaining bits that are not multiples of 8 bits 
            if( NUMBER_BITS_TO_HACK % NUMBER_BITS_IN_A_BYTE != 0 && j == ( NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE ) ){
                // The addition of unsigned number perform the append correctly until the value inside current_index_to_try[j] 
                // overcome the capacity of the bit to be copied, 
                // but this will never happen since we stop the cycle before it happen
                bytes_to_hack[j] = bits_to_maintain + current_index_to_try[j];
                continue;
            }
            ascii_character = char(index >> (NUMBER_BITS_IN_A_BYTE * j));
            memcpy(&bytes_to_hack[j], &ascii_character, 1);
        }

        // merge of the bits to hack inside the known key
        for (uint32_t j = 0; j < (NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE) + 1; j++) {
            if ( NUMBER_BITS_TO_HACK % NUMBER_BITS_IN_A_BYTE != 0 ) {
                memcpy(&hacked_key[AES_KEY_BYTES_LENGTH - j - 1], &bytes_to_hack[j], 1);
            }
            else if ( j < ( NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE ) ) {
                memcpy(&hacked_key[AES_KEY_BYTES_LENGTH - j - 1], &bytes_to_hack[j], 1);
            }
        }

        __syncthreads();
        
        single_block_decrypt(state_matrix, iv_aes, hacked_key);

        __syncthreads();

        for (uint32_t k = 0; k < AES_BLOCK_LENGTH; k++) {
             
            if ((state_matrix[k] == device_plaintext[k])) {
                if (k == (AES_BLOCK_LENGTH - 1)) {
                    
                    printf("Known key:\t");
                    for (uint32_t k = 0; k < AES_KEY_BYTES_LENGTH; k++){
                        printf("%d|", device_key_to_hack[k]);
                    }
                    printf("\n\n");
                    printf("KEY HACKED!\n\n");
                    printf("Hacked key:\t");
                    for (uint32_t k = 0; k < AES_KEY_BYTES_LENGTH; k++){
                        printf("%d|", hacked_key[k]);
                    }
                    printf("\n");
                    printf("Expected key:\t");
                    for (uint32_t k = 0; k < AES_KEY_BYTES_LENGTH; k++){
                        printf("%d|", key_aes[k]);
                    }
                    printf("\n");

                    memcpy(device_return_key, hacked_key, AES_KEY_BYTES_LENGTH);

                    return;
                }
            }
            else {
                return;
            }
        }

    }

}




int main() {

    /******************************************** SET GPU PROPERTIES **************************************************/


    // inizialize of a struct with all the gpu properties 
    cudaDeviceProp prop;                   
    // we define the field of the previous struct with the properties of the specified device
    // prop is the struct and the second paramether is the device number
    cudaGetDeviceProperties(&prop, 0);  

    /************************************** GET THE PLAINTEXT AND CIPHERTEXT ******************************************/

    // allocate of the plaintext space and read it from file
    unsigned char* plaintext = (unsigned char*)malloc(PLAINTEXT_LENGTH);
	if(!plaintext){
        printf("ERROR: plaintext space allocation went wrong\n");
		return -1;
	}
	memset(plaintext,0,PLAINTEXT_LENGTH);
	strcpy((char*)plaintext, (char*)read_data_from_file(plaintext_file).c_str());

    // allocate of the ciphertext space and read it from file
    unsigned char* ciphertext = (unsigned char*)malloc(CIPHERTEXT_LENGTH);
	if(!ciphertext){
        printf("ERROR: plaintext space allocation went wrong\n");
		return -1;
	}
	memset(ciphertext,0,CIPHERTEXT_LENGTH);

    string file_contents = hexToASCII(read_data_from_file(ciphertext_file));
	// convert to unsigned char
	for(int i=0; i<CIPHERTEXT_LENGTH; i++){
		ciphertext[i] = file_contents[i];
	}

    /************************************* KEY HACK CREATION ********************************************/

    //Creation of the key to hack
    uint8_t key_to_hack[AES_KEY_BYTES_LENGTH];

    //Copy the whole key
    memcpy(&key_to_hack, key_aes_host, AES_KEY_BYTES_LENGTH);

    //Clear the unknown part
    memset(&key_to_hack[AES_KEY_BYTES_LENGTH - (NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE)], 0, NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE);

    //This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
    uint8_t rem_bits = NUMBER_BITS_TO_HACK % NUMBER_BITS_IN_A_BYTE;

    //Use the shift to clean up the part that we don't know of the last byte (like 4 bits in case of 20 bits to discover)
    if (NUMBER_BITS_TO_HACK % NUMBER_BITS_IN_A_BYTE != 0) {
        //With 20 bits -> 2
        key_to_hack[AES_KEY_BYTES_LENGTH - 1 - (NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE)] = key_to_hack[AES_KEY_BYTES_LENGTH - 1 - (NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE)] >> rem_bits;
        key_to_hack[AES_KEY_BYTES_LENGTH - 1 - NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE] = key_to_hack[AES_KEY_BYTES_LENGTH -1  - NUMBER_BITS_TO_HACK / NUMBER_BITS_IN_A_BYTE] << rem_bits;
    }

    /************************************* ALLOCATE AND COPY ON THE DEVICE ********************************************/

    // declaration of the device variable
    uint8_t* device_ciphertext;
    uint8_t* device_plaintext;
    uint8_t* device_cbc_iv;
    uint8_t* device_key_to_hack;
    uint8_t* device_return_key;
    
    printf("------------------------------------------------------- Memory allocation on device --------------------------------------------------\n");
    
    cudaError_t cudaerr;

    printf("Allocation of the space for the ciphertext on the device:\t");
    // allocate device memory
    cudaerr = cudaMalloc((void**)&device_ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Allocation of the space for the plaintext on the device:\t");
    cudaerr = cudaMalloc((void**)&device_plaintext, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Allocation of the space for the IVs on the device:\t\t");
    cudaerr = cudaMalloc((void**)&device_cbc_iv, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Allocation of the space for the key to hack on the device:\t");
    cudaerr = cudaMalloc((void**)&device_key_to_hack, sizeof(uint8_t) * AES_KEY_BYTES_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Allocation of the space for the key hacked on the device:\t");
    cudaerr = cudaMalloc((void**)&device_return_key, sizeof(uint8_t) * AES_KEY_BYTES_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }

    printf("OK => Completed!\n");
    printf("--------------------------------------------------------------------------------------------------------------------------------------\n");

    printf("------------------------------------------------------ Copying data on device --------------------------------------------------------\n");

    printf("Copy of the ciphertext on the device:\t");
    cudaerr = cudaMemcpy(device_ciphertext, ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Copy of the plaintext on the device:\t");
    cudaerr = cudaMemcpy(device_plaintext, plaintext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Copy of the IVs on the device:\t\t");
    cudaerr = cudaMemcpy(device_cbc_iv, ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    printf("Copy of the key_to_hack on the device:\t");
    cudaerr = cudaMemcpy(device_key_to_hack, key_to_hack, sizeof(uint8_t) * AES_KEY_BYTES_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    else{
        printf("OK\n");
    }
    
    printf("OK => Completed!\n");
    printf("--------------------------------------------------------------------------------------------------------------------------------------\n");


    /********************************************* LAUNCH OF THE KERNEL ***********************************************/

    printf("-------------------------------------------------- Start of the brute force attack ---------------------------------------------------\n");


    // compute the maximum number of iteration in order to discover the key
    uint64_t iter_num = pow(2,NUMBER_BITS_TO_HACK);
    // maxThreadsPerBlock is the maximum number of threads per block for the current gpu
    size_t thread_per_block = (size_t)prop.maxThreadsPerBlock / 2;
    // compute the number of block to initialize
    size_t num_block = iter_num / thread_per_block;
    
    // qui si sta trovando il numero dei blocchi ma non so bene che sta facendo 
    //size_t device_setted_block_number = (message_num_block + thread_per_block - 1) / thread_per_block;

    printf("Number of block : %lu and Number of threads: %lu\n", num_block, thread_per_block);

    kernel_hack <<<num_block, thread_per_block >>> (device_ciphertext, device_plaintext, device_cbc_iv, iter_num, device_key_to_hack, device_return_key);

    cudaDeviceSynchronize();

    cudaerr = cudaGetLastError();
    if (cudaerr != cudaSuccess){
       printf("kernel launch failed with error \"%s\".\n",cudaGetErrorString(cudaerr));
    }

    //Copy the hacked key from device to host
    cudaerr = cudaMemcpy(key_to_hack, device_key_to_hack, sizeof(uint8_t) * AES_KEY_BYTES_LENGTH, cudaMemcpyDeviceToHost);
    if (cudaerr != cudaSuccess) {
        printf("CudaMemcpy error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    
    printf("--------------------------------------------------------------------------------------------------------------------------------------\n");

    /**************************************** RELEASE OF THE DEVICE ALLOCATION ****************************************/

    // release device memory
    cudaFree(device_ciphertext);
    cudaFree(device_plaintext);
    cudaFree(device_cbc_iv);
    cudaFree(device_key_to_hack);
    cudaFree(device_return_key);

}