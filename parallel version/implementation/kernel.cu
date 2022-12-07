#include "cuda_runtime.h"
#include "device_launch_parameters.h"
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

/******************************************* PARALLEL DEVICE DECRYPTION ******************************************/

/**
 * function that implement the AES_CBC algorithm and that call the single aes operation
 * 
 * @param state_matrix is the state matrix which element are trasnformed through all the phases
 */
__device__ void AES_CBC_decrypt(uint8_t *state_matrix, uint8_t *decrypted_ciphertext, uint8_t *iv) {


    AES_round_secret AES_secret;

    //Initialize the context
    initialize_AES_round_secret(&AES_secret, key_aes, iv);

    struct AES_round_secret* rs = &AES_secret;

    // use of AES 256
    decryption_rounds((state_t*)state_matrix, rs->expanded_key);
    // use of the Cipher Block Chaining (CBC)
    xor_with_iv(state_matrix, rs->round_iv);
    
    memcpy(decrypted_ciphertext, state_matrix, AES_BLOCK_LENGTH);    

    return;
}


/**
 * function that is called from host and executed on the device 
 * 
 * @param device_chipertext is the ciphertext allocated on the device and that is going to be decrypted
 */
__global__ void kernel_decrypt(uint8_t* device_chipertext, uint8_t* device_decrypted_chipertext, uint8_t* device_cbc_iv, size_t message_num_block){

    int index = blockIdx.x;
    if(index < message_num_block){

        if(index == 0){
            //printf("sono il thread [%d] che lavora all-indirizzo %d\n", index, (index * AES_BLOCK_LENGTH));
            AES_CBC_decrypt(device_chipertext + (index * AES_BLOCK_LENGTH), device_decrypted_chipertext + (index * AES_BLOCK_LENGTH), iv_aes);
        }
        else{
            //printf("sono il thread [%d] che lavora all-indirizzo %d\n", index, (index * AES_BLOCK_LENGTH));
            AES_CBC_decrypt(device_chipertext + (index * AES_BLOCK_LENGTH), device_decrypted_chipertext + (index * AES_BLOCK_LENGTH), device_cbc_iv + ((index -1) * AES_BLOCK_LENGTH));
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

    unsigned char* decrypted_plaintext = (unsigned char*)malloc(CIPHERTEXT_LENGTH);
    //host receive data: device => host
    memset(decrypted_plaintext, 0, CIPHERTEXT_LENGTH);

    // allocate of the plaintext space and read it from file
    unsigned char* plaintext = (unsigned char*)malloc(PLAINTEXT_LENGTH);
	if(!plaintext){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
		return -1;
	}
	memset(plaintext,0,PLAINTEXT_LENGTH);
	strcpy((char*)plaintext, (char*)read_data_from_file(plaintext_file).c_str());

    // allocate of the ciphertext space and read it from file
    unsigned char* ciphertext = (unsigned char*)malloc(CIPHERTEXT_LENGTH);
	if(!ciphertext){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
		return -1;
	}
	memset(ciphertext,0,CIPHERTEXT_LENGTH);

    string file_contents = hexToASCII(read_data_from_file(ciphertext_file));
	// convert to unsigned char
	for(int i=0; i<CIPHERTEXT_LENGTH; i++){
		ciphertext[i] = file_contents[i];
	}

    printf("CT:%s\n", ciphertext);

    /************************************* ALLOCATE AND COPY ON THE DEVICE ********************************************/

    // declaration of the device variable
    uint8_t* device_chipertext;
    uint8_t* device_plaintext;
    uint8_t* device_cbc_iv;
    uint8_t* device_decrypted_ciphertext;
    
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
    cudaerr = cudaMalloc((void**)&device_decrypted_ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }
    cudaerr = cudaMalloc((void**)&device_cbc_iv, sizeof(uint8_t) * CIPHERTEXT_LENGTH);
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
     cudaerr = cudaMemcpy(device_cbc_iv, ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyHostToDevice);
    if (cudaerr != cudaSuccess) {
        printf("kernel launch failed with error \"%s\".\n", cudaGetErrorString(cudaerr));
    }

    printf("\t completed! \n");


    /********************************************* LAUNCH OF THE KERNEL ***********************************************/


    printf("launch the kernel\n");

    // AES_BLOCKLEN = 16
    // si calcolano i blocchi totali del messaggio 
    size_t message_num_block = CIPHERTEXT_LENGTH / AES_BLOCK_LENGTH;
    // maxThreadsPerBlock is the maximum number of threads per block per la gpu con cui si lavora
    size_t thread_per_block = min(message_num_block, (size_t)prop.maxThreadsPerBlock);
    // qui si sta trovando il numero dei blocchi ma non so bene che sta facendo 
    printf("CIPHERTEXT_LENGTH: %d\n", CIPHERTEXT_LENGTH);
    printf("AES_BLOCK_LENGTH: %d\n", AES_BLOCK_LENGTH);
    printf("message_num_block: %lu\n", message_num_block);
    printf("(size_t)prop.maxThreadsPerBlock: %lu\n", (size_t)prop.maxThreadsPerBlock);
    printf("NUMERO THREADS = thread_per_block = min(message_num_block, (size_t)prop.maxThreadsPerBlock) %lu\n", thread_per_block);
    size_t device_setted_block_number = (message_num_block + thread_per_block - 1) / thread_per_block;

    printf("NUMERO BLOCK = device_setted_block_number = (message_num_block + thread_per_block - 1) / thread_per_block: %lu\n", device_setted_block_number);
    printf("thread_per_block: %lu\n", thread_per_block);

    kernel_decrypt <<<1763, 1>>> (device_chipertext, device_decrypted_ciphertext, device_cbc_iv, message_num_block);
    cudaerr = cudaDeviceSynchronize();
    if (cudaerr != cudaSuccess){
       printf("kernel launch failed with error \"%s\".\n",cudaGetErrorString(cudaerr));
    }
    
    // host receive data: device => host
    cudaMemcpy(decrypted_plaintext, device_decrypted_ciphertext, sizeof(uint8_t) * CIPHERTEXT_LENGTH, cudaMemcpyDeviceToHost);

    
    string s((char*)decrypted_plaintext);
    printf("[HOST]:Risultato con lunghezza %lu pari a: %s\n",s.length(), s.c_str());

    /**************************************** RELEASE OF THE DEVICE ALLOCATION ****************************************/

   
    // release device memory
    cudaFree(device_chipertext);
    cudaFree(device_plaintext);
    

}