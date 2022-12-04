#include <stdlib.h>
#include <iostream>
#include <thread>
#include <string.h>
#include <fstream>
#include <math.h> 
#include <sstream>
#include <time.h>
#include <chrono>
#include "AES/aes.c"

using namespace std;

//Encrypting/Decrypting Parameters definition
#define AES_KEYLENGTH 32
#define IV_KEYLENGTH 16
#define SALT_KEYLENGTH 8
#define DEBUG true
#define BLOCK_SIZE 16
#define PLAINTEXT_LENGHT 448

//Brute Force configuration
#define BASE_NUMBER 2


//              PARAMETERS
//  Key generated from openssl enc -aes-256-cbc -key_aes secret -P -md sha1
//  key = 85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC  
//  iv =D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96

const string plaintext_file = "./../files/text_files/plaintext.txt";
const string ciphertext_file = "./../files/text_files/ciphertext.txt";

/** Function that perform an encryption on AES-256
 * msg: Contain the data to be encrypted
 * msg_len: Contain the length of the data to be encrypted
 * ciphertext: filled at the end of the encryption, contain the whole encrypted message
 * cipherlen: filled with the length of the ciphertext
 * symmetric_key: key for symmetric encryption
 */
int cbc_encrypt_fragment(unsigned char* msg, unsigned char* symmetric_key, unsigned char* iv, AES_ctx* ctx){

	//Context initializing
	AES_init_ctx_iv(ctx,(uint8_t*)symmetric_key,(uint8_t*)iv);

	//Perform encryption
	AES_CBC_encrypt_buffer(ctx, (uint8_t*)msg, PLAINTEXT_LENGHT);

	return 0;
}

/** Function that perform a conversion from Hexadecimal number into their ASCII representation
 * hex: string that contains the Hexadecimal rapresentation of the text 
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

/** Function that perform the decryption on AES-256
 * ciphertext: contain the bitstream to be decrypted
 * cipherlen: contain the length of the cipher
 * plaintext: variable in which we return the decrypted PT
 * plainlen: length of the decrypted PT
 * symmetric_key: AES key used for decryption
 */
int cbc_decrypt_fragment (unsigned char* ciphertext, AES_ctx* ctx){

	AES_CBC_decrypt_buffer(ctx, ciphertext, PLAINTEXT_LENGHT);
	return 0;
}

/** Perfrom a read from a file
 * file: name of the file to read
 */
string read_data_from_file(string file){

	fstream getFile;
	string str;
	string file_contents;
	getFile.open(file,ios::in | ios::binary);

	while (getline(getFile, str)){
		file_contents += str;
		file_contents.push_back('\n');
	} 

	file_contents.pop_back();
	
	getFile.close();
	
	return file_contents;
}

/** Perform a convertion of the key from exadecimal to ASCII and save it on another file
 * file_to_read: file on which we read the exadecimal format key
 * file_to_save: file on which we save the converted key
 */
void convert_key(string file_to_read, string file_to_save){

	string str = read_data_from_file(file_to_read);

	ofstream SaveFile(file_to_save, ios::out | ios::binary);
	SaveFile << hexToASCII(str);
	SaveFile.close();

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
bool decryption_brute_force(unsigned char*& plaintext, unsigned char* ciphertext, int num_bits_to_hack,unsigned char* hacked_key,unsigned char* key, unsigned char* iv_aes){

	unsigned char ascii_character;
	//Calculate the number of cycles before the cycle to optimize
	uintmax_t index = pow (BASE_NUMBER, num_bits_to_hack);

	// array containg de character of the key that has to be hacked (i.e. 20 bits = 3 Bytes)
	unsigned char bytes_to_hack [num_bits_to_hack/8 + 1];

	unsigned char* ct_temp = (unsigned char*)malloc(PLAINTEXT_LENGHT);
	memset(ct_temp,0,PLAINTEXT_LENGHT);
	memcpy(ct_temp,ciphertext,PLAINTEXT_LENGHT);

	/* ---------------------------------------------------------------------------------------------------------------------------------------- */
	//This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
	uint8_t tmp, rem_bits = num_bits_to_hack % 8;

	//Copy inside the bytes_to_hack the last byte
	memcpy(bytes_to_hack + (num_bits_to_hack / 8), hacked_key + (num_bits_to_hack / 8), 1); // Copy just the last byte 

	//Use the shift to clean up the part that we don't know of the last byte (like 4 bits in case of 20 bits to discover)
	if(num_bits_to_hack % 8 != 0){
		//With 20 bits -> 2
		bytes_to_hack[num_bits_to_hack / 8 ] = hacked_key[AES_KEYLENGTH - 1 - (num_bits_to_hack / 8)] >> rem_bits;
		tmp = bytes_to_hack[num_bits_to_hack / 8] << rem_bits;
	}

	/* ---------------------------------------------------------------------------------------------------------------------------------------- */
	/* START THE BRUTEFORCE - INITIATE TIME COUNTING */
	auto begin = chrono::high_resolution_clock::now();

	for(uintmax_t i = 0; i < index; i++){	//2^NUM_BITES_TO_HACK Cycles

		AES_ctx new_ctx;
		//Get the index address in order to extract and manage one byte at a time
		uint8_t *pointer = (uint8_t*)&i;

		//cout<< "-------------------------------------------- Attempt #"<<i+1<<" ----------------------------------------------"<<endl;
		
		// clean of the array (only the bytes that have to be completely cleaned, i.e. last two bytes)
		memset(bytes_to_hack,0,num_bits_to_hack/8);

		memset(plaintext,0,PLAINTEXT_LENGHT);

		uint8_t numcycles = num_bits_to_hack/8 + 1;

		// First copy the bytes that are whole
		for(int j=0;j <  numcycles; j++){
			//This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
			if(num_bits_to_hack % 8 != 0 && j == num_bits_to_hack/8){
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
		for (int j = 0; j < (num_bits_to_hack/8) + 1; j++){
			if(num_bits_to_hack % 8 != 0){
				memcpy(&hacked_key[AES_KEYLENGTH - j - 1], &bytes_to_hack[j], 1);
			}
			else if(j < (num_bits_to_hack/8)){
				memcpy(&hacked_key[AES_KEYLENGTH - j -1], &bytes_to_hack[j],  1);
			}
		}

		//Initialize the context with the new key and the iv
		AES_init_ctx_iv(&new_ctx, hacked_key, iv_aes);

		//If the decrypt returns an error the key is wrong for sure
		int ret = cbc_decrypt_fragment(ct_temp, &new_ctx);
		if(ret == -1){
			continue;
		}

		
		if(!strcmp((const char*)hacked_key, (const char*)key)){

			printf("%s\n\n",ct_temp);

			auto end = chrono::high_resolution_clock::now();
			auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - begin);

			printf("# of Bits: %d, # of Attempt: %ld, Elapsed Time in ms: %ld\n", num_bits_to_hack, i, elapsed.count());

			char filename[62] = "sequential_result";
			sprintf(filename, "results/sequential_result_%d.txt", num_bits_to_hack);
			ofstream file_out;

			file_out.open(filename, std::ios_base::app);
			file_out <<elapsed.count()<< endl;
			file_out.close();
			cout << "Save results on file" << endl;

			free(ct_temp);
			return true;
		}
		else{
			memcpy(ct_temp,ciphertext,PLAINTEXT_LENGHT);
			continue;
		}
		//cout<< "--------------------------------------------------------------------------------------------------------------"<<endl;
	}

	cout<< "**************************************************"<<endl;
	free(ct_temp);
	return false;
}

int main (int argc, char **argv){
	
	int num_bits_to_hack = atoi(argv[1]);

	/* ------------------------------------- GET KEY -------------------------------------------------------- */
	printf("------------------------------------- GET KEY --------------------------------------------------------\n");
	
	/**
	 * simmetric key for aes decryption
	 * 85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC
	 * 
	 */
	unsigned char key_aes[AES_KEYLENGTH] = { 
		0x85, 0x92, 0x6b, 0xe3, 0xda, 0x73, 0x6f, 0x47, 0x54, 0x93, 0xc4, 0x92, 0x76, 0xed, 0x17, 0xd4, 
		0x18, 0xa5, 0x5a, 0x2c, 0xfd, 0x07, 0x7d, 0x12, 0x15, 0xed, 0x25, 0x1c, 0x4a, 0x57, 0xd8, 0xec
		};

	/**
	 * IV for aes decryption
	 * D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96
	 * 
	 */
	unsigned char iv_aes[IV_KEYLENGTH] = { 
		0xd8, 0x59, 0x6b, 0x73, 0x9e, 0xfa, 0xc0, 0x46, 0x0e, 0x86, 0x1f, 0x9b, 0x77, 0x90, 0xf9, 0x96
		};



	printf("------------------------------------------------------------------------------------------------------\n");
	/* ------------------------------------- GET PT -------------------------------------------------------- */
	printf("------------------------------------- GET PT ---------------------------------------------------------\n");

	//Allocating pt space
	unsigned char* plaintext = (unsigned char*)malloc(PLAINTEXT_LENGHT);
	if(!plaintext){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
		return -1;
	}
	memset(plaintext,0,PLAINTEXT_LENGHT);
	strcpy((char*)plaintext, (char*)read_data_from_file(plaintext_file).c_str());

	if(DEBUG){
		printf("DEBUG: The Plaintext is: %s\n", plaintext);
	}

	printf("------------------------------------------------------------------------------------------------------\n");
	/* ------------------------------------- Encryption  -------------------------------------------------------- */
	printf("------------------------------------- GET ENC --------------------------------------------------------\n");

	//Call the encryption function and obtain the Cyphertext
	AES_ctx ctx;

	unsigned char* ct = (unsigned char*)malloc(PLAINTEXT_LENGHT);
	memcpy(ct,plaintext,PLAINTEXT_LENGHT);

	int ret = cbc_encrypt_fragment(ct, key_aes, iv_aes, &ctx);

	//Save the ciphertext for bruteforcing
	unsigned char* saved_ct =(unsigned char*)malloc(PLAINTEXT_LENGHT);
	memcpy(saved_ct,ct,PLAINTEXT_LENGHT);

	if(ret != 0){
		printf("Error during encryption\n");
	}
	if(DEBUG){
		printf("[DEBUG] result: %s\n", ct);
	}

	printf("------------------------------------------------------------------------------------------------------\n");
	/* ------------------------------------- Decryption  -------------------------------------------------------- */
	printf("------------------------------------- GET DEC --------------------------------------------------------\n");

	//Call the decryption function 
	AES_ctx_set_iv(&ctx, (uint8_t*)&iv_aes);

	ret = 0;
	ret = cbc_decrypt_fragment (ct, &ctx);
	if(ret != 0){
		printf("Error during decryption\n");
	}

	if(DEBUG){
		printf("[DEBUG] result: %s\n", ct);
	}

	ret= strcmp((const char*)plaintext, (const char*)ct);
	if(ret==0 && DEBUG){
		printf("[DEBUG] strcmp ended with positive response\n");
	}
	else if(DEBUG){
		printf("strcmp returned %d\n",ret);
	}


	//TEST COMPLETED - PROCEED TO EXECUTE THE BRUTEFORCING
	printf("--------------------------------- PROCEED WITH BRUTEFORCING ----------------------------------------------\n");

	printf("Bits to hack: %d\n", num_bits_to_hack/8);

	//Copy the amount of known bits, ex. if 20 bits has to be discovered we copy all the key except the last two bytes, the last for bits will be removed using the shift later
    unsigned char* hacked_key = (unsigned char*)malloc(AES_KEYLENGTH);
	memset(hacked_key,0,AES_KEYLENGTH);
	//memcpy(hacked_key, key_aes, (AES_KEYLENGTH));
	strcpy((char*)hacked_key, (char*)key_aes);

	if(DEBUG){
		printf("HACKED KEY: %s\n", hacked_key);
		printf("KEY: %s\n", key_aes);
 	}

	if(DEBUG){
		printf("DEBUG: ** Start Bruteforcing **\n");
	}

	bool res = decryption_brute_force(plaintext, saved_ct, num_bits_to_hack, hacked_key ,key_aes, iv_aes);

	if(!res){
		printf("Error during brute forcing attack\n");
	}

	if(DEBUG){
		printf("DEBUG: Brute Force completed and key obtained: %s\n", hacked_key);
	}

	printf("----------------------------------------------------------------------------------------------------------\n");
	// ------------------------------------------------------ //

	free(plaintext);
	free(ct);

	return 1;
}
