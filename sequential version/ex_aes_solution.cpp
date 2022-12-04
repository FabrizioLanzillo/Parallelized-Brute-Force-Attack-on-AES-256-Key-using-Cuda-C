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
	
	//int num_bits_to_hack = atoi(argv[1]);
	int num_bits_to_hack = 8;
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

	unsigned char ct_final[PLAINTEXT_LENGHT] = {
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

	
	// save the ciphertext on a txt file in hex format
	ofstream outfile;
	outfile.open(ciphertext_file, ios::out | ios::binary);
	char ciphertext_element_hex [3];
	for(int i=0; i<PLAINTEXT_LENGHT; i++){
		sprintf(ciphertext_element_hex, "%02X", (int)saved_ct[i]);
		outfile <<  ciphertext_element_hex;
	}
	outfile.close();
	

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
