#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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
//  salt = B51DE47CC865460E
//  key = 85926BE3DA736F475493C49276ED17D418A55A2CFD077D1215ED251C4A57D8EC
//  85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC  
//  iv = D8596B739EFAC0460E861F9B7790F996
//  iv =D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96

const string plaintext_file = "./../files/text_files/plaintext.txt";
const string ciphertext_file = "./../files/text_files/ciphertext.txt";
const string key_aes_hex_file = "./../files/secret_files/key_aes_hex.txt";
const string key_aes_file = "./../files/secret_files/key_aes.txt";
//const string key_wrong_file = "key_wrong.txt";
//const string key_wrong_file_hex = "key_wrong_hex.txt";
const string iv_file_hex = "./../files/secret_files/iv_hex.txt";
const string iv_file = "./../files/secret_files/iv.txt";
const string salt_file_hex = "./../files/secret_files/salt_hex.txt";
const string salt_file = "./../files/secret_files/salt.txt";

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

/** Function that removes the padding from the deciphered plaintext
 * size: deciphered plaintext with padding size
 * plaintext_with_pad: plaintext on which we have to remove the padding
 * plaintext: resulting plaintext without padding
 */
bool remove_padding(int size, unsigned char*& plaintext_with_pad, unsigned char*& plaintext){
	//Calculating the size of the Plaintext without padding
	int padding_size_bytes = (int)plaintext_with_pad[size-1];

	if(padding_size_bytes > BLOCK_SIZE){
		return false;
	}

	memcpy(plaintext, plaintext_with_pad, size - padding_size_bytes);
	
	return true;
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


int main (int argc, char **argv){
	
	//int num_bits_to_hack = atoi(argv[1]);
	int num_bits_to_hack = 12;	

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

	if(ret != 0){
		printf("Error during encryption\n");
	}
	if(DEBUG){
		printf("[DEBUG] result: %s\n", ct);
	}

	unsigned char* dec_pt = ct;

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

	printf("Bytes to hack: %d\n", num_bits_to_hack/8);

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

	/*bool res = decryption_brute_force(plaintext, ct, PLAINTEXT_LENGHT, &ctx, decrypted_plaintext_no_pad, decrypted_PLAINTEXT_LENGHT, iv_aes, num_bits_to_hack);
	
	if(!strcmp((const char*)hacked_key, (const char*)key_aes)){
		printf("Key corresponds!\n");
	}
	else{
		printf("Error the keys does not correspond!\n");
	}

	if(!res){
		printf("Error during brute forcing attack\n");
	}

	if(DEBUG){
		printf("DEBUG: Brute Force completed and key obtained: %s\n", hacked_key);
	}

	printf("----------------------------------------------------------------------------------------------------------\n");
	// ------------------------------------------------------ //
	*/
	free(plaintext);
	free(ct);

	return 1;
}
