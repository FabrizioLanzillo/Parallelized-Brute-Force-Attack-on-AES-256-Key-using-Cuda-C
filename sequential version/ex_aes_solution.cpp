#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
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

using namespace std;

//Encrypting/Decrypting Parameters definition
#define AES_KEYLENGTH 32
#define IV_KEYLENGTH 16
#define SALT_KEYLENGTH 8
#define DEBUG true
#define BLOCK_SIZE 16
#define PLAINTEXT_LENGHT 445

//Brute Force configuration
#define NUM_BITS_TO_HACK 25
#define BASE_NUMBER 2


//              PARAMETERS
//  Key generated from openssl enc -aes-256-cbc -key_aes secret -P -md sha1
//  salt = B51DE47CC865460E
//  key = 85926BE3DA736F475493C49276ED17D418A55A2CFD077D1215ED251C4A57D8EC
//  85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC  
//  iv = D8596B739EFAC0460E861F9B7790F996
//  iv =D8 59 6B 73 9E FA C0 46 0E 86 1F 9B 77 90 F9 96

//Key in HEX format as global parameters
static const int key_size = 32;

const string plaintext_file = "plaintext.txt";
const string ciphertext_file = "ciphertext.txt";
const string key_aes_hex_file = "key_aes_hex.txt";
const string key_aes_file = "key_aes.txt";
const string key_wrong_file = "key_wrong.txt";
const string key_wrong_file_hex = "key_wrong_hex.txt";
const string iv_file_hex = "iv_hex.txt";
const string iv_file = "iv.txt";
const string salt_file_hex = "salt_hex.txt";
const string salt_file = "salt.txt";


//Utility function that handle encryption errors
void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

/** Function that perform an encryption on AES-256
 * msg: Contain the data to be encrypted
 * msg_len: Contain the length of the data to be encrypted
 * ciphertext: filled at the end of the encryption, contain the whole encrypted message
 * cipherlen: filled with the length of the ciphertext
 * symmetric_key: key for symmetric encryption
 */
int cbc_encrypt_fragment(unsigned char* msg, int msg_len, unsigned char*& ciphertext, int& cipherlen, unsigned char* symmetric_key, unsigned char* iv){
	int outlen;
	int ret;

	EVP_CIPHER_CTX* ctx;

	if (msg_len == 0) {
		std::cerr << "message length is not allowed: " << msg_len << endl;
		return -1;
	}

	try {
		// context definition
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "context definition failed" << endl;
			throw 2;
		}
			
		// init encryption
		ret = EVP_EncryptInit(ctx, EVP_aes_256_cbc(), symmetric_key, iv);
		if (ret != 1) {
			cerr << "failed to initialize encryption" << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}
		outlen = 0;
		cipherlen = 0;

		// encrypt update on the message
		ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)msg, msg_len);

		if (ret != 1) {
			ERR_print_errors_fp(stderr);
			throw 5;
		}

		cipherlen += outlen;

		ret = EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);

		if (ret != 1) {
			ERR_print_errors_fp(stderr);
			throw 6;
		}

		// extra check on the cipherlen overflow
		if (cipherlen > numeric_limits<int>::max() - outlen) {
			cerr << "overflow error on cipherlen" << endl;
			throw 7;
		}

		cipherlen += outlen;
	}
	catch (int error_code) {

		free(ciphertext);
		if (error_code > 1){
			EVP_CIPHER_CTX_free(ctx);
		}

		return -1;
	}
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
int cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, int& plainlen, unsigned char* symmetric_key, unsigned char *iv){
	int outlen;
	int ret;

	EVP_CIPHER_CTX* ctx;

	if (cipherlen == 0) {
		cerr << "ERR: input cipher len not allowed" << endl;
		return -1;
	}

	//error if iv is not set
	if (iv == nullptr){
		cerr << "ERR: missing iv for decryption" << endl;
		return -1;
	}

	try {
		// context definition
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "ERR: context definition failed" << endl;
			throw 2;
		}

		// init encryption
		ret = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), symmetric_key, iv);
		if (ret != 1) {
			cerr << "ERR: failed to initialize decryption" << endl;
			ERR_print_errors_fp(stderr);
			throw 3;
		}

		outlen = 0;
		plainlen = 0;

		ret = EVP_DecryptUpdate(ctx, plaintext + outlen, &outlen, (unsigned char*)ciphertext+outlen, cipherlen);

		if (ret != 1) {
			cerr << "ERR: failed decrypt update" << endl;
			ERR_print_errors_fp(stderr);
			throw 4;
		}

		plainlen += outlen;

		ret = EVP_DecryptFinal(ctx, plaintext + outlen, &outlen);

		if (ret != 1) {
			//cerr << "ERR: failed decrypt finalization" << endl;
			//ERR_print_errors_fp(stderr);
			throw 5;
		}

		// extra check on the cipherlen overflow
		if (plainlen > numeric_limits<int>::max() - outlen) {
			cerr << "ERR: overflow error on plaintext length" << endl;
			throw 6;
		}

		plainlen += outlen;
	}
	catch (int error_code) {
    

		if (error_code > 1){
			EVP_CIPHER_CTX_free(ctx);
		}

		//printf("ERROR DURING DECRYPTION: %d\n", error_code);
		return -1;
	}
	/*
	if(DEBUG){
		printf("DEBUG: Decryption completed successfully\n");
	}*/
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

/** Function that perform the bruteforcing of AES-256
 * hacked_key: key with an amount of bits that we suppose to know
 * knowed_plaintext: original plaintext needed to compare the one obtained from decryption
 * ciphertext: the cipher to decrypt
 * plaintext: variable on which we have to return the decrypted PT (with padding)
 * plaintext_no_pad: variable on which we have to return the decrypted PT (without padding)
 * plainlen: length of the expected plaintext
 * iv: variable needed to perform decryption, usually sent in clear with ciphertext size
 */
bool decryption_brute_force(unsigned char*& hacked_key, unsigned char* knowed_plaintext, unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, unsigned char*& plaintext_no_pad, int& plainlen, unsigned char*& iv){

	unsigned char ascii_character;
	//Calculate the number of cycles before the cycle to optimize
	uintmax_t index = pow (BASE_NUMBER, NUM_BITS_TO_HACK);

	// array containg de character of the key that has to be hacked (i.e. 20 bits = 3 Bytes)
	unsigned char bytes_to_hack [NUM_BITS_TO_HACK/8 + 1];

	/* ---------------------------------------------------------------------------------------------------------------------------------------- */
	//This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
	uint8_t tmp, rem_bits = NUM_BITS_TO_HACK % 8;

	//Copy inside the bytes_to_hack the last byte
	memcpy(bytes_to_hack + (NUM_BITS_TO_HACK / 8), hacked_key + (NUM_BITS_TO_HACK / 8), 1); // Copy just the last byte 

	//Use the shift to clean up the part that we don't know of the last byte (like 4 bits in case of 20 bits to discover)
	if(NUM_BITS_TO_HACK % 8 != 0){
		//With 20 bits -> 2
		bytes_to_hack[NUM_BITS_TO_HACK / 8 ] = hacked_key[key_size - 1 - (NUM_BITS_TO_HACK / 8)] >> rem_bits;
		tmp = bytes_to_hack[NUM_BITS_TO_HACK / 8] << rem_bits;
	}

	/* ---------------------------------------------------------------------------------------------------------------------------------------- */

	for(uintmax_t i = 0; i < index; i++){	//2^NUM_BITES_TO_HACK Cycles

		//Get the index address in order to extract and manage one byte at a time
		uint8_t *pointer = (uint8_t*)&i;

		if(i%1000000==0){
			cout<<"Attempt "<<i<<endl;
		}
		//cout<< "-------------------------------------------- Attempt #"<<i+1<<" ----------------------------------------------"<<endl;
		
		// clean of the array (only the bytes that have to be completely cleaned, i.e. last two bytes)
		memset(bytes_to_hack,0,NUM_BITS_TO_HACK/8);

		memset(plaintext,0,cipherlen);
		memset(plaintext_no_pad,0,cipherlen);

		uint8_t numcycles = NUM_BITS_TO_HACK/8 + 1;

		// First copy the bytes that are whole
		for(int j=0;j <  numcycles; j++){
			//This part must be executed only if there is a part of a byte remaining to be inserted (like last 4 bits in case of 20 bits)
			if(NUM_BITS_TO_HACK % 8 != 0 && j == NUM_BITS_TO_HACK/8){
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
		for (int j = 0; j < (NUM_BITS_TO_HACK/8) + 1; j++){
			if(NUM_BITS_TO_HACK % 8 != 0){
				memcpy(&hacked_key[key_size - j - 1], &bytes_to_hack[j], 1);
			}
			else if(j < (NUM_BITS_TO_HACK/8)){
				memcpy(&hacked_key[key_size - j -1], &bytes_to_hack[j],  1);
			}
		}

		//If the decrypt returns an error the key is wrong for sure
		int ret = cbc_decrypt_fragment(ciphertext, cipherlen, plaintext, plainlen, hacked_key, iv);
		if(ret == -1){
			continue;
		}

		if(!remove_padding(cipherlen, plaintext, plaintext_no_pad)){
			continue;
		}

		if(!strcmp((const char*)knowed_plaintext, (const char*)plaintext_no_pad)){
			if(DEBUG){
				printf("DEBUG: knowed_plaintext: %s\n\n", knowed_plaintext);
				printf("DEBUG: plaintext_no_pad: %s\n\n", plaintext_no_pad);
			}
			return true;
		}
		else
			continue;
		//cout<< "--------------------------------------------------------------------------------------------------------------"<<endl;

	}
	cout<< "**************************************************"<<endl;
	return false;
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


int main (void){
	
	/* ------------------------------------- GET KEY -------------------------------------------------------- */
	printf("------------------------------------- GET KEY --------------------------------------------------------\n");
	
	convert_key(iv_file_hex, iv_file);
	convert_key(key_aes_hex_file, key_aes_file);

	unsigned char* iv_aes = (unsigned char*)malloc(IV_KEYLENGTH);
	if(!iv_aes){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
	}
	memset(iv_aes, 0, IV_KEYLENGTH);
	strcpy((char*)iv_aes, (char*)read_data_from_file(iv_file).c_str());
	if(DEBUG){
		cout<<"IV: "<<iv_aes<<endl;
	}
	
	unsigned char* key_aes = (unsigned char*)malloc(AES_KEYLENGTH);
	if(!key_aes){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
	}
	memset(key_aes,0,AES_KEYLENGTH);
	strcpy((char*)key_aes, (char*)read_data_from_file(key_aes_file).c_str());
	if(DEBUG){
		cout<<"KEY TO ENCRYPT: "<<key_aes<<"s With length: "<<strlen((char*)key_aes)<<endl;

	}

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

	//Variables allocation	
	int ct_len;

	//Encryption needed variables
	unsigned char* ciphertext = (unsigned char*)malloc(PLAINTEXT_LENGHT + BLOCK_SIZE);
	if(!ciphertext){
		cerr << "ERROR: ciphertext space allocation went wrong" << endl;
		return -1;
	}
	memset(ciphertext,0,PLAINTEXT_LENGHT + BLOCK_SIZE);

	if(DEBUG){	
		printf("DEBUG: The Plaintext has length: %d\n", PLAINTEXT_LENGHT);
	}

	//Call the encryption function and obtain the Cyphertext
	int ret = cbc_encrypt_fragment(plaintext,PLAINTEXT_LENGHT,ciphertext,ct_len,key_aes, iv_aes);

	if(ret != 0){
		printf("Error during encryption\n");
	}
	if(DEBUG){
		printf("DEBUG: Encryption completed, the ciphertext is: %s\n",ciphertext);
		printf("DEBUG: The ciphertext has length: %d\n",ct_len);
	}

	// save the ciphertext on a txt file in hex format
	ofstream outfile;
	outfile.open(ciphertext_file, ios::out | ios::binary);
	char ciphertext_element_hex [3];
	for(int i=0; i<ct_len; i++){
		sprintf(ciphertext_element_hex, "%02X", (int)ciphertext[i]);
		outfile <<  ciphertext_element_hex;
	}
	outfile.close();
	
	if(DEBUG){
		cout << "ciphertext saved" << endl;
	}

	printf("------------------------------------------------------------------------------------------------------\n");
	/* ------------------------------------- Decryption  -------------------------------------------------------- */
	printf("------------------------------------- GET DEC --------------------------------------------------------\n");

	// Decryption needed variables
	unsigned char* decrypted_plaintext = (unsigned char*)malloc(ct_len);
	if(!decrypted_plaintext){
		cerr << "ERROR: decrypted_plaintext space allocation went wrong" << endl;
		return -1;
	}
	memset(decrypted_plaintext,0,ct_len);

	unsigned char* ciphertext_from_file = (unsigned char*)malloc(ct_len);
	if(!ciphertext_from_file){
		cerr << "ERROR: ciphertext_from_file space allocation went wrong" << endl;
	}
	memset(ciphertext_from_file,0,ct_len);
	
	// read from file and convert in ascii
	string file_contents = hexToASCII(read_data_from_file(ciphertext_file));

	// convert to unsigned char
	for(int i=0; i<ct_len; i++){
		ciphertext_from_file[i] = file_contents[i];
	}

	if(DEBUG){
		printf("DEBUG: the ciphertext: %s\n",ciphertext_from_file);
	}
	

	int decrypted_PLAINTEXT_LENGHT;
	//Call the decryption function 
	ret = 0;
	ret = cbc_decrypt_fragment (ciphertext_from_file, ct_len, decrypted_plaintext, decrypted_PLAINTEXT_LENGHT, key_aes, iv_aes);
	if(ret != 0){
		printf("Error during decryption\n");
	}

	//Allocate the buffer for PT without the padding
	unsigned char* decrypted_plaintext_no_pad = (unsigned char*)malloc(ct_len);
	if(!decrypted_plaintext_no_pad){
		cerr << "ERROR: decrypted_plaintext_no_pad space allocation went wrong" << endl;
		return -1;
	}
	memset(decrypted_plaintext_no_pad,0, ct_len);
	ret  = remove_padding(ct_len, decrypted_plaintext, decrypted_plaintext_no_pad);

	if(DEBUG){
		if(ret){
			printf("DEBUG: Padding removed successfully\n");
		}
		else{
			printf("DEBUG: Padding remove error\n");
		}
		
	}

	if(DEBUG){
		printf("DEBUG: Removed padding resulted in: %s\n", decrypted_plaintext_no_pad);
	}

	//TEST COMPLETED - PROCEED TO EXECUTE THE BRUTEFORCING
	printf("--------------------------------- PROCEED WITH BRUTEFORCING ----------------------------------------------\n");

	printf("Bytes to hack: %d\n", NUM_BITS_TO_HACK/8);

	//Copy the amount of known bits, ex. if 20 bits has to be discovered we copy all the key except the last two bytes, the last for bits will be removed using the shift later
    unsigned char* hacked_key = (unsigned char*)malloc(key_size);
	memset(hacked_key,0,key_size);
	memcpy(hacked_key, key_aes, (key_size));

	if(DEBUG){
		printf("HACKED KEY: %s\n", hacked_key);
		printf("KEY: %s\n", key_aes);
 	}

	memset(decrypted_plaintext,0,ct_len);
	memset(decrypted_plaintext_no_pad,0,ct_len);
	decrypted_PLAINTEXT_LENGHT = 0;
	
	if(DEBUG){
		printf("DEBUG: ** Start Bruteforcing **\n");
	}

	bool res = decryption_brute_force(hacked_key, plaintext, ciphertext, ct_len, decrypted_plaintext, decrypted_plaintext_no_pad, decrypted_PLAINTEXT_LENGHT, iv_aes);
	
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
	

	free(key_aes);
	free(iv_aes);
	free(plaintext);
	free(ciphertext);
	free(decrypted_plaintext);
	free(decrypted_plaintext_no_pad);

	return 1;
}
