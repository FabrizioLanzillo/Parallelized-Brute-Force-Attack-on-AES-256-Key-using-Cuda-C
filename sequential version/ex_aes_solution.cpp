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

//Parameters definition
#define AES_KEYLENGTH 32
#define DEBUG true
#define BLOCK_SIZE 16

//Brute Force configuration
#define NUM_BYTES_TO_HACK 16
#define BASE_NUMBER 16


//              PARAMETERS
//  Key generated from openssl enc -aes-256-cbc -k secret -P -md sha1
//  salt = B51DE47CC865460E
//  key = 85926BE3DA736F475493C49276ED17D418A55A2CFD077D1215ED251C4A57D8EC
//  85 92 6B E3 DA 73 6F 47 54 93 C4 92 76 ED 17 D4 18 A5 5A 2C FD 07 7D 12 15 ED 25 1C 4A 57 D8 EC  
//  iv = D8596B739EFAC0460E861F9B7790F996

//Key in HEX format as global parameters
static const char salt[] = "B51DE47CC865460E";
static const char key[] = "85926BE3DA736F475493C49276ED17D418A55A2CFD077D1215ED251C4A57D8EC";
unsigned char* iv = (unsigned char*)"D8596B739EFAC0460E861F9B7790F996";
static const int key_size = 32;

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
int cbc_encrypt_fragment(unsigned char* msg, int msg_len, unsigned char*& ciphertext, int& cipherlen, unsigned char* symmetric_key){
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

/** Function that perform the decryption on AES-256
 * ciphertext: contain the bitstream to be decrypted
 * cipherlen: contain the length of the cipher
 * plaintext: variable in which we return the decrypted PT
 * plainlen: length of the decrypted PT
 * symmetric_key: AES key used for decryption
 */
int cbc_decrypt_fragment (unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, int& plainlen, unsigned char* symmetric_key){
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
			cerr << "ERR: failed decrypt finalization" << endl;
			ERR_print_errors_fp(stderr);
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
    
		free(plaintext);

		if (error_code > 1){
			EVP_CIPHER_CTX_free(ctx);
		}

		printf("ERROR DURING DECRYPTION: %d\n", error_code);

	}

	if(DEBUG){
		printf("DEBUG: Decryption completed successfully\n");
	}
	return 0;
}

bool decryption_brute_force(unsigned char*& hacked_key, unsigned char* knowed_plaintext, unsigned char* ciphertext, int cipherlen, unsigned char*& plaintext, unsigned char*& plaintext_no_pad, int& plainlen){

	// array containg de character of the key that has to be hacked
	char bytes_to_hack [NUM_BYTES_TO_HACK +1];
	int padding_size_bytes;
	for(int i = 0; i < pow (BASE_NUMBER, NUM_BYTES_TO_HACK); i++){

		cout<< "-------------------------------------------- Attempt #"<<i+1<<" ----------------------------------------------"<<endl;
		// clean of the array
		memset(bytes_to_hack,0,key_size);
		memset(plaintext,0,cipherlen);
		memset(plaintext_no_pad,0,cipherlen);
		// the . set the precision and * the number of bytes to represent the number in hex
		sprintf (bytes_to_hack, "%.*X", NUM_BYTES_TO_HACK, i);
		
		// we assemble the key with the new character
		memcpy(hacked_key + ((key_size - NUM_BYTES_TO_HACK)), bytes_to_hack, NUM_BYTES_TO_HACK);
		if(DEBUG){
			printf ("[%s] is the key\n", hacked_key);
		}

		
		if(DEBUG){
			printf("DEBUG: knowed_plaintext: %s\n", knowed_plaintext);
			printf("DEBUG: plaintext_no_pad: %s\n", plaintext_no_pad);
		}

		int ret = cbc_decrypt_fragment (ciphertext, cipherlen, plaintext, plainlen, hacked_key);
		if(ret != 0){
			printf("Error during decryption\n");
			return false;
		}

		padding_size_bytes = (int)plaintext[cipherlen-1];
		if(DEBUG){
			printf("DEBUG: The size of the padding to remove is: %d\n", padding_size_bytes);
		}
		//Copy the PT without padding
		memset(plaintext_no_pad,0,cipherlen - padding_size_bytes);
		memcpy(plaintext_no_pad, plaintext, cipherlen - padding_size_bytes);

		if(DEBUG){
			printf("DEBUG: knowed_plaintext: %s\n", knowed_plaintext);
			printf("DEBUG: plaintext_no_pad: %s\n", plaintext_no_pad);
		}

		if(!strcmp((char *)knowed_plaintext,(char *)plaintext_no_pad)){
			return true;
		}
		else{
			printf("Key not found\n");
			memset(plaintext_no_pad,0,plainlen);
		}
		cout<< "--------------------------------------------------------------------------------------------------------------"<<endl;
	}


	cout<< "**************************************************"<<endl;
	return false;
}


int main (void){
	
	/* ------------------------------------- GET PT -------------------------------------------------------- */

	fstream getFile;
	string tp;
	getFile.open("lorem_ipsum.txt",ios::in);

	if (getFile.is_open()){
		getline(getFile, tp); //It has been written on one single row, so no cyclic reading needed
		getFile.close();
	}

	//Allocating pt space
	unsigned char* plaintext = (unsigned char*)malloc(tp.length()+1);
	if(!plaintext){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
		return -1;
	}

	//Conversion from string to unsigned char*
	memset(plaintext,0,tp.length()+1);
	strcpy((char*)plaintext, (char*)tp.c_str());

	if(DEBUG){
		printf("DEBUG: The Plaintext is: %s\n", plaintext);
	}

	/* ------------------------------------- GET KEY -------------------------------------------------------- */

	unsigned char* k = (unsigned char*)malloc(32);
	memset(k,0,32);
	string s;

	getFile.open("key_aes.txt",ios::in);

	if (getFile.is_open()){
		getline(getFile, s); //It has been written on one single row, so no cyclic reading needed
		getFile.close();
	}

	memcpy(k,s.c_str(),32);
	cout<<"KEY: "<<k<<endl;

	//Variables allocation		
	long int pt_len = strlen((char*)plaintext);
	int ct_len;

	//Encryption needed variables
	unsigned char* ciphertext = (unsigned char*)malloc(pt_len + BLOCK_SIZE);
	if(!ciphertext){
		cerr << "ERROR: ciphertext space allocation went wrong" << endl;
		return -1;
	}
	memset(ciphertext,0,pt_len + BLOCK_SIZE);

	if(DEBUG){	
		printf("DEBUG: The Plaintext has length: %ld\n", pt_len);
	}

	//Call the encryption function and obtain the Cyphertext
	int ret = cbc_encrypt_fragment(plaintext,pt_len,ciphertext,ct_len,k);

	if(DEBUG){
		printf("DEBUG: Encryption completed, the ciphertext has length: %d\n",ct_len);
	}
	if(ret != 0){
		printf("Error during encryption\n");
	}

	// Decryption needed variables
	unsigned char* decrypted_plaintext = (unsigned char*)malloc(ct_len);
	if(!decrypted_plaintext){
		cerr << "ERROR: decrypted_plaintext space allocation went wrong" << endl;
		return -1;
	}
	memset(decrypted_plaintext,0,ct_len);

	int decrypted_pt_len;
	//Call the decryption function 
	ret = 0;
	ret = cbc_decrypt_fragment (ciphertext, ct_len, decrypted_plaintext, decrypted_pt_len, k);
	if(ret != 0){
		printf("Error during decryption\n");
	}

	//Calculating the size of the Plaintext without padding
	int padding_size_bytes = (int)decrypted_plaintext[ct_len-1];

	if(DEBUG){
		printf("DEBUG: The size of the padding to remove is: %d\n", padding_size_bytes);
	}

	//Allocate the buffer for PT without the padding
	unsigned char* decrypted_plaintext_no_pad = (unsigned char*)malloc(ct_len - padding_size_bytes);
	if(!decrypted_plaintext_no_pad){
		cerr << "ERROR: decrypted_plaintext_no_pad space allocation went wrong" << endl;
		return -1;
	}
	//Copy the PT without padding
	memset(decrypted_plaintext_no_pad,0,ct_len - padding_size_bytes);
	memcpy(decrypted_plaintext_no_pad, plaintext, ct_len - padding_size_bytes);
	

	if(DEBUG){
		printf("DEBUG: Padding removed successfully\n");
	}

	if(DEBUG){
		printf("DEBUG: Decryption completed and resulted in: %s\n", decrypted_plaintext_no_pad);
	}

	//TEST COMPLETED - PROCEED TO EXECUTE THE BRUTEFORCING

    unsigned char* hacked_key = (unsigned char*)malloc(key_size);
    memcpy(hacked_key, key, (key_size - NUM_BYTES_TO_HACK));

	memset(decrypted_plaintext,0,ct_len);
	memset(decrypted_plaintext_no_pad,0,ct_len);
	decrypted_pt_len = 0;
	
	if(DEBUG){
		printf("DEBUG: Start Hack\n");
	}

	bool res = decryption_brute_force(hacked_key, plaintext, ciphertext, ct_len, decrypted_plaintext, decrypted_plaintext_no_pad, decrypted_pt_len);
	if(DEBUG){
		printf("DEBUG:pippo\n");
	}
	
	if(!res){
		printf("Error during brute forcing attack\n");
	}

	if(DEBUG){
		printf("DEBUG: Brute Force completed and key obtained: %s\n", hacked_key);
	}
	*/
	// ------------------------------------------------------ //


	free(k);

	return 1;
}
