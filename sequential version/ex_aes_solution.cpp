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

using namespace std;

//Parameters definition
#define AES_KEYLENGTH 256
#define DEBUG true
#define BLOCK_SIZE 16

//              PARAMETERS
//  Key generated from openssl enc -aes-256-cbc -k secret -P -md sha1
//  salt = B51DE47CC865460E
//  key = 85926BE3DA736F475493C49276ED17D418A55A2CFD077D1215ED251C4A57D8EC
//  iv = D8596B739EFAC0460E861F9B7790F996

//Key in HEX format as global parameters
static const char salt[] = "B51DE47CC865460E";
static const char key[] = "85926BE3DA736F475493C49276ED17D418A55A2CFD077D1215ED251C4A57D8EC";
unsigned char* iv = (unsigned char*)"D8596B739EFAC0460E861F9B7790F996";

//Utility function that handle encryption errors
void handleErrors(void)
{
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
  int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());
  int ret;

  EVP_CIPHER_CTX* ctx;
	
	if (msg_len == 0) {
    std::cerr << "message length is not allowed: " << msg_len << endl;
    return -1;
  }
	
	try {
    // buffer for the ciphertext + padding
    ciphertext = (unsigned char*)malloc(msg_len + block_size);
		if (!ciphertext) {
			std::cerr << "malloc ciphertext failed" << endl;
			throw 1;
	}
  // context definition
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    cerr << "context definition failed" << endl;
    throw 2;
  }
		
  // init encryption
  ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), symmetric_key, iv);
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

    if (error_code > 3){
      free(iv);
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
  	// buffer for the plaintext
  	plaintext = (unsigned char*)malloc(cipherlen);
		if (!plaintext) {
			cerr << "ERR: malloc plaintext failed" << endl;
			throw 1;
		}
		memset(plaintext,0,cipherlen);

		// context definition
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			cerr << "ERR: context definition failed" << endl;
			throw 2;
		}

		// init encryption
		ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), symmetric_key, iv);
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
	if(DEBUG)
		printf("DEBUG: Decryption completed successfully\n");
  return 0;
}


int main (void){
	// First of all get the Plaintext
	fstream getFile;
	string tp;
	getFile.open("lorem_ipsum.txt",ios::in);
  if (getFile.is_open()){
    getline(getFile, tp); //It has been written on one single row, so no cyclic reading needed
  	getFile.close();
  }

	unsigned char* plaintext = (unsigned char*)malloc(tp.length()+1);
	if(!plaintext){
		cerr << "ERROR: plaintext space allocation went wrong" << endl;
		return -1;
	}
	memset(plaintext,0,tp.length()+1);
	strcpy((char*)plaintext, (char*)tp.c_str());

	if(DEBUG)
		printf("DEBUG: The Plaintext is: %s\n", plaintext);
	
	unsigned char* ciphertext;
	unsigned char* decrypted_plaintext;

	unsigned char aes_key[AES_KEYLENGTH];
	long int pt_len = strlen((char*)plaintext);
	int ct_len;

	if(DEBUG)
	  printf("DEBUG: The Plaintext has length: %ld\n", pt_len);

	//Clean the memory
	memset(aes_key,0,AES_KEYLENGTH/8);

	//Copy the key as a bitstream
	strcpy((char*) aes_key, key);
	if(DEBUG)
	  printf("DEBUG: The key is: %s\n", aes_key);

	//Call the encryption function and obtain the Cyphertext
	int ret = cbc_encrypt_fragment(plaintext,pt_len,ciphertext,ct_len,aes_key);

	if(DEBUG)
	  printf("DEBUG: Encryption completed, the ciphertext has length: %d\n",ct_len);
	if(ret != 0)
		printf("Error during encryption\n");

	int decrypted_pt_len;
	//Call the decryption function 
	cbc_decrypt_fragment (ciphertext, ct_len, decrypted_plaintext, decrypted_pt_len, aes_key);

	if(DEBUG)
	  printf("DEBUG: Decryption completed and resulted in: %s\n", decrypted_plaintext);

	//TEST COMPLETED, NOW PROCEED TO EXECUTE THE BRUTEFORCING


	// ------------------------------------------------------ //

	//Clean memory
	free(ciphertext);
	free(decrypted_plaintext);
	free(plaintext);

	return 1;
}
