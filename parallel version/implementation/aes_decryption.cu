#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <math.h> 
#include <sstream>
#include <time.h>
#include <chrono>
#include <cuda.h>

using namespace std;

//Encrypting/Decrypting Parameters definition
#define AES_KEYLENGTH 32
#define IV_KEYLENGTH 16
#define SALT_KEYLENGTH 8
#define DEBUG true
#define BLOCK_SIZE 16
#define PLAINTEXT_LENGHT 445

//Brute Force configuration
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

//Utility function that handle encryption errors
void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
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
	
	int num_bits_to_hack = atoi(argv[1]);

	/* ------------------------------------- GET KEY -------------------------------------------------------- */
	printf("------------------------------------- GET KEY --------------------------------------------------------\n");
	
	convert_key(iv_file_hex, iv_file);
	convert_key(key_aes_hex_file, key_aes_file);

	unsigned char* iv_aes = (unsigned char*)malloc(IV_KEYLENGTH);
	if(!iv_aes){
		printf ("ERROR: iv space allocation went wrong\n");
	}
	memset(iv_aes, 0, IV_KEYLENGTH);
	strcpy((char*)iv_aes, (char*)read_data_from_file(iv_file).c_str());
	if(DEBUG){
		printf ("IV: %s\n", iv_aes);
	}
	
	unsigned char* key_aes = (unsigned char*)malloc(AES_KEYLENGTH);
	if(!key_aes){
        printf ("ERROR: key space allocation went wrong\n");
	}
	memset(key_aes,0,AES_KEYLENGTH);
	strcpy((char*)key_aes, (char*)read_data_from_file(key_aes_file).c_str());
	if(DEBUG){

        printf ("KEY TO ENCRYPT: %s With length: %lu\n", key_aes, strlen((char*)key_aes));
	}

    printf("------------------------------------------------------------------------------------------------------\n");
	/* ------------------------------------- GET PT -------------------------------------------------------- */
	printf("------------------------------------- GET PT ---------------------------------------------------------\n");



	//Allocating pt space
	unsigned char* plaintext = (unsigned char*)malloc(PLAINTEXT_LENGHT);
	if(!plaintext){
		printf ("ERROR: plaintext space allocation went wrong\n");
		return -1;
	}
	memset(plaintext,0,PLAINTEXT_LENGHT);
	strcpy((char*)plaintext, (char*)read_data_from_file(plaintext_file).c_str());

	if(DEBUG){
		printf("DEBUG: The Plaintext is: %s\n", plaintext);
	}


}