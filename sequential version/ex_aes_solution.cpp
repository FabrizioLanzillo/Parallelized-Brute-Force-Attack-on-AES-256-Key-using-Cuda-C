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

//Parameters definition
#define AES_KEYLENGTH 256
#define DEBUG true

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
 * plaintext: Contain the data to be encrypted
 * plaintext_len: Contain the length of the data to be encrypted
 * iv: random nonce
 * ciphertext: filled at the end of the encryption, contain the whole encrypted message
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char* aes_key, unsigned char *iv, unsigned char *ciphertext)
{
  //Structure filled with encryption informations
  EVP_CIPHER_CTX *ctx;
  //Utility variables
  int len;
  int ciphertext_len;
  int ret;

  //Create and initialise the context
  ctx = EVP_CIPHER_CTX_new();
  //Encrypt init
  ret = EVP_EncryptInit(ctx, EVP_aes_256_cbc(), (const unsigned char*)aes_key, iv);
  if (DEBUG && ret != -1)
    printf("Context set up SUCCESSFULLY\n");
  else  
    printf("Context set up ERROR with code: %d", ret);

  // Calculate the encryption 
  int n_blocks = plaintext_len / 16;
  //for(int i = 0; i < n_blocks; i++){
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
      handleErrors();
      return -1;
    }
  //}

  if(DEBUG){
    printf("The cyphertext has length: %d\n", len);
  }

  // Finalize the encrption, some bytes may be added at this stage
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
    handleErrors();
    return -1;
  }
  ciphertext_len += len;
  //Free the context
  EVP_CIPHER_CTX_free(ctx);
  
  return ciphertext_len;
}

/** Function that perform a decryption on AES-256
 * plaintext: Contain the data to be encrypted
 * ciphertext_len: Contain the length of the encrypted data
 * iv: random nonce
 * aes_key: key for symmetric decryption
 * ciphertext: filled with the encryption, contain the whole encrypted message
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, char* aes_key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ret;
  int plaintext_len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if(!ctx)
    handleErrors();

  // Decrypt Init
  ret = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), (const unsigned char*)aes_key, iv);
  if (DEBUG && ret != -1)
    printf("Context set up SUCCESSFULLY\n");
  else if(DEBUG && ret < 0)
    printf("Context set up ERROR with code: %d", ret);

  // Decrypt Update: one call is enough because our mesage is very short.
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  printf("CIAO\n");
  // Decryption Finalize
  if(1 != EVP_DecryptFinal(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  // Clean the context!
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}



int main (void){
    // TODO - Fix the string with the one obtained from a File, it may be more efficient to load it chunk by chunk inside the encrypt if the file is pretty big

    // First of all get the Plaintext
    unsigned char* plaintext = (unsigned char*)"Hi I'm Federico and this is a string!";
    
    unsigned char* ciphertext = (unsigned char*)malloc(sizeof(char)*1024);
    unsigned char* decrypted_plaintext = (unsigned char*)malloc(sizeof(char)*1024);

    memset(ciphertext,0,1024);
    memset(decrypted_plaintext,0,1024);

    unsigned char aes_key[AES_KEYLENGTH];
    long int pt_len = strlen((char*)plaintext);
    long int ct_len;

    if(DEBUG)
      printf("The Plaintext has length: %ld\n", pt_len);

    //Clean the memory
    memset(aes_key,0,AES_KEYLENGTH/8);

    //Copy the key as a bitstream
    strcpy((char*) aes_key, key);
    if(DEBUG)
      printf("The key is: %s\n", aes_key);

    //Call the encryption function and obtain the Cyphertext
    ct_len = encrypt(plaintext,pt_len,aes_key,iv,ciphertext);

    if(DEBUG)
      printf("Encryption completed\n");

    //Call the decryption function 
    decrypt(ciphertext,ct_len,(char*) aes_key,iv,decrypted_plaintext);

    if(DEBUG)
      printf("Decryption completed and resulted in: %s\n", decrypted_plaintext);

    free(ciphertext);
    free(decrypted_plaintext);
    return 1;
}
