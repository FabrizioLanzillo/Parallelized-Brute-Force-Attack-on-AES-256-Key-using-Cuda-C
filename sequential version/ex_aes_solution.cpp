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


//Utility function that handle encryption errors
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/** Function that perform an encryption on AES-256
 * plaintext: Contain the data to be encrypted
 * plaintext_len: Contain the length of the data to be encrypted
 * key: contain the symmetric key to be used for encryption
 * iv: random nonce
 * ciphertext: filled at the end of the encryption, contain the whole encrypted message
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  //Structure filled with encryption informations
  EVP_CIPHER_CTX *ctx;
  //Utility variables
  int len;
  int ciphertext_len;

  //Create and initialise the context
  ctx = EVP_CIPHER_CTX_new();
  //Encrypt init
  EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, iv);

  //Calculate the number of blocks to be encrypted
  uintmax_t n_blocks = (plaintext_len / 32) + 1;
  unsigned char* ct_temp;

  //Calculate the encrypted block on each cycle for each block 
  for (uintmax_t i = 0; i < n_blocks; i++){
    if (EVP_EncryptUpdate(ctx, ct_temp, &len, plaintext, plaintext_len) == 0)
	    handleErrors();
    ciphertext_len = len;

  }


  //Encrypt Final. Finalize the encryption and adds the padding
  if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
	handleErrors();
  ciphertext_len += len;

  // MUST ALWAYS BE CALLED!!!!!!!!!!
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();

  // Decrypt Init
  EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv);

  // Decrypt Update: one call is enough because our mesage is very short.
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  // Decryption Finalize
  if(1 != EVP_DecryptFinal(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  // Clean the context!
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}



int main (void){
  //256 bit key (32 characters * 8 bit)
  unsigned char *key = (unsigned char *)"12345363265462567588718362176679 ";

  //Our Plaintext
  unsigned char plaintext[] = "This is a Very Short message";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, depending on the
   * algorithm and mode*/
  unsigned char* ciphertext = (unsigned char *) malloc(sizeof(plaintext)+16);

  int decryptedtext_len, ciphertext_len;
  // Encrypt utility function
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, NULL, ciphertext);

  // Redirect our ciphertext to the terminal
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  // Buffer for the decrypted text 
  unsigned char* decryptedtext = (unsigned char *) malloc(ciphertext_len);

  // Decrypt the ciphertext
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, NULL, decryptedtext);

  // Add a NULL terminator. We are expecting printable text
  decryptedtext[decryptedtext_len] = '\0';

  // Show the decrypted text 
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);
  
  return 0;
}
