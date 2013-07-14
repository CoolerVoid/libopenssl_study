/*
This is another
AES cbc encryption/decryption with OpenSSL EVP example...

to run:
 $ gcc -Wall aes.c -o aes -lcrypto -lssl

c00f3r[at]gmail[dot]com

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

int 
main(int argc, char **argv)
{
  EVP_CIPHER_CTX en, de;

  unsigned int salt[] = {13371, 17331};
  unsigned char *key_data=NULL;
  int key_data_len=0, x=0;
  char *input[] = {"boa noite", "bom dia", "boa tarde", "this is sparta !", 
                   "faith no more","just another test",
                   NULL};

  key_data = (unsigned char *)"Coolerudos key";
  key_data_len = strlen("Coolerudos key");
  
  if(aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) 
  {
    fprintf(stdout,"Error init AES cipher\n");
    return -1;
  }

  while(input[x]) 
  {
    char *plaintext=NULL;
    unsigned char *ciphertext=NULL;
    int outlen=0, len=0;
    
    len = strlen(input[x])+1;
    outlen=len;
    ciphertext=aes_encrypt(&en, (unsigned char *)input[x], &len);
    fprintf(stdout,"aes_cipher: %s\n",ciphertext);
    plaintext=(char *)aes_decrypt(&de, ciphertext,&len);

    if(strncmp(plaintext, input[x], outlen)) 
      fprintf(stdout,"MISTAKE:\n  encrypt/decrypt: \"%s\"\n", input[x]);
    else 
      fprintf(stdout,"OK:\n encrypt/decrypt:  \"%s\"\n", plaintext);
    
    free(ciphertext);
    free(plaintext);
    x++;
  }

  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);

  return 0;
}
  


int 
aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int x=0, nrounds = 5;
  unsigned char key[32], iv[32];
  
  x = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if(x != 32) 
  {
    fprintf(stdout,"Key size %d bits - should be 256 bits\n", x);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

unsigned char 
*aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

unsigned char 
*aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}
