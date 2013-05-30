/* 
 simple blowfish with str,  example...
by Cooler_
c00f3r[at]gmail[dot]com

gcc -o code code.c -lssl -lcrypto
 *                               */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/blowfish.h>

#define SIZE 256


unsigned char *bf_str_encrypt(unsigned char * str)
{

 if(!strlen(str)) 
  return "."; 

 unsigned char *ptr=str;
 unsigned char *encrypt=(unsigned char *)malloc(sizeof(char)*512);
 unsigned char *tmp=(unsigned char *)malloc(sizeof(char)*9);
 unsigned char *out = calloc(9, sizeof(unsigned char *));

 BF_KEY *key = calloc(9, 9);
 BF_set_key(key, SIZE, (const unsigned char*)"TestKey" );

 unsigned int jmp=0,counter=0;

 bzero(encrypt,512);

 while(*ptr != '\0' && counter != 512)
 {
  *(tmp+jmp)=*ptr;
  if(jmp==7)
  {
   BF_ecb_encrypt(tmp, out, key, BF_ENCRYPT);
   strcat(encrypt,out);
   bzero(out,9);
   bzero(tmp,9);
   jmp=-1;
  }
  ptr++; 
  jmp++;
  counter++;
 }

 if(strlen(tmp)<=8)
 {
   bzero(out,9);
    while(strlen(tmp)<7)
     strcat(tmp,".");
   BF_ecb_encrypt(tmp, out, key, BF_ENCRYPT);
   strcat(encrypt,out);
 }


 bzero(out,9);
 bzero(tmp,9);
 if(out)
  free(out);
 if(tmp)
  free(tmp); 

 fprintf(stdout,"Result %s\n",encrypt);

 return encrypt;
}


unsigned char *bf_str_decrypt(unsigned char * str)
{
 if(!strlen(str)) 
  return "."; 

 unsigned char *ptr=str;
 unsigned char *decrypt=(unsigned char *)malloc(sizeof(char)*512);
 unsigned char *tmp=(unsigned char *)malloc(sizeof(char)*9);
 unsigned char *out = calloc(9, sizeof(unsigned char *));
 

  BF_KEY *key = calloc(9, 9);
  BF_set_key(key, SIZE, (const unsigned char*)"TestKey" );

  unsigned int jmp=0,counter=0;

  bzero(decrypt,512);

  while(*ptr != '\0' && counter != 511)
  {
   *(tmp+jmp)=*ptr;
   if(jmp==7)
   {
    BF_ecb_encrypt(tmp, out, key, BF_DECRYPT);
    strcat(decrypt,out);
    bzero(out,9);
    bzero(tmp,9);
    jmp=-1;
   }
   ptr++; 
   jmp++;
   counter++;
  }

  if( jmp > 0 && jmp < 8)
  {
    BF_ecb_encrypt(tmp, out, key, BF_DECRYPT);
    strcat(decrypt,out);
  }

  bzero(out,9);
  bzero(tmp,9);

  if(out)
   free(out);
  if(tmp)
   free(tmp); 
 
 return decrypt;

}






int main()
{
  unsigned char *in = (unsigned char *)"TestData";
  unsigned char *out = calloc(1024, sizeof(unsigned char *));
  unsigned char *out2 = calloc(1024, sizeof(unsigned char *));

  unsigned char *out3 = calloc(1024, sizeof(unsigned char *));
  BF_KEY *key = calloc(256, 256);

  /* set up a test key */
  BF_set_key(key, SIZE, (const unsigned char*)"TestKey" );

  /* test out encryption */
  BF_ecb_encrypt(in, out, key, BF_ENCRYPT);
  printf("%s\n", out);

  /* test out decryption */
  BF_ecb_encrypt(out, out2, key, BF_DECRYPT);
  printf("%s\n", out2);

//  printf ("result %s \n",bf_str_encrypt("Linux"));
  unsigned char *out4=bf_str_encrypt("seu madruga na vila");

  printf ("result %s \n",out4);
  puts("OK!"); 
  unsigned char *out5=bf_str_decrypt(out4);

  printf ("result decrypt %s \n",out5);

  if(out)
   free(out);

  if(out2)
   free(out2);

  if(out4)
   free(out4);

  if(out5)
   free(out5);

  return 0;
}
