/*
Just another example how to use lib openssl to do md5 hash

c00f3r[at]gmail[dot]com
by Cooler_

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

void 
md5(const void *content, ssize_t content_len, char *result, ssize_t result_len)
{
 EVP_MD_CTX md;
 unsigned char md_value[EVP_MAX_MD_SIZE],byte[3];
 unsigned int md_len=0,x=0,i=0;
 
 EVP_DigestInit(&md, EVP_md5());
 EVP_DigestUpdate(&md, content, (size_t) content_len);
 EVP_DigestFinal_ex(&md, md_value, &md_len);
 EVP_MD_CTX_cleanup(&md);

 while(x<md_len)
 {
  snprintf((char *)byte, sizeof(byte), "%02x", md_value[x]);
  result[i++]=byte[0];
  result[i++]=byte[1];
  x++;
 }
  
 result[i]=0;
}


int 
main()
{
 char result[64];
 // string input to md5
 char *data = "Castelo Ratimbum";
 md5(data, strlen(data), result, sizeof(result));

 fprintf(stdout,"%s\n", result);

 return 0;
}



