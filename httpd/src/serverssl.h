#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define FAIL    -1
 
int test_isRoot();
int Listen_server_https(int port);
SSL_CTX* InitServerCTX(void);
void Load_Certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void List_Certificates(SSL* ssl);
void Server_callback(SSL* ssl); 

 

