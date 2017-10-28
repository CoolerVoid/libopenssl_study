#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
/*
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define FAIL    -1
 */
#include "serverssl.h"
 
int main(int count, char *strings[])
{
	SSL_CTX *ctx;
	int server;
	char *portnum;
 
	if(!test_isRoot())
    	{
        	printf("This program must be run as root user!!");
        	exit(0);
    	}

    	if(count != 2)
    	{
        	printf("follow command: %s <portnum>\n", strings[0]);
        	exit(0);
    	}

    	SSL_library_init();
 
    	portnum = strings[1];
    	ctx = InitServerCTX();        
    	Load_Certificates(ctx, "keys/testcert.pem", "keys/testcert.pem"); 
	int port=(int)strtol(portnum,NULL,10);
    	server = Listen_server_https(port);    

    	while(1)
   	{   
		struct sockaddr_in addr;
        	socklen_t len = sizeof(addr);
        	SSL *ssl;
 
        	int client = accept(server, (struct sockaddr*)&addr, &len);  
        	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        	ssl = SSL_new(ctx);              
        	SSL_set_fd(ssl, client);     
        	Server_callback(ssl);         
    	}

    	close(server);          
    	SSL_CTX_free(ctx);
	exit(0);   
}
