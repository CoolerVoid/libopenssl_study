#include "serverssl.h"
 
int test_isRoot()
{
	if(getuid() != 0)
        	return 0;
    	else
        	return 1;
}

int Listen_server_https(int port)
{   
	int sd;
    	struct sockaddr_in addr;
 
    	sd = socket(PF_INET, SOCK_STREAM, 0);
    	bzero(&addr, sizeof(addr));
    	addr.sin_family =  AF_UNSPEC;
    	addr.sin_port = htons(port);
    	addr.sin_addr.s_addr = INADDR_ANY;

    	if(bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    	{
        	perror("can't bind this port");
        	abort();
    	}
 
   	if(listen(sd, 10) != 0)
   	{
        	perror("Cannot listening port");
        	abort();
    	}

	return sd;
}
 

SSL_CTX* InitServerCTX(void)
{   
    	SSL_CTX *ctx;
 
    	OpenSSL_add_all_algorithms();  
    	SSL_load_error_strings();    
    	ctx = SSL_CTX_new(TLSv1_2_server_method());   

    	if(ctx == NULL)
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}

	return ctx;
}
 
void Load_Certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}

    	if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}

    	if(!SSL_CTX_check_private_key(ctx) )
    	{
        	fprintf(stderr, "Private key does not match the public certificate\n");
        	abort();
    	}
}
 
void List_Certificates(SSL* ssl)
{   
	X509 *cert;
    	char *line,*line2;
 
    	cert = SSL_get_peer_certificate(ssl); 

    	if(cert != NULL)
    	{
        	printf("List certificate:\n");
        	line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        	printf("Subject: %s\n", line);
        	free(line);
		line=NULL;

        	line2 = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        	printf("Issuer name: %s\n", line2);
        	free(line2);
		line2=NULL;
        	X509_free(cert);

    	} else 
        	printf("Cannot load certificates. \n function List_Certificates()\n");
	
}
 
void Server_callback(SSL* ssl) 
{   
	char buf[1024],back[1024];
 	int sd, bytes;
	const char* response="HTTP/1.1 200 Ok\n\n<html><body><h1>HTTPd - TLS server test</h1><pre>%s</pre></body></html>\n";
 
	if(SSL_accept(ssl) == FAIL)    
	        ERR_print_errors_fp(stderr);
    	else
    	{
        	List_Certificates(ssl);        
        	bytes = SSL_read(ssl, buf, sizeof(buf)); 
        	if(bytes > 0 && bytes <= 1023)
        	{
            		buf[bytes] = 0;
            		printf("Client msg: \"%s\"\n", buf);
            		sprintf(back, response, buf);  
            		SSL_write(ssl, back, strlen(back)); //equivalend to send() of sockets
        	} else
            		ERR_print_errors_fp(stderr);
    	}

    	sd = SSL_get_fd(ssl);       
    	SSL_free(ssl);         
    	close(sd);          
}
 
