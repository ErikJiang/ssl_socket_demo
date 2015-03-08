#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF			4096
#define CLIENT_CERT		"certs/client/client.crt"
#define CLIENT_KEYF		"certs/client/client.key"
#define ROOTCERTF		"certs/root/root.crt"
#define SERVER_ADDR		"127.0.0.1"
#define SERVER_PORT		8443

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

void main()
{
	int err;
	int sd;				//socket handle
	struct sockaddr_in sa;		//sockaddr_in struct
	SSL_CTX* ctx;			//SSL context handle
	SSL* ssl;			//SSL struct pointer
	X509* server_cert;		//Server X509 cert struct
	char* str;
	char buf[MAXBUF];
	SSL_METHOD *meth;		//SSL protocol
	
	//init OpenSSL environment
	SSL_library_init();             //init algorithms library
	OpenSSL_add_all_algorithms();   //Load all SSL algorithms
	SSL_load_error_strings();       //receive SSL error info
	//SSL protocol version, V2 V3
	meth = SSLv23_client_method();
	//Create SSL context handle
	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx);
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, ROOTCERTF, NULL);	

	//Set server cert
	if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	//Set server priKey
	if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEYF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	//Check match PriKey & Cert 
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

	//Create Socket
	sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(sd, "socket");
	//init sa, Set TCP protocol,Port 8443
	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(SERVER_ADDR);
	sa.sin_port = htons(SERVER_PORT);
	//link server
	err = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
	CHK_ERR(err, "connect");
	//Create SSL
	ssl = SSL_new(ctx);
	CHK_NULL(ssl);
	//Set link handle for SSL struct
	SSL_set_fd(ssl, sd);
	//Start SSL link
	err = SSL_connect(ssl);
	CHK_SSL(err);
	//Get SSL link use algorithm
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	//Get client cert 
	server_cert = SSL_get_peer_certificate(ssl);
	if(server_cert != NULL)
	{
		printf("Server certifcate:\n");
		str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		CHK_NULL(str);
		printf("\t subject: %s\n", str);
		OPENSSL_free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
		CHK_NULL(str);
		printf("\t issuer: %s\n", str);
		OPENSSL_free(str);
		X509_free(server_cert);
	}
	else
	{
		printf("Server does not have certificate.\n");
	}
	
	//Send message to server
	err = SSL_write(ssl, "Hi, I am client!", strlen("Hi, I am client!"));
	CHK_SSL(err);
 
	//Read server send info
	err = SSL_read(ssl, buf, sizeof(buf)-1);
	CHK_SSL(err);
	buf[err] = '\0';
	printf("Got %d chars:'%s'\n", err, buf);

	SSL_shutdown(ssl);	//shutdown SSL link
	SSL_free(ssl);
	close(sd);
	SSL_CTX_free(ctx);
}




