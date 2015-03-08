#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF		4096
#define SERVER_CERT	"certs/server/server.crt"		//server cert file
#define SERVER_KEYF	"certs/server/server.key"		//server key file
#define ROOTCERTF	"certs/root/root.crt"			//root cert file
#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main()
{
	int err = 0;
	int listen_sd = 0;
	int sd = 0;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	SSL_CTX* ctx = NULL;			//SSL context handle
	SSL* ssl = NULL;			//SSL struct pointer
	X509* client_cert = NULL;		//Client X509 cert struct
	char* str = NULL;
	char buf[MAXBUF];
	SSL_METHOD *meth = NULL;		//SSL protocol

	//init OpenSSL environment
	SSL_library_init();			//init algorithms library
	OpenSSL_add_all_algorithms();		//Load all SSL algorithms
	SSL_load_error_strings();       	//receive SSL error info
	//SSL protocol version, V2 V3
	meth = SSLv23_server_method();
	//Create SSL context handle
	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, ROOTCERTF, NULL);
	//Set server cert
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	//Set server priKey
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEYF, SSL_FILETYPE_PEM) <= 0)
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

	SSL_CTX_set_cipher_list(ctx, "RC4-MD5");

	//Create Socket
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");
	//init sa_serv, Set TCP protocol,Port 8443
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(8443);
	//bind port
	err = bind(listen_sd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
	CHK_ERR(err, "bind");
	//Start receive TCP link
	err = listen(listen_sd, 5);
	CHK_ERR(err, "listen");
	client_len = sizeof(sa_cli);
	//Accept client TCP link
	sd = accept(listen_sd, (struct sockaddr*)&sa_cli, &client_len);
	CHK_ERR(sd, "accept");
	close(listen_sd);
	//Print client info
	printf("Connection from %s, port %d\n",
		inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));
	//Create SSL
	ssl = SSL_new(ctx);
	CHK_NULL(ssl);
	//Set link handle for SSL struct
	SSL_set_fd(ssl, sd);
	//Accept SSL link
	err = SSL_accept(ssl);
	CHK_SSL(err);
	//Get SSL link use algorithm
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	//Get client cert 
	client_cert = SSL_get_peer_certificate(ssl);
	if(client_cert != NULL)
	{
		printf("Client certifcate:\n");
		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t subject: %s\n", str);
		OPENSSL_free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t issuer: %s\n", str);
		OPENSSL_free(str);
		X509_free(client_cert);
	}
	else
	{
		printf("Client does not have certificate.\n");
	} 
	//Read client send info
	err = SSL_read(ssl, buf, sizeof(buf)-1);
	CHK_SSL(err);
	buf[err] = '\0';
	printf("Got %d chars:'%s'\n", err, buf);
	//Send message to client
	err = SSL_write(ssl, "Hello,I am server!", strlen("Hello,I am server!"));
	CHK_SSL(err);
	
	SSL_shutdown(ssl);	//shutdown SSL link
	SSL_free(ssl);
	close(sd);
	SSL_CTX_free(ctx);
	return 0;
}




