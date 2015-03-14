/*
 *FileName  :   ssl_client.c
 *Author    :   JiangInk
 *Version   :   V0.1
 *Date      :   2015.03.10
*/

/*****************************************************************************/
/*** ssl_client.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL client.                                            ***/
/*****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ssl_common.h"

/*---------------------------------------------------------------------*/
/*--- open_connection - create socket and connect to server.        ---*/
/*---------------------------------------------------------------------*/
int open_connection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- init_client_ctx - initialize the SSL engine.                  ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* init_client_ctx(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();                 /* init algorithms library */
    OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */
    SSL_load_error_strings();           /* load all error messages */
    //method = SSLv23_client_method();  /* create new server-method instance */
    method = TLSv1_client_method();
    ctx = SSL_CTX_new(method);          /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- verify_callback - SSL_CTX_set_verify callback function.       ---*/
/*---------------------------------------------------------------------*/
int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
    if (ok)
    {
        fprintf(stderr, "verify_callback\n{\n");
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);

        fprintf(stderr, "certificate at depth: %i\n", depth);
        memset(data, 0, sizeof(data));
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "issuer = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "subject = %s\n", data);
        fprintf(stderr, "error status:  %i:%s\n}\n", err, X509_verify_cert_error_string(err));
    }
    return ok;
}

/*---------------------------------------------------------------------*/
/*--- load_certificates - load from files.                          ---*/
/*---------------------------------------------------------------------*/
void load_certificates(SSL_CTX* ctx, char* CaFile, char* CertFile, char* KeyFile)
{
    #if 1
    /* set maximum depth for the certificate chain */
    //SSL_CTX_set_verify_depth(ctx, 1);
    /* set verify mode*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    /* load CA certificate file */
    if (SSL_CTX_load_verify_locations(ctx, CaFile, NULL) <=0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    #endif
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set server private key password */ 
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)PRIKEY_PASSWD);
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    /* set SSL cipher type */
    //SSL_CTX_set_cipher_list(ctx, ALGO_TYPE);
}

/*---------------------------------------------------------------------*/
/*--- show_certs_info - print out the certificates.                 ---*/
/*---------------------------------------------------------------------*/
void show_certs_info(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);   /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);                         /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);                         /* free the malloc'ed string */
        X509_free(cert);                    /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
	hostname = strings[1];
	portnum = strings[2];

    ctx = init_client_ctx();                                        /* initialize SSL */
    load_certificates(ctx, ROOTCERTF, CLIENT_CERT, CLIENT_KEYF);    /* load certs */
    server = open_connection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);                 /* create new SSL connection state */
    SSL_set_fd(ssl, server);            /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )     /* perform the connection */
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        char *msg = "Hi! I am Client!";

        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        show_certs_info(ssl);                       /* get any certs */
        SSL_write(ssl, msg, strlen(msg));           /* encrypt & send message */
        memset(buf, 0, sizeof(buf));
        bytes = SSL_read(ssl, buf, sizeof(buf)-1);  /* get reply & decrypt */
        buf[bytes] = '\0';
        printf("Server msg: \"%s\"\n", buf);
        SSL_shutdown(ssl);                          /* shutdown SSL link */
        SSL_free(ssl);                              /* release connection state */
    }
    close(server);                                  /* close socket */
    SSL_CTX_free(ctx);                              /* release context */

    return 0;
}
