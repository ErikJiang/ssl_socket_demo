/*
 *FileName  :   ssl_common.h
 *Author    :   JiangInk
 *Version   :   V0.1
 *Date      :   2015.03.10
*/

#ifndef _SSL_COMMON_H_
#define _SSL_COMMON_H_

#define FAIL			-1
#define MAXBUF			1024
#define PRIKEY_PASSWD	"123456"						//prikey password
#define ALGO_TYPE		"RC4-MD5"						//algorithm type
#define SERVER_CERT		"certs/server/server.crt"		//server cert file
#define SERVER_KEYF		"certs/server/server.key"		//server key file
#define CLIENT_CERT		"certs/client/client.crt"		//client cert file
#define CLIENT_KEYF		"certs/client/client.key"		//client key file
#define ROOTCERTF		"certs/root/root.crt"			//root cert file

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#endif	/* !_SSL_COMMON_H_ */

