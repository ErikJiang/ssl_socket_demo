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
#define SERVERHTML		\
 						"<html>\n" \
 							"<body>\n" \
 								"<h3>Client Request:</h3>\n" \
 								"<p>\n{\n%s\n}\n</p>\n" \
 								"<br/>\n" \
 								"<h3>Server Response:</h3>\n" \
								"<p>\n{\nHello! I am Server!\n}\n</p>\n" \
 							"</body>\n" \
 						"</html>"


#endif	/* !_SSL_COMMON_H_ */

