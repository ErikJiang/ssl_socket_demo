# SSLSocketDemo
基于OpenSSL实现C/S SSL Socket简单交互程序

## 关于客户端及服务端程序的编译：
``` bash
$ gcc -g -o client client.c -lssl -lcrypto
$ gcc -g -o server server.c -lssl -lcrypto
```

## 涉及到证书及密钥生成方法说明：

### 1、CA根密钥及证书生成过程:
``` bash
$ openssl genrsa -des3 -out root.key
$ openssl req -new -key root.key -out root.csr
$ openssl x509 -req -days 3650 -sha1 -extensions v3_ca -signkey root.key -in root.csr -out root.crt
``` 

### 2、服务端密钥及证书生成过程：
``` bash
$ openssl genrsa -des3 -out server.key 2048
$ openssl req -new -key server.key -out server.csr
$ openssl x509 -req -days 3650 -sha1 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in server.csr -out server.crt
```
### 3、客户端密钥及证书生成过程：
``` bash
$ openssl genrsa -des3 -out client.key 2048
$ openssl req -new -key client.key -out client.csr
$ openssl x509 -req -days 3650 -sha1 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in client.csr -out client.crt
```
**合并证书和密钥生成PFX文件：**
``` bash
$ openssl pkcs12 -export -in client.crt -inkey client.key -out client.pfx
```

