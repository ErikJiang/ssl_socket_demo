## ssl_socket_demo
基于OpenSSL工具包实现SSL Client/Server简单安全交互程序

### 一、关于客户端及服务端程序的编译：
```bash
$ make    #编译
$ make clean    #编译清除     
```

### 二、涉及到证书及密钥生成方法说明：

#### 1、CA根密钥及证书生成过程:
```bash
# 生成根密钥
$ openssl genrsa -des3 -out root.key
# 生成根证书
$ openssl req -new -key root.key -out root.csr
# 根证书自签名
$ openssl x509 -req -days 3650 -sha1 -extensions v3_ca -signkey root.key -in root.csr -out root.crt
``` 

#### 2、服务端密钥及证书生成过程：
```bash
# 生成服务端密钥
$ openssl genrsa -des3 -out server.key 2048
# 生成服务端证书
$ openssl req -new -key server.key -out server.csr
# 使用根证书及密钥签发服务端子证书
$ openssl x509 -req -days 3650 -sha1 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in server.csr -out server.crt
```
#### 3、客户端密钥及证书生成过程：
```bash
# 生成客户端密钥
$ openssl genrsa -des3 -out client.key 2048
# 生成客户端证书
$ openssl req -new -key client.key -out client.csr
# 使用根证书及密钥签发客户端子证书
$ openssl x509 -req -days 3650 -sha1 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in client.csr -out client.crt
```
**合并证书和密钥生成PFX文件：**
```bash
# PFX格式供客户端安装
$ openssl pkcs12 -export -in client.crt -inkey client.key -out client.pfx
```

