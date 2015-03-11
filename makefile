LDFLAGS = -lssl -lcrypto

all : ssl_client ssl_server

ssl_client : ssl_client.o
    gcc -g $(LDFLAGS) $^ -o $@
ssl_server : ssl_server.o
    gcc -g $(LDFLAGS) $^ -o $@ 

ssl_client.o ssl_server.o : ssl_common.h

.PHONY : clean
clean :
    rm ssl_client ssl_server ssl_client.o ssl_server.o
