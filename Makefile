CC = gcc

all: proxy

proxy:
	rm -rf ./pbproxy
	${CC} -o pbproxy pbproxy.c -lpthread -lcrypto

clean:
	rm -rv pbproxy
