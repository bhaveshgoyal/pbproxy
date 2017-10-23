CC = gcc

all: cli proxy


proxy:
	rm -rf ./pbproxy
	${CC} -o pbproxy pbproxy.c -lpthread -lcrypto

cli:
	rm -rf ./client
	${CC} -o client cli.c

clean:
	rm -rv client pbproxy
