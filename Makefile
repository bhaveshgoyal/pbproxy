CC = gcc

all: cli srv


srv:
	rm -rf ./server
	${CC} -o server srv.c

cli:
	rm -rf ./client
	${CC} -o client cli.c

clean:
	rm -rv client server
