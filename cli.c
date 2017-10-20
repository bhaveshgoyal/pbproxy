#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define PORT 9090
#define MAXLINE 1024

int main(int argc, char **argv){
	int sockfd, n;
	char sendline[MAXLINE+1], recvline[MAXLINE+1];
	struct sockaddr_in servaddr;

	if (argc != 2){
		printf("usage: a.out <IP ADDRESS>");
	}
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			printf("Error Creating Socket");
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) < 0){
			printf("Can't translate Network IPs");
	}

	if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
			printf("connect error");

    while(fgets(sendline, MAXLINE, stdin) != NULL){
        write(sockfd, sendline, strlen(sendline));

        if (read(sockfd, recvline, MAXLINE) == 0)
            printf("Server Terminated");
        fputs(recvline, stdout);
		memset(recvline, 0, sizeof(recvline));
    }

	if (n < 0)
			printf("read error");

	exit(0);

}
