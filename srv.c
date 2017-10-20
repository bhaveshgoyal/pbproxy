#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m\n\0"
#define MAXLINE 1024
#define LISTENQ 1024

int main(int argc, char **argv){

    struct sockaddr_in servaddr;
    int sockfd, connfd;
    char buf[MAXLINE + 1];
    ssize_t n;

    if (argc < 3)
        printf("Illegal usage: server echoport timeport");

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        printf("Error Creating Socket");
    bzero(&(servaddr), sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((int) strtol(argv[2], (char **)NULL, 10));
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

    listen(sockfd, LISTENQ);

    connfd = accept(sockfd, (struct sockaddr *) NULL, NULL);
    char sendbuf[MAXLINE+1] = {0};
    char tempbuf[MAXLINE+1] = {0};
    while((n = read(connfd, buf, MAXLINE)) > 0){        
            buf[n] = '\0';
            strcat(sendbuf, ANSI_COLOR_CYAN);
            strncpy(tempbuf, buf, strlen(buf)-1); // Remove NULL from buf
            strcat(sendbuf, tempbuf);
            strcat(sendbuf, ANSI_COLOR_RESET);
            
           	write(connfd, sendbuf, strlen(sendbuf));

            memset(sendbuf, 0, sizeof(sendbuf));
            memset(tempbuf, 0, sizeof(tempbuf));
    }
        close(connfd);

    return 0;
}
