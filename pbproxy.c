#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define MAXLINE 1024
#define LISTENQ 1024

int main(int argc, char **argv){

		struct sockaddr_in lisaddr, forwaddr;
		int lisfd, forwfd, connfd;
		char buf[MAXLINE + 1], opt, *key = NULL;
		ssize_t n;
		int lflag = 0, kflag = 0;
		int lport = 0, idx = 0;
		char *socket_meta[2];

		while((opt = getopt(argc, argv, "l:k:")) != -1){

				switch(opt){
						case 'l':
								lflag = 1;
								lport = strtol(optarg, (char **)NULL, 10);
								break;
						case 'k':
								kflag = 1;
								key = optarg;
								break;
						case ':':
								fprintf(stderr, "requires an argument");
								break;
						case '?':
								if (optopt == 'i' || optopt == 'r' || optopt == 's')
										fprintf(stderr, "Option %c requires an argument\n", optopt);                                 
								else
										fprintf(stderr, "Invalid option %c to program\n", optopt);
								break;
						default:
								break;
				}
		}
		for(int i = optind; i < argc; i++){
				socket_meta[idx++] = argv[i];
		}
		printf("%d %s %s %s", lport, key, socket_meta[0], socket_meta[1]);

		if (socket_meta[1] == NULL || socket_meta[0] == NULL){
				fprintf(stderr, "proxy requires ip:port to run on\n");
				exit(0);
		}
		if (lflag == 1){
				if ((lisfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
						fprintf(stderr, "Error Creating Socket\n");
						exit(0);
				}

				bzero(&(lisaddr), sizeof(lisaddr));

				lisaddr.sin_family = AF_INET;
				lisaddr.sin_port = htons(lport);
				lisaddr.sin_addr.s_addr = htonl(INADDR_ANY);

				bind(lisfd, (struct sockaddr *) &lisaddr, sizeof(lisaddr));
				listen(lisfd, LISTENQ);

				printf("Listening for connections on %d\n", lport);
				fflush(stdout);

				if ((forwfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
						fprintf(stderr, "Error Creating Socket\n");
						exit(0);
				}

				bzero(&(forwaddr), sizeof(forwaddr));

				forwaddr.sin_family = AF_INET;
				forwaddr.sin_port = htons((int)strtol(socket_meta[1], (char **)NULL, 10));

				if (inet_pton(AF_INET, socket_meta[0], &forwaddr.sin_addr) < 0){
						fprintf(stderr, "Could not translate IP %s\n", socket_meta[0]);
						exit(0);
				}
				if (connect(forwfd, (struct sockaddr *)&forwaddr, sizeof(forwaddr)) < 0){
						fprintf(stderr, "Connection error to specified service %s %s", socket_meta[0], socket_meta[1]);
						exit(0);
				}
				connfd = accept(lisfd, (struct sockaddr *) NULL, NULL);
				char sendbuf[MAXLINE+1] = {0};
				while((n = read(connfd, buf, MAXLINE)) > 0){        
						buf[n] = '\0';
						strcpy(sendbuf, buf);
						write(forwfd, buf, strlen(sendbuf));
						memset(sendbuf, 0, sizeof(sendbuf));
				}
				close(connfd);
		}

    return 0;
}
