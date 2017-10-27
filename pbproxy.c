#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#define MAXLINE 4096 // 1024 + 8(IV)
#define LISTENQ 1024
int max(int a, int b){
	return (a >= b) ? a : b;
}
struct ctr_state {
    unsigned char ivec[16];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[16];
};
struct thread_args{
	int fd;
	int lfd;
	int enc;
    unsigned char *key;
};

void init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
    state->num = 0;
    memset(state->ecount, 0, 16);

    memset(state->ivec + 8, 0, 8);

    memcpy(state->ivec, iv, 8);
}
void *forw_handler(void *t_args){
    struct thread_args *args = (struct thread_args*) t_args;
    int forwfd = ((args)->fd);
    int lisfd = ((args)->lfd);
    unsigned char *key = args->key;

    char recvline[MAXLINE+1];
    ssize_t n = 0;
    unsigned char iv[8];
    struct ctr_state state;

    AES_KEY aes_key;

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0){ 
        fprintf(stderr, "Could not set key\n" );
        exit(0);
    }    

    while((n = read(lisfd, recvline, MAXLINE)) > 0){    

        int len = n;
        if (args->enc == 1){ 

            if (!RAND_bytes(iv, 8)){
                fprintf(stderr, "Counter not initialized\n");
            }   

            char encout[n+8];
            memset(encout, 0, sizeof(encout));
            memcpy(encout, iv, 8); 


            char ciphertext[n];
            memset(ciphertext, 0, sizeof(ciphertext));
            init_ctr(&state, iv);
            AES_ctr128_encrypt((unsigned char *)recvline, (unsigned char *)ciphertext, len, &aes_key, state.ivec, state.ecount, &state.num);
            memcpy(encout+8, ciphertext, sizeof(ciphertext));


            write(forwfd, encout, sizeof(encout));
            memset(recvline, 0, sizeof(recvline));  
        }   
        else{
            char transmission[n-8];
            memset(transmission, 0, sizeof(transmission));
            memcpy(iv, recvline, 8); 
            init_ctr(&state, iv);
            AES_ctr128_encrypt((unsigned char *)(recvline+8), (unsigned char *)transmission, len-8, &aes_key, state.ivec, state.ecount, &state.num);

            write(forwfd, transmission, sizeof(transmission));
        }   

        memset(recvline, 0, sizeof(recvline));  
    }   
    pthread_exit(0);
    close(lisfd);
    close(forwfd);
    free(t_args);
    return 0;
}
int main(int argc, char **argv){
		
//		EVP_CIPHER_CTX en, de;
//		unsigned int salt[] = {12345, 54321};
		int key_len;
		struct sockaddr_in lisaddr, forwaddr;
		int lisfd, forwfd, connfd;
		char buf[MAXLINE + 1], opt;
		unsigned char *key = NULL;
		int lflag = 0, kflag = 0;
		int lport = 0, idx = 0;
		char *socket_meta[2];
		ssize_t n = 0;

		while((opt = getopt(argc, argv, "l:k:")) != -1){

				switch(opt){
						case 'l':
								lflag = 1;
								lport = strtol(optarg, (char **)NULL, 10);
								break;
						case 'k':
								kflag = 1;
								key = (unsigned char *)optarg;
								key_len = strlen((const char *)key);
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
		int i = 0;
		for(i = optind; i < argc; i++){
				socket_meta[idx++] = argv[i];
		}

		if (socket_meta[1] == NULL || socket_meta[0] == NULL){
				fprintf(stderr, "proxy requires ip:port to run on\n");
				exit(0);
		}
		if (key == NULL){
			fprintf(stderr, "Missing key: Plugboard proxy requires a key argument for transmission..\n");
			exit(0);

		}
		unsigned char iv[8];
		struct ctr_state state;

		AES_KEY aes_key;
	
		if (AES_set_encrypt_key(key, 128, &aes_key) < 0){
				fprintf(stderr, "Could not set key\n" );
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

//				printf("Listening for connections on %d\n", lport);
//				fflush(stdout);

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
						fprintf(stderr, "Connection error to specified service %s %s\n", socket_meta[0], socket_meta[1]);
						exit(0);
				}
				fd_set readfs;
				char recvline[MAXLINE+1] = {0};
				connfd = accept(lisfd, (struct sockaddr *)NULL, NULL);
				int maxfd = max(connfd, forwfd);
				while(1){
					FD_ZERO(&readfs);
					FD_SET(forwfd, &readfs);
					FD_SET(connfd, &readfs);
					int status = select(maxfd+1, &readfs, NULL, NULL, NULL);
					if (status < 0){
							fprintf(stderr, "Invalid Socket [Reverse proxy]");
							exit(0);
					}
					if (FD_ISSET(forwfd, &readfs)){

							pthread_t tid;
							struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
							args->lfd = forwfd;
							args->fd = connfd;
							args->key = key;
							args->enc = 1;
							
							if (pthread_create(&tid, NULL, forw_handler, (void*)args) < 0){
									printf("Could Not Create time service thread");
									continue;
							}
							
							pthread_detach(tid);
					}
					else if (FD_ISSET(connfd, &readfs)){
							pthread_t tid;
							struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
							args->lfd = connfd;
							args->fd = forwfd;
							args->key = key;
							args->enc = 0;
							
							if (pthread_create(&tid, NULL, forw_handler, (void*)args) < 0){
									printf("Could Not Create time service thread");
									continue;
							}
							
							pthread_detach(tid);
					}
				}
				close(forwfd);
				close(connfd);
				close(lisfd);
		}
		else{	
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

				char sendline[MAXLINE+1] = {0}, recvline[MAXLINE+1] = {0};

				fd_set readfs;
				int maxfd = max(forwfd, STDIN_FILENO);
				
				while(1){
						FD_ZERO(&readfs);
						FD_SET(forwfd, &readfs);
						FD_SET(STDIN_FILENO, &readfs);
						int status = select(maxfd+1, &readfs, NULL, NULL, NULL);
						if (status < 0){
								fprintf(stderr, "Invalid Select");
								exit(0);
						}
						if (FD_ISSET(forwfd, &readfs)){
								if ((n = read(forwfd, recvline, MAXLINE)) == 0){
										fprintf(stderr, "Server connection closed..\n");
										break;
								}
								memcpy(iv, recvline, 8);
								
								char plaintext[n-8];

								memset(plaintext, 0, sizeof(plaintext));
								init_ctr(&state, iv);
								int len = n;
								AES_ctr128_encrypt((unsigned char *)(recvline+8), (unsigned char *)plaintext, len-8, &aes_key, state.ivec, state.ecount, &state.num);
								
								write(STDOUT_FILENO, plaintext, sizeof(plaintext));
								memset(recvline, 0, sizeof(recvline));
//
}
						else if (FD_ISSET(STDIN_FILENO, &readfs)){
								if ((n = read(STDIN_FILENO, sendline, MAXLINE)) == 0){
										fprintf(stderr, "EOF encountered. Closing connection..\n");
										shutdown(forwfd, SHUT_WR);
										FD_CLR(STDIN_FILENO, &readfs);
										continue;
								}
								else{
										if (!RAND_bytes(iv, 8)){
												fprintf(stderr, "Counter not initialized\n");
//
}
										char transmission[n+8];
										
										memset(transmission, 0, sizeof(transmission));
										memcpy(transmission, iv, 8);

										init_ctr(&state, iv);

										char ciphertext[n];
										memset(ciphertext, 0, sizeof(ciphertext));
										int len;
										len = n;

										AES_ctr128_encrypt((unsigned char *)sendline, (unsigned char *)ciphertext, len, &aes_key, state.ivec, state.ecount, &state.num);
										memcpy(transmission+8, ciphertext, sizeof(ciphertext));
										write(forwfd, transmission, sizeof(transmission));
}

								memset(sendline, 0, sizeof(sendline));
						}
				}
				close(forwfd);
		}

		return 0;
}
