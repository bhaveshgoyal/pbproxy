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
#define BUF_SIZE 4106 // 1024 + 8(IV)
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
int forw_handler(void *t_args){
		struct thread_args *args = (struct thread_args*) t_args;
		int forwfd = ((args)->fd);
		int lisfd = ((args)->lfd);
		unsigned char *key = args->key;

		unsigned char *recvline = (unsigned char *)malloc(BUF_SIZE);
		memset(recvline, 0, BUF_SIZE);
		ssize_t n = 0;
		unsigned char iv[8];
		struct ctr_state state;

		AES_KEY aes_key;

		if (AES_set_encrypt_key(key, 128, &aes_key) < 0){ 
				fprintf(stderr, "Could not set key\n" );
				exit(0);
		}    

		if((n = read(lisfd, recvline, MAXLINE)) > 0){    

				int len = n;
				if (args->enc == 1){ 

						if (!RAND_bytes(iv, 8)){
								fprintf(stderr, "Counter not initialized\n");
						}   

						unsigned char *encout = (unsigned char *)malloc(n+8);
						memset(encout, 0, n+8);
						memcpy(encout, iv, 8); 


						unsigned char *ciphertext = (unsigned char *)malloc(n);
						memset(ciphertext, 0, n);
						init_ctr(&state, iv);
						AES_ctr128_encrypt(recvline, ciphertext, len, &aes_key, state.ivec, state.ecount, &state.num);
						memcpy(encout+8, ciphertext, n);

						write(forwfd, encout, n+8);
						free(encout);
						free(ciphertext);
				}   
				else{
						unsigned char *transmission = (unsigned char *)malloc(n-8);
						memset(transmission, 0, n-8);
						memcpy(iv, recvline, 8); 
						init_ctr(&state, iv);
						AES_ctr128_encrypt((recvline+8), transmission, len-8, &aes_key, state.ivec, state.ecount, &state.num);
						write(forwfd, transmission, n-8);
						free(transmission);    
				}   

				memset(recvline, 0, BUF_SIZE);  
				usleep(600);
		}   
		free(t_args);
		return n;
}
int main(int argc, char **argv){

		int key_len;
		struct sockaddr_in lisaddr, forwaddr;
		int lisfd, forwfd, connfd;
		char opt;
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


				while(1){
						printf("Waiting for new connection\n");
						fflush(stdout);
						connfd = accept(lisfd, (struct sockaddr *)NULL, NULL);
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

						int eof_enc = 0;
						
						while(1){
								FD_ZERO(&readfs);
								FD_SET(forwfd, &readfs);
								FD_SET(connfd, &readfs);
								int maxfd = max(forwfd, connfd);
								int status = select(maxfd+1, &readfs, NULL, NULL, NULL);
								if (status < 0){
										fprintf(stderr, "Can't Multiples betrween Sockets [Reverse proxy]");
										exit(0);
								}
								if (FD_ISSET(forwfd, &readfs)){
										
										struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
										args->lfd = forwfd;
										args->fd = connfd;
										args->key = key;
										args->enc = 1;
										int ret = forw_handler((void *)args);
										if (ret == 0){
												eof_enc++;
										}
										if (eof_enc > 10)
											break;
								}
								else if (FD_ISSET(connfd, &readfs)){
										struct thread_args *args2 = (struct thread_args *)malloc(sizeof(struct thread_args));
										args2->lfd = connfd;
										args2->fd = forwfd;
										args2->key = key;
										args2->enc = 0;
										int ret = forw_handler((void *)args2);
								}
						}
						printf("Connection Terminated\n");
						fflush(stdout);
						close(connfd);
						close(forwfd);
				}
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
								unsigned char *sendline = (unsigned char *)malloc(BUF_SIZE);
								unsigned char *recvline = (unsigned char *)malloc(BUF_SIZE);
								memset(sendline, 0, BUF_SIZE);
								memset(recvline, 0, BUF_SIZE);

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
												if ((n = read(forwfd, recvline, BUF_SIZE)) == 0){
														fprintf(stderr, "Server connection closed..\n");
														break;
												}
												memcpy(iv, recvline, 8);

												unsigned char *plaintext = (unsigned char *)malloc(n-8);

												memset(plaintext, 0, n-8);
												init_ctr(&state, iv);
												int len = n;
												AES_ctr128_encrypt((recvline+8), plaintext, len-8, &aes_key, state.ivec, state.ecount, &state.num);

												write(STDOUT_FILENO, plaintext, n-8);
												memset(recvline, 0, BUF_SIZE);
												free(plaintext);

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

														}
														unsigned char *transmission = (unsigned char *)malloc(n+8);

														memset(transmission, 0, n+8);
														memcpy(transmission, iv, 8);

														init_ctr(&state, iv);

														unsigned char *ciphertext = (unsigned char *)malloc(n);
														memset(ciphertext, 0, n);
														int len;
														len = n;
														AES_ctr128_encrypt(sendline, ciphertext, len, &aes_key, state.ivec, state.ecount, &state.num);
														memcpy(transmission+8, ciphertext, n);
														write(forwfd, transmission, n+8);
														free(transmission);
														free(ciphertext);
												}

												memset(sendline, 0, BUF_SIZE);
										}
								}
								close(forwfd);
						}

						return 0;
				}
