#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <rpc/des_crypt.h>
#include <poll.h>
#include <signal.h>
#include <time.h>

#include "comm_header.h"

#define MAX_REQUEST_SIZE (1024*1024)
#define MAX_SAVED 100

int server_fd;  /* server socket */
credential_t cred_table[MAX_SAVED];
//client_t client_table[MAX_SAVED];
unsigned long des_key = 0x35675593;

struct CONN_STAT {
		char  state; /* registered, logged in etc */

		char rec[MAX_REQUEST_SIZE];		//0 if unknown ye
		char send[MAX_REQUEST_SIZE];
		//0 if unknown yet
		//char username[8];
		char id[8];
		int size;
		int status; //0 - recieve header, 1 - recieve data, 2 - send header, 3 - send data
		int nRecv;
		int nSent;
		int lastIndex;
};

int nConns;	//total # of data sockets
struct pollfd peers[MAX_CONCURRENCY_LIMIT+1];	//sockets to be monitored by poll()
struct CONN_STAT connStat[MAX_CONCURRENCY_LIMIT+1];	//app-layer stats of the sockets



void Error(const char * format, ...) {
		char msg[4096];
		va_list argptr;
		va_start(argptr, format);
		vsprintf(msg, format, argptr);
		va_end(argptr);
		fprintf(stderr, "Error: %s\n", msg);
		exit(-1);
}

void Log(const char * format, ...) {
		time_t utime;
		struct tm * timei;
		time(&utime);
		timei = localtime(&utime);
		char msg[2048];
		va_list argptr;
		va_start(argptr, format);
		vsprintf(msg, format, argptr);
		va_end(argptr);
		char* time = asctime(timei);
		time[strlen(time)-1] = '\0';
		fprintf(stderr, "[%s] %s\n", time, msg);
}

void my_encrypt(uint8_t *data, int data_len)
{
		unsigned long long *data_ptr =  (unsigned long long*)data;
		// if (data_len % 8) {
				// Log("Encryption datalen(%d) is not multiple of 8 bytes \n", data_len);
				//exit(1);
		// }

		//Log("Encrypting %d bytes\n", data_len);
	
		while (data_len > 0) {
			*data_ptr ^= des_key;
			data_len -= 8;
			data_ptr++;
		}
		// ecb_crypt(key, data, data_len, DES_ENCRYPT);
}

void my_decrypt(uint8_t *data, int data_len)
{
		unsigned long long *data_ptr =  (unsigned long long*)data;
		// if (data_len % 8) {
				// Log("Decryption datalen(%d) is not multiple of 8 bytes \n", data_len);
				// exit(1);
		// }
		
		//Log("Decrypting %d bytes\n", data_len);
		// ecb_crypt(key, data, data_len, DES_DECRYPT);

		my_encrypt(data, data_len);
}

char *type_to_string(int type)
{
	char *str;
	switch (type) {
		case PKT_REGISTER : 
			str = "REGISTER";
			break;
		case PKT_LOGIN : 
			str = "LOGIN";
			break;
		case PKT_LOGOUT : 
			str = "LOGOUT";
			break;
		case PKT_SEND : 
			str = "SEND";
			break;
		case PKT_SEND2 : 
			str = "SEND2";
			break;
		case PKT_SENDA : 
			str = "SENDA";
			break;
		case PKT_SENDA2 : 
			str = "SENDA2";
			break;
		case PKT_SENDF : 
			str = "SENDF";
			break;
		case PKT_SENDF2 : 
			str = "SENDF2";
			break;
		case PKT_LIST_REQ : 
			str = "LIST_REQ";
			break;
		case PKT_LIST_RESP : 
			str = "LIST_RESP";
			break;
  		case PKT_ERR : 
			str = "ERROR";
			break;
		default:
			str = "Unknown";
			break;
	}
	return str;
}

void delete_credential()
{
		char cmd[80];
		sprintf(cmd, "rm -f %s", CRED_FILE);
		Log("Removing credential file with command %s", cmd);
		system(cmd);
}

void read_credential()
{
		FILE *fn;
		int ret;

		fn = fopen(CRED_FILE, "rb");
		if (fn == NULL) {
				Log("Could not open credential file %s for read", CRED_FILE);
				return;
		}
		ret = fread((uint8_t *)cred_table, 1, sizeof(cred_table), fn);
		if (ret != sizeof(cred_table)) {
				Log("read returned incorrect size, got %d expected %ld", ret, sizeof(cred_table));
				return;
		}

		my_decrypt((uint8_t *)cred_table, sizeof(cred_table));

		Log("Loaded Credentials");
		fclose(fn);
}

void save_credential()
{
		FILE *fn;
		int ret;

		fn = fopen(CRED_FILE, "wb");
		if (fn == NULL) {
				Log("Could not open credential file %s for write", CRED_FILE);
				return;
		}
		my_encrypt((uint8_t *)cred_table, sizeof(cred_table));

		ret = fwrite((uint8_t *)cred_table, 1, sizeof(cred_table), fn);
		if (ret != sizeof(cred_table)) {
				Log("write returned incorrect size, got %d expected %ld", ret, sizeof(cred_table));
				return;
		}

		my_decrypt((uint8_t *)cred_table, sizeof(cred_table));

		Log("Saved Credentials");


		fclose(fn);
}


void initialize() 
{
		read_credential(); /* Read credential and initialize cred_table */

		/* 	memcpy(cred_table[0].username, "Devansh", 8);
			memcpy(cred_table[0].password, "Testing", 8);
			memcpy(cred_table[1].username, "Devishi", 8);
			memcpy(cred_table[1].password, "Nest", 8);
			*/

		//printf("1st entry %s %s\n", cred_table[0].username, cred_table[0].password);
		//printf("2nd entry %s %s\n", cred_table[1].username, cred_table[1].password);
}

int Send_NonBlocking(int sockFD, char * data, struct CONN_STAT * pStat, struct pollfd * pPeer) {	
		while (pStat->lastIndex > 0) {
				//pStat keeps tracks of how many bytes have been sent, allowing us to "resume" 
				//when a previously non-writable socket becomes writable. 
				int n = send(sockFD, data, pStat->lastIndex, 0);
				//Log("Sent %d bytes to %s\n", n, pStat->id);


				if (n >= 0) {
						//pStat->nSent += n;
						if (pStat->lastIndex - n) {
							memmove(data, data+n, pStat->lastIndex-n);
						}
						pStat->lastIndex -= n;

				} else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
						Log("Connection closed.");
						close(sockFD);
						return -1;
				} else if (n < 0 && (errno == EWOULDBLOCK)) {
						//The socket becomes non-writable. Exit now to prevent blocking. 
						//OS will notify us when we can write
						pPeer->events |= POLLWRNORM; 
						return 0; 
				} else {
						Error("Unexpected send error %d: %s", errno, strerror(errno));
				}
		}
		pPeer->events &= ~POLLWRNORM;
		return 0;
}

int Recv_NonBlocking(int sockFD, char * data, struct CONN_STAT * pStat, struct pollfd * pPeer) {
		//pStat keeps tracks of how many bytes have been rcvd, allowing us to "resume" 
		//when a previously non-readable socket becomes readable. 
		while (pStat->nRecv < pStat->size) {
				int n = recv(sockFD, data + pStat->nRecv, pStat->size - pStat->nRecv, 0);
				if (n > 0) {
						//Log("Recieved %d bytes on %d", n, sockFD);
						pStat->nRecv = pStat->nRecv + n;
				} else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
						Log("Connection closed."); 
						close(sockFD);
						return -1;
				} else if (n < 0 && (errno == EWOULDBLOCK)) { 
						//The socket becomes non-readable. Exit now to prevent blocking. 
						//OS will notify us when we can read
						return 0; 
				} else {
						Error("Unexpected recv error %d: %s.", errno, strerror(errno));
				}
		}

		return 0;
}

void SetNonBlockIO(int fd) {
		int val = fcntl(fd, F_GETFL, 0);
		if (fcntl(fd, F_SETFL, val | O_NONBLOCK) != 0) {
				Error("Cannot set nonblocking I/O.");
		}
}

void RemoveConnection(int i) {
		close(peers[i].fd);	
		if (i < nConns) {	
				memmove(peers + i, peers + i + 1, (nConns-i) * sizeof(struct pollfd));
				memmove(connStat + i, connStat + i + 1, (nConns-i) * sizeof(struct CONN_STAT));
		}
		nConns--;
}


int transferToSend(int i) {
		pkt_header_t *header = (pkt_header_t*)(connStat[i].rec);
		int success = 1;
		if(header->pkt_type == PKT_SEND || header->pkt_type == PKT_SENDA || header->pkt_type == PKT_SENDF){
				
				char username[8];
				switch(header->pkt_type)
				{
						case PKT_SEND: 
								{
										pkt_send_t *data = (pkt_send_t*)(connStat[i].rec+sizeof(pkt_header_t));
										memcpy(data->username, connStat[i].id, sizeof(connStat[i].id));
										break;
								}
						case PKT_SENDF: 
								{
										pkt_sendf_t *data = (pkt_sendf_t*)(connStat[i].rec+sizeof(pkt_header_t));
										memcpy(data->username, connStat[i].id, sizeof(connStat[i].id));
										break;
								} 
						default:
								break;
				}
				for(int j = 1; j <= nConns; j++){ //find first empty slot and set info to usernae
						if(j != i && connStat[i].state == LOGGED_IN){
								//check if NOT available
								if((sizeof(connStat[j].send) - connStat[j].lastIndex) < connStat[i].size) {
										success = 0;
										break;
								} 
						}
				}
				if(success){
						Log("%s sending a %s of size %d to everyone", connStat[i].id, type_to_string(header->pkt_type), connStat[i].size-sizeof(pkt_header_t)); //USERNAME TYPE AND TO WHO
						for(int j = 1; j <= nConns; j++){
								if(j != i){
										memcpy(connStat[j].send+connStat[j].lastIndex, connStat[i].rec, connStat[i].size);
     									my_encrypt(connStat[j].send+connStat[j].lastIndex, connStat[i].size);
										connStat[j].lastIndex += connStat[i].size;
								}
						}
						connStat[i].status = 0;
						connStat[i].nRecv = 0;
						connStat[i].size = sizeof(pkt_header_t);;
						memset(connStat[i].rec, 0, sizeof(connStat[i].rec));
				}

		} else if(header->pkt_type == PKT_SEND2 || header->pkt_type == PKT_SENDA2 || header->pkt_type == PKT_SENDF2) {
				char username[8];
				switch(header->pkt_type)
				{
						case PKT_SEND2: 
								{
										pkt_send2_t *data = (pkt_send2_t*)(connStat[i].rec+sizeof(pkt_header_t));
										memcpy(username, data->username, sizeof(username));
										memcpy(data->username, connStat[i].id, sizeof(connStat[i].id));
										break;
								}
						case PKT_SENDA2: 
								{
										pkt_senda2_t *data = (pkt_senda2_t*)(connStat[i].rec+sizeof(pkt_header_t));
										memcpy(username, data->username, sizeof(username));
										memcpy(data->username, connStat[i].id, sizeof(connStat[i].id));
										break;
								} 
						case PKT_SENDF2: 
								{

										pkt_sendf2_t *data = (pkt_sendf2_t*)(connStat[i].rec+sizeof(pkt_header_t));
										memcpy(username, data->username, sizeof(username));
										memcpy(data->username, connStat[i].id, sizeof(connStat[i].id));
										break;
								}
						default:
								break;
				}
				int index = 0;
				for(int j = 1; j <= nConns; j++){
						if(strncmp(username, connStat[j].id, sizeof(username)) == 0 && strncmp(username, connStat[i].id, sizeof(username)) != 0){ 
								//check if NOT available
                success = 2;
								if((sizeof(connStat[j].send) - connStat[j].lastIndex) < connStat[i].size){
										success = 0;
										break;
								} else {
										index = j;
										break;
								}

						}
				}
        //success - 0 - dont have space but found -> do nothing
        //success - 1 - did not find -> error
        //success - 2 - found and has space -> transfer to send
				if(success == 2) {
						Log("%s sent a %s of size %d to %s", connStat[i].id, type_to_string(header->pkt_type), connStat[i].size - sizeof(pkt_header_t), connStat[index].id);
						memcpy(connStat[index].send+connStat[index].lastIndex, connStat[i].rec, connStat[i].size);
     					my_encrypt(connStat[index].send+connStat[index].lastIndex, connStat[i].size);
						connStat[index].lastIndex += connStat[i].size;
						connStat[i].status = 0;
						connStat[i].nRecv = 0;
						memset(connStat[i].rec, 0, sizeof(connStat[i].size));
						connStat[i].size = sizeof(pkt_header_t);
				} else if (success == 1) {
					pkt_err_t err;
                                	Log("Failed to send to %s, username does not exist", username);
                                        strcpy(err.message, "Username does not exist.");
                                        pkt_header_t err_head;
                                        err_head.pkt_type = PKT_ERR;
                                        err_head.pkt_data_len = sizeof(pkt_err_t);
                                        memset(connStat[i].rec, 0, sizeof(connStat[i].size));
					memcpy(connStat[i].rec, (char *)&err_head, sizeof(pkt_header_t));
                                        memcpy(connStat[i].rec+sizeof(pkt_header_t), (char *)&err, sizeof(pkt_err_t));
                                        connStat[i].status = 2;
                                		connStat[i].size = sizeof(pkt_header_t) + sizeof(pkt_err_t);                                                                                                                   

            //ERROR- NO USERS MATCH REQUEST
        }
		} else if(header->pkt_type == PKT_LIST_REQ) {
				//MAKE LIST PACKET
        //pkt_list_resp_t *data = (pkt_list_resp_t*)(connStat[i].rec+sizeof(pkt_header_t));
        pkt_list_resp_t data;
        pkt_header_t list_head;
        list_head.pkt_type = PKT_LIST_RESP;
        list_head.pkt_data_len = sizeof(data);
        int count = 0;
        for(int i = 1; i <= nConns; i++){
          if(connStat[i].state == LOGGED_IN){
            memcpy(data.username[count], connStat[i].id, sizeof(connStat[i].id));
            count++;
          }
        }
        data.count = count;
        //Log("Size of LIST: %ld %d", strlen(data), count);
        if((sizeof(connStat[i].send) - connStat[i].lastIndex) >= sizeof(data)+sizeof(list_head)){
            Log("Listing users for %s", connStat[i].id);
            memcpy(connStat[i].send + connStat[i].lastIndex, (char *)&list_head, sizeof(list_head)); //header -> rec
            memcpy(connStat[i].send+sizeof(list_head)+connStat[i].lastIndex, (char *)&data, sizeof(data)); //data ->rec
     		my_encrypt(connStat[i].send+connStat[i].lastIndex, sizeof(list_head) + sizeof(data));
            
            connStat[i].lastIndex += sizeof(list_head)+sizeof(data);
            connStat[i].status = 0;
						connStat[i].nRecv = 0;
						connStat[i].size = sizeof(pkt_header_t);;
						memset(connStat[i].rec, 0, sizeof(connStat[i].rec));
				} 
        
		} else if(header->pkt_type == PKT_ERR) {
				//Log("Sending Error to %s, len=%d", connStat[i].id, header->pkt_data_len);
				if((sizeof(connStat[i].send) - connStat[i].lastIndex) >= connStat[i].size){
						memcpy(connStat[i].send+connStat[i].lastIndex, connStat[i].rec, connStat[i].size);
     					my_encrypt(connStat[i].send+connStat[i].lastIndex, connStat[i].size);
						connStat[i].lastIndex += connStat[i].size;
						connStat[i].status = 0;
						connStat[i].nRecv = 0;
						connStat[i].size = sizeof(pkt_header_t);;
						memset(connStat[i].rec, 0, sizeof(connStat[i].rec));
				} 
		} else {
		}

		return 0;
}


void DoServer(int svrPort, int maxConcurrency) {
		Log("Initializing Server...");
		int listenFD = socket(AF_INET, SOCK_STREAM, 0);
		if (listenFD < 0) {
				Error("Cannot create listening socket.");
		}
		SetNonBlockIO(listenFD);

		struct sockaddr_in serverAddr;
		memset(&serverAddr, 0, sizeof(struct sockaddr_in));	
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_port = htons((unsigned short) svrPort);
		serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

		int optval = 1;
		int r = setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (r != 0) {
				Error("Cannot enable SO_REUSEADDR option.");
		}
		signal(SIGPIPE, SIG_IGN);

		if (bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
				Error("Cannot bind to port %d.", svrPort);
		}

		if (listen(listenFD, 16) != 0) {
				Error("Cannot listen to port %d.", svrPort);
		}

		nConns = 0;	
		memset(peers, 0, sizeof(peers));	
		peers[0].fd = listenFD;
		peers[0].events = POLLRDNORM;	
		//memset(connStat, 0, sizeof(connStat));
		int connID = 0;
		Log("Initialization Complete");
		while (1) {	//the main loop		
				//monitor the listening sock and data socks, nConn+1 in total
				r = poll(peers, nConns + 1, -1);	
				if (r < 0) {
						Error("Invalid poll() return value.");
				}			

				struct sockaddr_in clientAddr;
				socklen_t clientAddrLen = sizeof(clientAddr);	


				for (int i=1; i<=nConns; i++) {
						if (peers[i].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
								int fd = peers[i].fd;

								if (connStat[i].status == 0) {
										connStat[i].size = sizeof(pkt_header_t);
								}	

								//printf("Connection %d has some data, status is %d  nRecv = %d, size %d\n", fd, connStat[i].status, connStat[i].nRecv,  connStat[i].size);
								if (connStat[i].status == 0 || (connStat[i].nRecv < connStat[i].size && connStat[i].status == 1)) {

										if (Recv_NonBlocking(fd, connStat[i].rec, &connStat[i], &peers[i]) < 0) {

												Log("Connection removed"); //FINAL - connection removed with unknown/known client
                        RemoveConnection(i);
												//printf("FAILED 1\n");
												continue;
										} 

										if(connStat[i].status == 0 && connStat[i].nRecv == sizeof(pkt_header_t)){
												//get header

												pkt_header_t *header = (pkt_header_t*)(connStat[i].rec); 
												my_decrypt((char *) header, sizeof(pkt_header_t));
												//Log("Recieved Header: Type = %d connection from %s", header->pkt_type, connStat[i].id);
												pkt_header_t data;
												connStat[i].size = header->pkt_data_len + sizeof(header);
												//Log("Recieved Size: Type = %d", header->pkt_data_len);
												connStat[i].status = 1;
										}

										if (connStat[i].nRecv == connStat[i].size && connStat[i].status == 1) {

												pkt_header_t* header = (pkt_header_t*)(connStat[i].rec);

												//Log("Entering to process packet \n");

												if (header->pkt_data_len) {
													my_decrypt(connStat[i].rec + sizeof(pkt_header_t), header->pkt_data_len);
												}
												//see if password match, else err/status == 2
												//send, sendA, sendf -> to who = everyone/status ==2
												//send2, sendA2, sendf2 -> to who = username(valid check otherwise err), status ==2
												//list -> status == 2
												if(header->pkt_type == PKT_REGISTER){
														pkt_register_t *data = (pkt_register_t*)(connStat[i].rec+sizeof(pkt_header_t));
														//Log("Register Request: Username %s Password %s\n", data->username, data->password);
														int valid = 1;
														for(int j = 0; j < MAX_SAVED; j++) {
																if(strncmp(cred_table[j].username, data->username, sizeof(data->username)) == 0) {
																		pkt_err_t err;
																		Log("Failed Attempt to Register Account: Username %s Password %s, username already exists.", data->username, data->password);
																		strcpy(err.message, "That username already exists.");
																		pkt_header_t err_head;
																		err_head.pkt_type = PKT_ERR;
																		err_head.pkt_data_len = sizeof(pkt_err_t);
																		memset(connStat[i].rec, 0, sizeof(connStat[i].size));
																		memcpy(connStat[i].rec, (char *)&err_head, sizeof(pkt_header_t));
																		memcpy(connStat[i].rec+sizeof(pkt_header_t), (char *)&err, sizeof(pkt_err_t));
																		connStat[i].status = 2;
																		connStat[i].size = sizeof(pkt_header_t) + sizeof(pkt_err_t);
																		valid = 0;
																		break;
																}
														}

														if(valid) {
																for(int j = 0; j < MAX_SAVED; j++) {
																		if(strcmp(cred_table[j].username,"") == 0) {
																				Log("Registered New Account: Username %s Password %s", data->username, data->password);
																				memcpy(cred_table[j].username, data->username, sizeof(data->username));
																				memcpy(cred_table[j].password, data->password, sizeof(data->password));
																				save_credential();
																				connStat[i].status = 0;
																				connStat[i].size = sizeof(pkt_header_t);;
																				connStat[i].nRecv = 0;
																				break;
																		}
																}
														}
												} else if (header->pkt_type == PKT_LOGIN) {
														//CHEKC TO SEE IF THAT PERSON IS ONLINE
														pkt_login_t *data = (pkt_login_t*)(connStat[i].rec+sizeof(pkt_header_t));
														int processed = 0; // 0
														for(int j = 0; j < MAX_SAVED; j++) {
																if(strncmp(cred_table[j].username, data->username, sizeof(data->username)) == 0 && strncmp(cred_table[j].password, data->password, sizeof(data->password)) == 0) {
																		Log("%s Logged in", data->username);
																		memcpy(connStat[i].id, data->username, sizeof(data->username));
																		//Log("Logged in: %s at %d", connStat[i].id, i);
																		connStat[i].status = 0;
																		connStat[i].nRecv = 0;
																		connStat[i].state = LOGGED_IN;
																		processed = 1; //
                                    break; 

																}
														}

														if(!processed) {
																pkt_err_t err;
                                Log("Failed to Log In to %s, wrong username or password", data->username);
																strcpy(err.message, "Wrong username or password.");
																pkt_header_t err_head;
																err_head.pkt_type = PKT_ERR;
																err_head.pkt_data_len = sizeof(pkt_err_t);
																memset(connStat[i].rec, 0, sizeof(connStat[i].size));
																memcpy(connStat[i].rec, (char *)&err_head, sizeof(pkt_header_t));
																memcpy(connStat[i].rec+sizeof(pkt_header_t), (char *)&err, sizeof(pkt_err_t));
																connStat[i].status = 2;
                                connStat[i].size = sizeof(pkt_header_t) + sizeof(pkt_err_t);                                                                                                                   
														}
												} else if (header->pkt_type == PKT_LOGOUT){
                            //if(connStat[i].state == LOGGED_IN){
                              Log("%s Logged Out", connStat[i].id);
                              strcpy(connStat[i].id, "");
                              connStat[i].status = 0;
						                  connStat[i].nRecv = 0;
						                  connStat[i].size = sizeof(pkt_header_t);;
						                  memset(connStat[i].rec, 0, sizeof(connStat[i].rec));
                            //RESET                                              
                              connStat[i].state = LOGGED_OUT;
                            //}
                        
                        } else  {
														
														if(connStat[i].state != LOGGED_IN) {

                                Log("%s Request Rejected: User Not Logged In", type_to_string(header->pkt_type));
																pkt_err_t err;
																strcpy(err.message , "You are not logged in.");
																pkt_header_t err_head;
																err_head.pkt_type = PKT_ERR;
																err_head.pkt_data_len = sizeof(pkt_err_t);
																memset(connStat[i].rec, 0, sizeof(connStat[i].size));
																memcpy(connStat[i].rec, (char *)&err_head, sizeof(pkt_header_t));
																memcpy(connStat[i].rec+sizeof(pkt_header_t), (char *)&err, sizeof(pkt_err_t));
                                connStat[i].size = sizeof(pkt_header_t) + sizeof(pkt_err_t);
														} 
														connStat[i].status = 2;
												} 

												transferToSend(i);

										}

								}

								//a previously blocked data socket becomes writable
								if (peers[i].revents & POLLWRNORM) {
										//Log("Sending Blocked Data");
										if (Send_NonBlocking(peers[i].fd, connStat[i].send, &connStat[i], &peers[i]) < 0) {
												RemoveConnection(i);
												continue;
										}
								}
						}
				}

				//new incoming connection
				if ((peers[0].revents & POLLRDNORM) && (nConns < maxConcurrency)) {					
						Log("Incoming Connection Request");
						int fd = accept(listenFD, (struct sockaddr *)&clientAddr, &clientAddrLen);
						if (fd != -1) {
								SetNonBlockIO(fd);
								nConns++;
								peers[nConns].fd = fd;
								peers[nConns].events = POLLRDNORM;
								peers[nConns].revents = 0;

								memset(&connStat[nConns], 0, sizeof(struct CONN_STAT));
								//Log("Connection Successful fd=%d\n", fd);
								Log("Connection Successful");
						}
				}

				//SEND STUFF
				for(int i = 1; i <= nConns; i++){
						if(connStat[i].lastIndex > 0){
								if (Send_NonBlocking(peers[i].fd, connStat[i].send, &connStat[i], &peers[i]) < 0) {
										RemoveConnection(i);
										continue;
								}
						}

						if(connStat[i].status == 2){
								transferToSend(i);
						}
				}
		}
		//Log("LOOP");	
}
int main(int argc, char *argv[])
{
		struct sockaddr_in servaddr;
		int server_port;

		if (argc < 2) {
				printf("Usage: \n %s <port no>  - to set up a server with TCP port or \n  %s reset - to reset the username/password database \n", argv[0], argv[0]);
				exit(1);
		}

		if (strcmp(argv[1], "reset") == 0) {
				/* clear the username/password database */
				delete_credential();
				exit(0);
		}

		server_port = atoi(argv[1]);

		initialize();  /* Initialize evrything, including cred_table*/
		save_credential();

		DoServer(server_port, MAX_CONCURRENCY_LIMIT);
		return 0;
}
