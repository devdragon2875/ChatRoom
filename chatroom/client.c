#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
//#include <rpc/des_crypt.h>

#include "comm_header.h"

char client_send_buf[10000000];
char client_recv_buf[10000000];
struct pollfd pf[1];
unsigned long des_key = 0x35675593;


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
     char msg[2048];
     va_list argptr;
     va_start(argptr, format);
     vsprintf(msg, format, argptr);
     va_end(argptr);
     fprintf(stderr, "%s\n", msg);
}

void my_encrypt(uint8_t *data, int data_len)
{
		unsigned long long *data_ptr =  (unsigned long long*)data;
		if (data_len % 8) {
				Log("Encryption datalen(%d) is not multiple of 8 bytes \n", data_len);
				exit(1);
		}

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
//SEND
int Send_Blocking(int sockFD, char * data, int len) {
     int nSent = 0;

    //printf("Sending %d bytes\n", len);
    // if (len %8 ) {
        //printf("Non 64bit transfer!!!\n");
    // }

     my_encrypt(data, len);
     while (nSent < len) {
          int n = send(sockFD, data + nSent, len - nSent, 0);
          if (n >= 0) {
               nSent += n;
               //printf("nSent: %d\n", nSent);
          } else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
               Log("Connection closed.");
               close(sockFD);
               return -1;
          } else {
               Error("Unexpected error %d: %s.", errno, strerror(errno));
          }
     }
     return 0;
}

//RECIEVE
int Recv_Blocking(int sockFD, char * data, int len) {
     int nRecv = 0;

    //printf("Receiving %d bytes\n", len);
    // if (len %8 ) {
        // printf("Non 64bit transfer!!!\n");
    // }

     while (nRecv < len) {
          int n = recv(sockFD, data + nRecv, len - nRecv, 0);
          if (n > 0) {
               nRecv += n;
          } else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
               Log("Connection closed.");
               close(sockFD);
               return -1;
          } else {
               Error("Unexpected error %d: %s.", errno, strerror(errno));
          }
     }
     my_decrypt(data, len);
     return 0;
}

//Simply another function. Wanted to separate server connecting and send/rec.
int Process(const char* input, int sockFD)
{
        FILE * file = fopen(input, "r"); // opens file
        if(file == NULL){
                perror("Unable to open file \n");
                return -1;
        }
           
        char buf[512] = "";

        while(fgets(buf, sizeof(buf), file)){ //goes through file line by line to get instr
                pkt_header_t header;
                //get type of msg
                char type[12] = "";
                int index = 0;
                while(buf[index] != ' ' && buf[index] != '\n'){
                        index++;
                }
                memcpy(type, buf, index); // gets the type of msg
                //printf("Processing command %s\n", type);
                //printf("Rest of the command %s\n", &buf[index]);
                if(strcmp(type, "REGISTER") == 0){ //REGISTER
                     pkt_register_t regis;
                       int offset = index+1;
                       int i = offset;
                       while(buf[i] != ' '){
                        i++;
                    }
                    
                    //Value Check
                    if(i-offset > 8){
                            printf("Username is larger than 8 characters\n");
							continue;
                    }
                    
                    //Parse Value
                    memset((char *)&regis, 0, sizeof(regis));
                    memcpy(regis.username, buf+offset, i-offset);

                    offset = i+1;
                    i = offset;
                    while(buf[i] != '\n'){
                            i++;
                    }

                    //Value Check
                    if(i-offset > 8){
                            printf("Password is larger than 8 characters\n");
                            continue;
                    }
                    
                    //Parse Value
                    memcpy(regis.password, buf+offset, i-offset);

		   printf("Registering Account\n");
                    header.pkt_type = PKT_REGISTER;
                    header.pkt_data_len = sizeof(regis);
                    if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                    if (Send_Blocking(sockFD, (char *) &regis, sizeof(regis)) < 0) return -1;
            } else if(strcmp(type, "LOGIN") == 0) { //LOGIN
                    pkt_login_t login;

                    int offset = index+1;
                    int i = offset;
                    while(buf[i] != ' '){
                                i++;
                    }
                        
                        //Value Check
                    if(i-offset > 8){
                        printf("Username is larger than 8 characters\n");
						continue;
                    }
                        //Parse Value
                    memset((char *)&login, 0, sizeof(login));
                    memcpy(login.username, buf+offset, i-offset);

                    offset = i+1;
                    i = offset;
                    while(buf[i] != '\n'){
                                i++;
                    }

                        //Value Check
                    if(i-offset > 8){
                                printf("Password is larger than 8 characters\n");
								continue;
                    }
                        //Parse Value
                    memcpy(login.password, buf+offset, i-offset);

                    header.pkt_type = PKT_LOGIN;
                    header.pkt_data_len = sizeof(login);
                    
                    Log("Logging in");
                    if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                    if (Send_Blocking(sockFD, (char *) &login, sizeof(login)) < 0) return -1;

                } else if(strcmp(type, "LOGOUT") == 0) { //LOGOUT
                    Log("Logging Out");
                    header.pkt_type = PKT_LOGOUT;
                    header.pkt_data_len = 0;
                    if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;

                } else if(strcmp(type, "SEND") == 0) {
                        pkt_send_t send;
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
						if(i-offset > 256){
									printf("Message is larger than 256\n");
									continue;
						}
                        memset((char *)&send, 0, sizeof(send));
                        //check if its a valid message
                        memcpy(send.message, buf+offset, i-offset);
                        Log("[YOU]%s", send.message);
                        header.pkt_type = PKT_SEND;
                        header.pkt_data_len = sizeof(send);
                        if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                        if (Send_Blocking(sockFD, (char *) &send, sizeof(send)) < 0) return -1;
                
                } else if(strcmp(type, "SEND2") == 0) {
                        pkt_send2_t send2;
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != ' '){
                                i++;
                        }
                        
						if(i-offset > 8){
							printf("Username is larger than 8 characters\n");
							continue;
						}
                        //check if its a valid username
                        memset((char *)&send2, 0, sizeof(send2));
                        memcpy(send2.username, buf+offset, i-offset);
			
                        offset = i+1;
                        i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
                        
						if(i-offset > 256){
									printf("Message is larger than 256\n");
									continue;
						}
                        //check if its a valid message
                        memcpy(send2.message, buf+offset, i-offset);
                        Log("[YOU->%s]%s", send2.username,send2.message);
                        header.pkt_type = PKT_SEND2;
                        header.pkt_data_len = sizeof(send2);
                        if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                        if (Send_Blocking(sockFD, (char *) &send2, sizeof(send2)) < 0) return -1;
                } else if(strcmp(type, "SENDA") == 0) {
                        pkt_senda_t senda;
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
                        
                        //check if its a valid message
                        
						if(i-offset > 256){
									printf("Message is larger than 256\n");
									continue;
						}
                        memset((char *)&senda, 0, sizeof(senda));
                        memcpy(senda.message, buf+offset, i-offset);
                        Log("[YOU(Anonymous)]%s", senda.message);
                        header.pkt_type = PKT_SENDA;
                        header.pkt_data_len = sizeof(senda);
                        if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                        if (Send_Blocking(sockFD, (char *) &senda, sizeof(senda)) < 0) return -1;
                } else if(strcmp(type, "SENDA2") == 0) {
                        pkt_senda2_t senda2;
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != ' '){
                                i++;
                        }
                        
                    if(i-offset > 8){
                        printf("Username is larger than 8 characters\n");
						continue;
                    }
                        //check if its a valid username
                        memset((char *)&senda2, 0, sizeof(senda2));
                        memcpy(senda2.username, buf+offset, i-offset);

                        offset = i+1;
                        i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
                        
						if(i-offset > 256){
									printf("Message is larger than 256\n");
									continue;
						}
                        //check if its a valid message
                        memcpy(senda2.message, buf+offset, i-offset);
                        Log("[YOU(Anonymous)->%s]%s", senda2.username,senda2.message);
                        header.pkt_type = PKT_SENDA2;
                                  header.pkt_data_len = sizeof(senda2);
                                 if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                                 if (Send_Blocking(sockFD, (char *) &senda2, sizeof(senda2)) < 0) return -1;
                } else if(strcmp(type, "SENDF") == 0) {
                        pkt_sendf_t sendf;
                        FILE *fn;
                        struct stat st;
                        int ret, file_len;
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
                        
                    if(i-offset > 32){
                        printf("Filename is larger than 32 characaters\n");
						continue;
                    }
                        //check if its a valid message

                        memset((char *)&sendf, 0, sizeof(sendf));
                        memcpy(sendf.file_name, buf+offset, i-offset);

                        stat(sendf.file_name, &st);
                        sendf.file_len = st.st_size;

                        fn = fopen(sendf.file_name, "rb");
                        if (fn == NULL) {
                            printf("Could not open SENDF file %s for read\n", sendf.file_name);
                            continue;
                        }
                        /* Read the entire file to a client buffer */
                        
                        ret = fread(client_send_buf, 1, sendf.file_len, fn);
                        if (ret != sendf.file_len) {
                            printf("fread returned incorrect size, got %d expected %d\n", ret, sendf.file_len);
                            continue;
                        }
                        fclose(fn);
						file_len = (sendf.file_len + 7) & ~7;
                        header.pkt_type = PKT_SENDF;
                        header.pkt_data_len = sizeof(sendf) + ((sendf.file_len + 7) & ~7);
                        Log("[YOU] Attached file %s", sendf.file_name);
                        if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                        if (Send_Blocking(sockFD, (char *) &sendf, sizeof(sendf)) < 0) return -1;
                        if (Send_Blocking(sockFD, client_send_buf, file_len) < 0) return -1;
                } else if(strcmp(type, "SENDF2") == 0) {
                        pkt_sendf2_t sendf2;
                        FILE *fn;
                        struct stat st;
                        int ret, file_len;
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != ' '){
                                i++;
                        }
                        
                        //check if its a valid username
                    if(i-offset > 8){
                        printf("Username is larger than 8 characters\n");
						continue;
                    }
                        memset((char *)&sendf2, 0, sizeof(sendf2));
                        memcpy(sendf2.username, buf+offset, i-offset);

                        offset = i+1;
                        i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
                        
                    if(i-offset > 32){
                        printf("Filename is larger than 32 characaters\n");
						continue;
                    }
                        memset(sendf2.file_name, 0, sizeof(sendf2.file_name));
                        memcpy(sendf2.file_name, buf+offset, i-offset);
                        //check if its a valid message
                        
                        stat(sendf2.file_name, &st);
                        sendf2.file_len = st.st_size;

                        fn = fopen(sendf2.file_name, "rb");
                        if (fn == NULL) {
                            printf("Could not open SENDF2 file %s for read\n", sendf2.file_name);
                            continue;
                        }
                        /* Read the entire file to a client buffer */
                        
                        ret = fread(client_send_buf, 1, sendf2.file_len, fn);
                        if (ret != sendf2.file_len) {
                            printf("fread returned incorrect size, got %d expected %d\n", ret, sendf2.file_len);
                            continue;
                        }
                        fclose(fn);
						file_len = (sendf2.file_len + 7) & ~7;
                        header.pkt_type = PKT_SENDF2;
                        header.pkt_data_len = sizeof(sendf2) + ((sendf2.file_len + 7) & ~7);
    			 Log("[YOU->%s] Attached file %s", sendf2.username, sendf2.file_name);
                        if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                        if (Send_Blocking(sockFD, (char *) &sendf2, sizeof(sendf2)) < 0) return -1;
                        if (Send_Blocking(sockFD, client_send_buf, file_len) < 0) return -1;

                } else if(strcmp(type, "LIST") == 0) {
                        header.pkt_type = PKT_LIST_REQ;
                        header.pkt_data_len = 0;
                        Log("Requested a list of all online users");
                        if (Send_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1;
                } else if(strcmp(type, "DELAY") == 0) {
                        char timestr[15] = "";
                        int offset = index+1;
                        int i = offset;
                        while(buf[i] != '\n'){
                                i++;
                        }
                        memcpy(timestr, buf+offset, i-offset);

                        //printf("Delay: %s\n", timestr);
                                 int delay = atoi(timestr);
                        //printf("Delay: %d\n", delay);
                        int timer = 0;
                        time_t end;
                        time_t start = time(NULL);

			
                        while(delay > timer){
                            int status = poll(pf, 1, (delay - timer) *1000); //check if we recieved smth
                            if(status < 0) {
                                   Error("Poll Error. Could not wait.");
                                   return -1;
                            }
                            end = time(NULL);
                            timer = end-start;
                            //printf("Time: %f\n", timer);

                           if (pf[0].revents & POLLRDNORM) {
                                   //Log("Ready to receive data\n");
                            } else {
                                   //Log("Not ready to receive data\n");
                                   //Log("time %d timer %f end %ld start %ld\n", time, timer, end, start);
				continue;
			    }
                            if (Recv_Blocking(sockFD, (char *) &header, sizeof(header)) < 0) return -1; 
                            if(header.pkt_data_len) {
                                 if (Recv_Blocking(sockFD, client_recv_buf , header.pkt_data_len) < 0) return -1;
                            }
                            switch(header.pkt_type){
                                case PKT_SEND :
                                        {
                                            pkt_send_t *send = (pkt_send_t *) client_recv_buf;
                                            printf("[%s(Public)]%s\n", send->username, send->message);
                                            break;
                                        }
                                case PKT_SEND2 :
                                        {
                                            pkt_send2_t *send2 = (pkt_send2_t *) client_recv_buf;
                                            char username[9] = "";
                                            memcpy(username, send2->username, 8); /* To take care of a terminating null for %s\n" */
                                            printf("[%s(Private)]%s \n", username,  send2->message);
                                            break;
                                        }
                                case PKT_SENDA :
                                        {
                                            pkt_senda_t *senda = (pkt_senda_t *) client_recv_buf;
                                            printf("[Anonymous(Public)]%s\n", senda->message);
                                            break;
                                        }
                                case PKT_SENDA2 :
                                        {
                                            pkt_senda2_t *senda2 = (pkt_senda2_t *) client_recv_buf;
                                            printf("[Anonymous(Private)]%s\n", senda2->message);
                                            break;
                                        }
                                case PKT_SENDF :
                                        {
                                            FILE *fn;
                                            int ret;
                                            pkt_sendf_t *sendf = (pkt_sendf_t *) client_recv_buf;
                                            printf("[%s(Public)] Sent file %s (%d bytes)\n", sendf->username, sendf->file_name,sendf->file_len);
                                            fn = fopen(sendf->file_name, "wb");
                                            if (fn == NULL) {
                                                printf("Could not open new file %s for write\n", sendf->file_name);
                                                continue;
                                            }

                                            ret = fwrite((uint8_t *)(client_recv_buf + sizeof(pkt_sendf_t)), 1, sendf->file_len, fn);
                                            if (ret != sendf->file_len) {
                                                    printf("write returned incorrect size, got %d expected %d\n", ret, sendf->file_len);
                                                    continue;
                                            }

                                            fclose(fn);
                                        }
					break;
                                case PKT_SENDF2 :
                                        {
                                            FILE *fn;
											char filename[32+1];
                                            int ret;
                                             pkt_sendf2_t *sendf2 = (pkt_sendf2_t *) client_recv_buf;
                                            char username[9];

											memset(filename, 0, sizeof(filename));
											memset(username, 0, sizeof(username));
                                            memcpy(username, sendf2->username, 8); /* To take care of a terminating null for %s\n" */
                                            printf("[%s(Private)] Sent file %s (%d bytes)\n", sendf2->username, sendf2->file_name, sendf2->file_len);

                                            fn = fopen(sendf2->file_name, "wb");
                                            if (fn == NULL) {
                                                printf("Could not open new file %s for write\n", sendf2->file_name);
                                                continue;
                                            }

                                            ret = fwrite((uint8_t *)(client_recv_buf + sizeof(pkt_sendf2_t)), 1, sendf2->file_len, fn);
                                            if (ret != sendf2->file_len) {
                                                    printf("write returned incorrect size, got %d expected %d\n", ret, sendf2->file_len);
                                                    continue;
                                            }

                                            fclose(fn);
                                            break;
                                        }
                                case PKT_LIST_RESP:
                                        {
                                               pkt_list_resp_t *list_resp = (pkt_list_resp_t *) client_recv_buf;
                                            printf("Received list of active clients - count %d\n", list_resp->count);
                                            for (i = 0; i < list_resp->count; i++) {
                                                char username[9] = "";
												memset(username, 0, sizeof(username));
                                                memcpy(username, list_resp->username[i], 8); /* To take care of a terminating null for %s\n" */
                                                printf("User%d: %s\n", i, username);
                                            }
                                            break;
                                        }
                                case PKT_ERR:
                                        {
                                            pkt_err_t *err = (pkt_err_t *) client_recv_buf;
                                            printf("[ERROR]%s\n", err->message);
                                            break;
                                        }
                            }
                    

                           }
                } else { //COULDNT FIND ANYTHING
                        printf("Ivalid command in script %s \n", type);
                }


        }
        fclose(file); /* Close the script file */
        return 0;
}
   
int main(int argc, char *argv[])
{
    int sockFD;
    struct sockaddr_in servaddr;
    char *svrIP;
    char *fileName; 
    int server_port;

     if (argc < 4) {
          printf("Usage: \n %s [server IP] [server Port] [input File] \n", argv[0]);
          exit(1);
     }

     svrIP = argv[1]; 
     server_port = atoi(argv[2]);
     fileName = argv[3];
     
    //Initialize encrypt/decrypt key
   
    // socket create and verification
    sockFD = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFD == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, svrIP, &servaddr.sin_addr);
    servaddr.sin_port = htons(server_port);
   
    // connect the client socket to server socket
    if (connect(sockFD, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
   
    memset(pf, 0, sizeof(pf));
    pf[0].fd = sockFD;
    pf[0].events = POLLRDNORM;
    pf[0].revents = 0;

    Process(fileName, sockFD);
   
    // close the socket
    close(sockFD);
    return 0;
}
