#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <stdbool.h>
#include "packet.h"


const char* LOG_IN = "/login";
const char* LOG_OUT = "/logout";
const char* JOIN_SESSION = "/joinsession";
const char* LEAVE_SESSION = "/leavesession";
const char* CREATE_SESSION = "/createsession";
const char* LIST = "/list";
const char* QUIT = "/quit";

pthread_t client_p;


void* server_response(void* sfd) {
  int* sockfd = (int*)sfd;
  int byte_num = 0;
  char buffer[MAX_BUFFER] = {0};
  while (1) {
    byte_num = recv(*sockfd, buffer, MAX_BUFFER - 1, 0);
    if (byte_num < 0) {
      perror("receive server ack fail\n");
      return NULL;
    }
    if (byte_num == 0) continue;
    buffer[byte_num] = '\0';
    packet* rec_packet = stop(buffer);
    if (rec_packet->type == LO_ACK) {
      printf("login ok \n");
    } else if (rec_packet->type == LO_NAK) {
      printf("login fail \n");
      printf("%s\n", rec_packet->data);
    } else if (rec_packet->type == JN_ACK) {
      printf("join session ok \n");
    } else if (rec_packet->type == JN_NAK) {
      printf("join session fail \n");
    } else if (rec_packet->type == NS_ACK) {
      printf("create session and join ok \n");
    } else if (rec_packet->type == QU_ACK) {
      printf("list:\n%s", rec_packet->data);
    } else if (rec_packet->type == EXIT) {
      printf("%s\n", rec_packet->data);
    } else if (rec_packet->type == MESSAGE){
      printf("%s\n", rec_packet->data);
    }
    fflush(stdout);
  }

  return NULL;
}


bool login(int* sfd, struct sockaddr_in* s_addr, char* cid, char* pw, char* sip, const char* port, pthread_t* thread) {
  bool rec = true;
  do {
    //connect to server
    int rv;
		struct addrinfo hints, *servinfo, *p;
		char s[INET6_ADDRSTRLEN];
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		
		if ((rv = getaddrinfo(sip, (const char*)port, &hints, &servinfo)) != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      rec = false;
			break;
		}
		for(p = servinfo; p != NULL; p = p->ai_next) {
			if ((*sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
				fprintf(stderr ,"client: socket\n");
				continue;
			}
			if (connect(*sfd, p->ai_addr, p->ai_addrlen) == -1) {
				close(*sfd);
				fprintf(stderr, "client: connect\n");
				continue;
			}
			break; 
		}
		if (p == NULL) {
			fprintf(stderr, "client: failed to connect from addrinfo\n");
			close(*sfd);
      *sfd = -1;
      rec = false;
      break;
		}

    //prepare message
    packet pk = {0};
    strncpy((char*)pk.data, pw, MAX_DATA);
    strncpy((char*)pk.source, cid, MAX_NAME);
    pk.type = LOGIN;
    pk.size = strlen((char*)pk.data);

    char* packet_str = ptos(&pk);
    //printf("str = %s\n", packet_str);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send login file fail\n");
      rec = false;
      break;
    }

    if (pthread_create(thread, NULL, server_response, sfd) != 0) {
      printf("login error\n");
      rec = false;
      break;
    }

  } while (0);

  return rec;
}

bool logout(int* sfd, struct sockaddr_in* s_addr, char* cid, pthread_t* thread) {
  bool rec = true;
  do {
    packet p = {0};
    p.type = EXIT;
    strncpy((char*)p.source, cid, strlen(cid));
    char* packet_str = ptos(&p);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send logout file fail\n");
      rec = false;
      break;
    }
    if (pthread_cancel(*thread)) {
      fprintf(stderr, "logout failure\n");
      rec = false;
      break;
    } else {
      fprintf(stdout, "logout success\n");	
    } 

    close(*sfd);
    *sfd = -1;
  } while (0);

  return rec;
}

bool join_session(int* sfd, struct sockaddr_in* s_addr, char* sid, char* cid, pthread_t* thread) {
  bool rec = true;
  do {
    packet p = {0};
    p.type = JOIN;
    p.size = strlen(sid);
    char* session_id = sid;
    strncpy((char*)p.source, cid, strlen(cid));
    strncpy((char*)p.data, session_id, strlen(session_id));
    char* packet_str = ptos(&p);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send join file fail\n");
      rec = false;
      break;
    }
  } while (0);

  return rec;
}

bool leave_session(int* sfd, struct sockaddr_in* s_addr, char* cid, pthread_t* thread) {
  bool rec = true;
  do {
    packet p = {0};
    p.type = LEAVE_SESS;
    strncpy((char*)p.source, cid, strlen(cid));
    char* packet_str = ptos(&p);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send leave file fail\n");
      rec = false;
      break;
    }
  } while (0);

  return rec;
}

bool create_session(int* sfd, struct sockaddr_in* s_addr, char* sid, char* cid, pthread_t* thread) {
  bool rec = true;
  do {
    packet p = {0};
    p.type = NEW_SESS;
    p.size = strlen(sid);
    char* session_id = sid;
    strncpy((char*)p.source, cid, strlen(cid));
    strncpy((char*)p.data, session_id, strlen(session_id));

    char* packet_str = ptos(&p);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send create file fail\n");
      rec = false;
      break;
    }
  } while (0);

  return rec;
}

bool list(int* sfd, struct sockaddr_in* s_addr, char* cid, pthread_t* thread) {
  bool rec = true;
  do {
    packet p = {0};
    p.type = QUERY;
    strncpy((char*)p.source, cid, strlen(cid));
    char* packet_str = ptos(&p);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send list file fail\n");
      rec = false;
      break;
    }
  } while (0);

  return rec;
}

bool send_text(int* sfd, char* text, char* cid, pthread_t* thread) {
  bool rec = true;
  do {
    packet p = {0};
    p.type = MESSAGE;
    p.size = strlen(text);
    strncpy((char*)p.data, text, strlen(text));
    strncpy((char*)p.source, cid, strlen(cid));
    char* packet_str = ptos(&p);

    if (send(*sfd, packet_str, MAX_BUFFER - 1, 0) < 0) {
      fprintf(stderr, "send list file fail\n");
      rec = false;
      break;
    }
  } while (0);

  return rec;
}

int main (int argc, char const *argv[]) {
  //get input
  char input[MAX_BUFFER];
  char rec_buffer[MAX_BUFFER];

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  char client_id[MAX_BUFFER];
  char password[MAX_BUFFER];
  char ip[MAX_BUFFER];
  char session_id[MAX_BUFFER];
  int port = -1;

  fd_set read_fds;
  int fdmax = sockfd;

  while (1) {
    fgets(input, MAX_BUFFER, stdin);
    input[strcspn(input, "\n")] = 0; 

    const char* command = strtok(strdup(input), " ");  

    // /login mo 123 128.100.13.251 55000
    if (strcmp(command, LOG_IN) == 0) {
      strcpy(client_id, strtok(NULL, " ")); 
      strcpy(password, strtok(NULL, " "));
      strcpy(ip, strtok(NULL, " "));
      const char* pt = strtok(NULL, " ");
      port = atoi(pt);
      if (sockfd != -1) {
        close(sockfd);
        sockfd = -1;
      }
      sockfd = socket(AF_INET, SOCK_STREAM, 0);

      if (sockfd == -1) {
        perror("create socket fail\n");
        exit(EXIT_FAILURE);
      }

      //prepare server info
      server_addr.sin_port = htons(port);
      if (0 >= inet_pton(AF_INET, ip, &server_addr.sin_addr)) {
        fprintf(stderr, "ips convertion fail\n");
        exit(errno);
      }
      bool rec = login(&sockfd, &server_addr, (char*)client_id, (char*)password, (char*)ip, pt, &client_p);
      if (!rec) {
        printf("login function fail\n");
      }

    } else if (strcmp(command, LOG_OUT) == 0) {
      bool rec = logout(&sockfd, &server_addr, (char*)client_id, &client_p);
      if (!rec) {
        printf("logout function fail\n");
      }
    
    } else if (strcmp(command, JOIN_SESSION) == 0) {
      strcpy(session_id, strtok(NULL, " "));
      bool rec = join_session(&sockfd, &server_addr,  session_id, (char*)client_id, &client_p);
      if (!rec) {
        printf("join function fail\n");
      }
    
    } else if (strcmp(command, LEAVE_SESSION) == 0) {
      bool rec = leave_session(&sockfd, &server_addr, (char*)client_id, &client_p);
      if (!rec) {
        printf("leave function fail\n");
      }
    
    } else if (strcmp(command, CREATE_SESSION) == 0) {
      strcpy(session_id, strtok(NULL, " "));
      bool rec = create_session(&sockfd, &server_addr, session_id, (char*)client_id, &client_p);
      if (!rec) {
        printf("create function fail\n");
      }
    
    } else if (strcmp(command, LIST) == 0) {
      bool rec = list(&sockfd, &server_addr, (char*)client_id, &client_p);
      if (!rec) {
        printf("list function fail\n");
      }

    } else if (strcmp(command, QUIT) == 0) {
      bool rec = logout(&sockfd, &server_addr, (char*)client_id, &client_p);
      if (!rec) {
        printf("quit function fail\n");
      }
      break;
    } else {
      //printf("input: %s\n", input);
      bool rec = send_text(&sockfd, input, (char*)client_id, &client_p);
      if (!rec) {
        printf("send text function fail\n");
      }
    }
  }

  close(sockfd);
  sockfd = -1;
  return 0;
}