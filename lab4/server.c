#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/select.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include "packet.h"

// record all user info
user** users;
int user_count = 0; //includes logged out users
const int max_user_count = 50;

int session_count = 0;
const int max_session_count = 10;

int session_user_counts[10] = {0};
char* session_names[10] = {0};

pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t userCount_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sessionCount_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sessionUserCounts_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sessionNames_mutex = PTHREAD_MUTEX_INITIALIZER;


int get_session_index(char* session_name) {
  for (int i=0; i < max_session_count; ++i) {
    if (strcmp(session_name, session_names[i]) == 0) {
      return i;
    }
  }
  return -1;
}

int get_free_session_index() {
  for (int i=0; i< max_session_count; ++i) {
    if (session_user_counts[i] == 0) {
      return i;
    }
  }
  return -1;
}

int get_user_index(char* user_name) {
  for (int i=0; i < user_count; ++i) {
    if (strcmp(user_name, (char*)(users[i]->name)) == 0) {
      return i;
    }
  }
  return -1;
}

void send_nak(user** u, char* name, char* msg) {
  packet p = {0};
  p.type = LO_NAK;
  memcpy(p.source, "server", strlen("server"));
  p.size = strlen(msg);
  memcpy(p.data, msg, strlen(msg));
  char* p_str = ptos(&p);

  if (send((*u)->sockfd, p_str, MAX_BUFFER-1, 0) == -1) {
    printf("send %s NAK fail\n", name);
  }
}

void send_ack(user** u, char* name) {
  packet p = {0};
  p.type = LO_ACK;
  char* p_str = ptos(&p);

  if (send((*u)->sockfd, p_str, MAX_BUFFER-1, 0) == -1) {
    printf("send %s ACK fail\n", name);
  }
}

void login_handler(packet** info, user** new_user) {

  if (user_count >= max_user_count) { //user limit reached
    send_nak(new_user, "login", "user limit reached, login failed");
    return;
  }

  int user_index = get_user_index((char*)(*info)->source);
  if (user_index >= 0 && users[user_index]->log_status == 1) { //user already logged in
    send_nak(new_user, "login", "user already logged in, login failed");
    return;
  }

  //login stuff
  pthread_mutex_lock(&user_mutex);
  strncpy((char*)(*new_user)->name, (char*)(*info)->source, MAX_NAME);
  strncpy((char*)(*new_user)->password, (char*)(*info)->data, MAX_DATA);
  (*new_user)->log_status = 1;
  (*new_user)->session_status = 0;
  (*new_user)->session_id = "none";
  users[user_count] = *new_user;
  pthread_mutex_unlock(&user_mutex);

  pthread_mutex_lock(&userCount_mutex);
  ++user_count;
  pthread_mutex_unlock(&userCount_mutex);

  send_ack(new_user, "login");
}

void logout_handler(user** new_user) {
  packet back_p = {0};
  back_p.type = EXIT;

  int user_index = get_user_index((*new_user)->name));
  if (users[user_index]->log_status == 0) { //user already logged out
    char* s = "already logout";
    memcpy(back_p.data, s, strlen(s));
    memcpy(back_p.source, "server", strlen("server"));
    back_p.size = strlen(s);

    char* str = ptos(&back_p);
    if (send((*new_user)->sockfd, str, MAX_BUFFER - 1, 0) == -1) {
      printf("sending \"already logout ack\" failed\n");
    }
    return;
  }

  //logout stuff
  int session_index = get_session_index((*new_user)->session_id);
  if (session_index != -1) { //exit session

  }
  pthread_mutex_lock(&user_mutex);
  (*new_user)->log_status = 0;
  (*new_user)->session_status = 0;
  (*new_user)->session_id = "none";
  pthread_mutex_unlock(&user_mutex);

  char* s = "logout successful";
  memcpy(back_p.data, s, strlen(s));
  back_p.size = strlen(s);
  memcpy(back_p.source, "server", strlen("server"));
  char* str = ptos(&back_p);
  if (send((*new_user)->sockfd, str, MAX_BUFFER - 1, 0) == -1) {
    printf("send logout ack fail\n");
  }
  
}

void join_handler(packet** pack, user** new_user) {
  packet* rec_packet = *pack;
  char* session_id =(char*)(rec_packet->data);
  bool rec = true;

  if (strcmp(session_id, server_session) != 0) {
    printf("join session does not exist\n");
    rec = false;
  }
  if (strcmp((*new_user)->session_id, server_session) == 0) {
    printf("already in the join session\n");
    rec = false;
  }
  if (!rec) {
    packet back_p = {0};
    back_p.type = JN_NAK;
    char* back_str = ptos(&back_p);
    if (send((*new_user)->sockfd, back_str, MAX_BUFFER - 1, 0) == -1) {
      printf("send join ack fail\n");
    }
    return;
  }

  pthread_mutex_lock(&user_mutex);
  (*new_user)->session_status = 1;
  (*new_user)->session_id = session_id;
  pthread_mutex_unlock(&user_mutex);

  //update session user count
  pthread_mutex_lock(&sessionUserCnt_mutex);
  current_session_user_count += 1;
  pthread_mutex_unlock(&sessionUserCnt_mutex);

  packet back_p = {0};
  back_p.type = JN_ACK;

  char* back_str = ptos(&back_p);
  if (send((*new_user)->sockfd, back_str, MAX_BUFFER - 1, 0) == -1) {
    printf("send join ack fail\n");
  }

}

void leave_handler(user** new_user) {
  if ((*new_user)->session_status == 0) {
    printf("already leave session\n");
    return;
  }

  pthread_mutex_lock(&user_mutex);
  (*new_user)->session_status = 0;
  (*new_user)->session_id = "none";
  pthread_mutex_unlock(&user_mutex);

  //update session user count
  pthread_mutex_lock(&sessionUserCnt_mutex);
  current_session_user_count -= 1;
  if (current_session_user_count == 0) {
    current_session_num = 0;
    server_session = "";
  }
  pthread_mutex_unlock(&sessionUserCnt_mutex);

  packet back_p = {0};
  back_p.type = LEAVE_SESS;

  char* back_str = ptos(&back_p);
  if (send((*new_user)->sockfd, back_str, MAX_BUFFER - 1, 0) == -1) {
    printf("send leave session ack fail\n");
  }
  /*
  else {
    //find session user count
    int user_count = 0;
    for (int i = 0; i < user_num; ++ i) {
      //char* name = (char*)users[i]->name;
      char* sid = users[i]->session_id;
      if (strcmp((*new_user)->session_id, sid) == 0) {
        user_count += 1;
      }
    }
    if (user_count == 0) { //delete session

    }
  }*/
}

void create_handler(packet** pack, user** new_user) {
  if (current_session_num >= max_session_num) {
    printf("have max session already\n");
    return;
  }
  

  packet* rec_packet = *pack;
  char* session_id = (char*)(rec_packet->data);
  server_session = session_id;

  pthread_mutex_lock(&user_mutex);
  (*new_user)->session_status = 1;
  (*new_user)->session_id = server_session;
  pthread_mutex_unlock(&user_mutex);

  //update session user count
  pthread_mutex_lock(&sessionUserCnt_mutex);
  current_session_user_count += 1;
  pthread_mutex_unlock(&sessionUserCnt_mutex);

  pthread_mutex_lock(&sessionCnt_mutex);
  ++ current_session_num;
  pthread_mutex_unlock(&sessionCnt_mutex);


  packet back_p = {0};
  back_p.type = NS_ACK;

  char* back_str = ptos(&back_p);
  if (send((*new_user)->sockfd, back_str, MAX_BUFFER - 1, 0) == -1) {
    printf("send create ack fail\n");
  }

}

void message_handler(packet** pack, user** new_user) {
  char* session_id = (*new_user)->session_id;
  if (strcmp(session_id, "none") == 0) {
    printf("not in any session, send message fail\n");
    return;
  }
  if (strcmp(session_id, server_session) != 0) {
    printf("not in server session, send message fail\n");
    return;
  }
  
  packet* rec_packet = *pack;
  char* message = (char*)(rec_packet->data);

  packet back_p = {0};
  back_p.type = MESSAGE;
  back_p.size = strlen(message);
  memcpy(back_p.source, "server", strlen("server"));
  memcpy(back_p.data, message, strlen(message));

  char* mes = ptos(&back_p);

  for (int i = 0; i < user_num; ++ i) {
    char* uname = (char*)users[i]->name;
    char* current_user = (char*)(*new_user)->name;
    if (strcmp(users[i]->session_id, session_id) == 0 && strcmp(uname, current_user) != 0) {
      if((send(users[i]->sockfd, mes, MAX_BUFFER - 1, 0)) == -1) {
        printf("send message fail\n");
        return;
      }
    }
  }

}

void list_handler(user** new_user) {
  int str_length = 0;
  for (int i = 0; i < user_num; ++i) {
    str_length += strlen((char*)users[i]->name) + strlen((*new_user)->session_id) + 3; 
  }
  char* list_str = malloc(str_length * sizeof(char));

  for (int i = 0; i < user_num; ++ i) {
    char* name = (char*)users[i]->name;
    char* sid = users[i]->session_id;
    strcat(list_str, name);
    strcat(list_str, ":");
    strcat(list_str, sid);
    if (i < user_num - 1) {
      strcat(list_str, ":");
    }
    
  }
  list_str[str_length] = '\0';

  packet back_p = {0};
  back_p.type = QU_ACK;
  back_p.size = strlen(list_str);
  memcpy(back_p.source, "server", strlen("server"));
  memcpy(back_p.data, list_str, strlen(list_str));

  char* back_str = ptos(&back_p);
  if (send((*new_user)->sockfd, back_str, MAX_BUFFER - 1, 0) == -1) {
    printf("send list ack fail\n");
  }
  free(list_str);
}

void* event_handler(void *arg) {
  user* new_user = (user*) arg;
  char buffer[MAX_BUFFER] = {0};
  int byte_num;

  while (1) {
    byte_num = recv(new_user->sockfd, buffer, MAX_BUFFER - 1, 0);
    if (byte_num < 0) {
      printf("receive str fail\n");
      if (errno  == ECONNRESET) {
        logout_handler(&new_user);
      }
      break;
    }
    if (byte_num == 0) {
      printf("close conn/n");
      logout_handler(&new_user);
      break;
    }
    buffer[byte_num] = '\0';

    packet* p = stop(buffer);

    if (p->type == LOGIN) {
      login_handler(&p, &new_user);
    } else if (p->type == NEW_SESS) {
      create_handler(&p, &new_user);
    } else if (p->type == JOIN) {
      join_handler(&p, &new_user);
    } else if (p->type == LEAVE_SESS) {
      leave_handler(&new_user);
    } else if (p->type == QUERY) {
      list_handler(&new_user);
    } else if (p->type == EXIT) {
      logout_handler(&new_user);
    } else if (p->type == MESSAGE) {
      message_handler(&p, &new_user);
    }
    
  }
  return NULL;
}


int main (int argc, char const *argv[]) {
  struct addrinfo hints, *servinfo, *p;
  int yes = 1;
  int rv;

  int port = atoi(argv[1]);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;    
  hints.ai_flags = AI_PASSIVE;       
  if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  int sockfd;
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("Server: socket");
      continue;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
    }
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("Server: bind");
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo); 

  if (listen(sockfd, 10) < 0) {
    perror("listen failed");
    exit(EXIT_FAILURE);
  }
  printf("Server is listening on port %d\n", port);

  //init users
  users = malloc(max_user * sizeof(user*));

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    user* new_user = malloc(sizeof(user));
    int new_socket = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_size);
   
    if (new_socket < 0) {
      perror("accept failed");
      continue; 
    }

    new_user->sockfd = new_socket;

    pthread_create(&(new_user -> p), NULL, event_handler, (void *)new_user);

  }

  close(sockfd);

  return 0;
}