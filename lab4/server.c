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
#include <assert.h>
#include "packet.h"

// record all user info
user** users;
int user_count = 0; //includes logged out users
const int max_user_count = 50;

int session_count = 0;
const int max_session_count = 10;

int session_user_counts[10] = {0};
char* session_names[10];

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

bool is_valid_session_name(char* session_name) {
  return strcmp(session_name, "none") != 0;
}

int get_user_index(char* user_name) {
  for (int i=0; i < user_count; ++i) {
    if (strcmp(user_name, (char*)(users[i]->name)) == 0) {
      return i;
    }
  }
  return -1;
}

void send_packet(user** u, int type, char* name, char* msg) {
  packet p = {0};
  p.type = type;
  p.size = strlen(msg);
  memcpy(p.source, "server", strlen("server"));
  memcpy(p.data, msg, strlen(msg));
  char* p_str = ptos(&p);

  if (send((*u)->sockfd, p_str, MAX_BUFFER-1, 0) == -1) {
    printf("send %s fail\n", name);
  }
}

void login_handler(packet** info, user** new_user) {

  if (user_count >= max_user_count) { //user limit reached
    send_packet(new_user, LO_NAK, "login nak", "user limit reached, login failed");
    return;
  }

  int user_index = get_user_index((char*)(*info)->source);
  if (user_index != -1 && users[user_index]->log_status == 1) { //user already logged in
    send_packet(new_user, LO_NAK, "login nak", "user already logged in, login failed");
    return;
  }

  //login stuff
  if (user_index == -1) { //first-time login
    user_index = user_count;

    pthread_mutex_lock(&userCount_mutex);
    ++user_count;
    pthread_mutex_unlock(&userCount_mutex);
  }
  pthread_mutex_lock(&user_mutex);
  strncpy((char*)(*new_user)->name, (char*)(*info)->source, MAX_NAME);
  strncpy((char*)(*new_user)->password, (char*)(*info)->data, MAX_DATA);
  (*new_user)->log_status = 1;
  (*new_user)->session_status = 0;
  (*new_user)->session_id = "none";
  users[user_index] = *new_user;
  pthread_mutex_unlock(&user_mutex);

  send_packet(new_user, LO_ACK, "login ack", "");
}

void logout_handler(user** new_user) {

  int user_index = get_user_index((*new_user)->name);
  if (users[user_index]->log_status == 0) { //user already logged out
    send_packet(new_user, LO_NAK, "logout nak", "user already logged out, logout failed");
  }

  //logout stuff
  int session_index = get_session_index((*new_user)->session_id);
  
  if (is_valid_session_name((*new_user)->session_id) && session_index != -1) { //exit session
    pthread_mutex_lock(&sessionUserCounts_mutex);
    --session_user_counts[session_index];
    pthread_mutex_unlock(&sessionUserCounts_mutex);
    
    if (session_user_counts[session_index] == 0) {
      pthread_mutex_lock(&sessionNames_mutex);
      session_names[session_index] = "none";
      pthread_mutex_unlock(&sessionNames_mutex);

      pthread_mutex_lock(&sessionCount_mutex);
      --session_count;
      pthread_mutex_unlock(&sessionCount_mutex);
    }
  }
  pthread_mutex_lock(&user_mutex);
  (*new_user)->log_status = 0;
  (*new_user)->session_status = 0;
  (*new_user)->session_id = "none";
  pthread_mutex_unlock(&user_mutex);

  send_packet(new_user, EXIT, "logout ack", "logout successful");
}

void join_handler(packet** pack, user** new_user) {
  packet* rec_packet = *pack;
  char* session_id =(char*)(rec_packet->data);
  int session_index = get_session_index(session_id);

  if (session_index == -1) {
    printf("session does not exist\n");
    send_packet(new_user, JN_NAK, "join nak", "");
    return;
  }
  if (strcmp((*new_user)->session_id, session_id) == 0) {
    printf("user already joined session\n");
    send_packet(new_user, JN_NAK, "join nak", "");
    return;
  }

  pthread_mutex_lock(&user_mutex);
  (*new_user)->session_status = 1;
  (*new_user)->session_id = session_id;
  pthread_mutex_unlock(&user_mutex);

  //update session user count
  pthread_mutex_lock(&sessionUserCounts_mutex);
  ++session_user_counts[session_index];
  pthread_mutex_unlock(&sessionUserCounts_mutex);

  send_packet(new_user, JN_ACK, "join ack", "");
}

void leave_handler(user** user) {
  if ((*user)->session_status == 0) {
    printf("user not in a session\n");
    return;
  }

  int session_index = get_session_index((*user)->session_id);
  assert(session_index != -1);

  pthread_mutex_lock(&sessionUserCounts_mutex);
  --session_user_counts[session_index];
  pthread_mutex_unlock(&sessionUserCounts_mutex);
  if (session_user_counts[session_index] == 0) {
      pthread_mutex_lock(&sessionNames_mutex);
      session_names[session_index] = "none";
      pthread_mutex_unlock(&sessionNames_mutex);

      pthread_mutex_lock(&sessionCount_mutex);
      --session_count;
      pthread_mutex_unlock(&sessionCount_mutex);
  }

  pthread_mutex_lock(&user_mutex);
  (*user)->session_status = 0;
  (*user)->session_id = "none";
  pthread_mutex_unlock(&user_mutex);

  send_packet(user, LEAVE_SESS, "leave session ack", "");
}

void create_handler(packet** pack, user** new_user) {
  
  packet* rec_packet = *pack;
  char* session_id = (char*)(rec_packet->data);

  if (!is_valid_session_name(session_id)) {
    //printf("invalid session name, failed to create session\n");
    send_packet(new_user, JN_NAK, "create nak", "invalid session name, failed to create session");
    return;
  }

  int session_index = get_session_index(session_id);
  if (session_index != -1) {
    //printf("session already exists, failed to create session\n");
    send_packet(new_user, JN_NAK, "create nak", "session already exists, failed to create session");
    return;
  }

  session_index = get_free_session_index();
  if (session_index == -1) {
    //printf("session limit reached, failed to create session\n");
    send_packet(new_user, JN_NAK, "create nak", "session limit reached, failed to create session");
    return;
  }
  
  //create session stuff
  pthread_mutex_lock(&sessionNames_mutex);
  session_names[session_index] = session_id;
  pthread_mutex_unlock(&sessionNames_mutex);

  pthread_mutex_lock(&sessionCount_mutex);
  ++session_count;
  pthread_mutex_unlock(&sessionCount_mutex);

  pthread_mutex_lock(&sessionUserCounts_mutex);
  ++session_user_counts[session_index];
  pthread_mutex_unlock(&sessionUserCounts_mutex);

  pthread_mutex_lock(&user_mutex);
  (*new_user)->session_status = 1;
  (*new_user)->session_id = session_id;
  pthread_mutex_unlock(&user_mutex);

  send_packet(new_user, NS_ACK, "create session ack", "");
}

void message_handler(packet** pack, user** new_user) {

  char* session_id = (*new_user)->session_id;
  int session_index = get_session_index(session_id);
  if (!is_valid_session_name(session_id) || session_index == -1) {
    printf("not in any session, send message fail\n");
    return;
  }
  
  packet* rec_packet = *pack;
  char* message = (char*)(rec_packet->data);
  char* src_name = (char*)(*new_user)->name;
  //printf("%s\n", message);

  for (int i = 0; i < user_count; ++i) {
    char* dest_name = (char*)users[i]->name;
    if (strcmp(dest_name, src_name) == 0) { //don't send to self
      continue;
    }

    if (strcmp(users[i]->session_id, session_id) == 0) {
      send_packet(&users[i], MESSAGE, "message", message);
    }
  }

}

void list_handler(user** new_user) {
  //calculate string length
  int str_length = 1; //for null terminator
  for (int i = 0; i < user_count; ++i) {
    str_length += strlen((char*)users[i]->name) + strlen((*new_user)->session_id) + 3; 
  }

  //build string
  char* list_str = malloc(str_length * sizeof(char));
  list_str[0] = '\0'; //so strcat works properly
  for (int i = 0; i < user_count; ++i) {
    char* name = (char*)users[i]->name;
    char* sid = users[i]->session_id;
    strcat(list_str, name);
    strcat(list_str, "; ");
    strcat(list_str, sid);
    strcat(list_str, "\n");
  }
  list_str[str_length-1] = '\0';

  send_packet(new_user, QU_ACK, "list ack", list_str);
  free(list_str);
}

void* event_handler(void *arg) {

  user* new_user = (user*) arg;
  char buffer[MAX_BUFFER] = {0};
  int byte_num;
  
  while (1) {
    byte_num = recv(new_user->sockfd, buffer, MAX_BUFFER - 1, 0);
    printf("received %d bytes\n", byte_num);

    if (byte_num < 0) {
      if (errno  == ECONNRESET) {
        logout_handler(&new_user);
      }
      break;
    }
    if (byte_num == 0) {
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
  users = malloc(max_user_count * sizeof(user*));

  //init session names (no mutex needed yet)
  for (int i=0; i < max_session_count; ++i) {
    session_names[i] = "none";
  }

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