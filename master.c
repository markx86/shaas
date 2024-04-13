#include "include/shaas/config.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <shaas/request.h>
#include <shaas/config.h>
#include <pthread.h>
#include <stdbool.h>

// LOCAL TYPE DEFINITIONS
typedef struct {
  struct sockaddr_in saddr;
  int fd;
  int request_fd;
  int listen_fd;
  pthread_t thread;
  pthread_mutex_t mutex;
} arg_pack_t;

// PROTOS
static int
listen_for_requests(int target_fd, arg_pack_t *arg);

// GLOBAL VARS
static size_t pool_index = 0;
static arg_pack_t args[MAX_CONNS] = {0};
static int running;

static void
sigint_handler(int signo) {
  running = 0;

  size_t i;
  for (i=0; i<MAX_CONNS; ++i) {
    if (args[i].fd != 0)
      close(args[i].fd);
    if (args[i].request_fd != 0)
      close(args[i].request_fd);
    if (args[i].listen_fd != 0)
      close(args[i].listen_fd);
    memset(&args[i], 0, sizeof(arg_pack_t));
  }
}

static void
sigint_thread_handler(int signo){
  pthread_exit(NULL);
}

static void
*target_conn_handler(void *_) {

  // Set sigint handler which brutally exits the thread on sigint
  // fds are closed by the main thread sigint handler
  struct sigaction sa;
  sa.sa_handler = &sigint_thread_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1) {
      perror("sigaction");
      return (void*)-1;
  }

  // UNPACK
  arg_pack_t *arg = (arg_pack_t*)_;
  pthread_mutex_lock(&arg->mutex);
  struct sockaddr_in target_addr = arg->saddr;
  int target_fd = arg->fd;
  pthread_mutex_unlock(&arg->mutex);

  // Start thread to handle the connection
  char ip_str[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &target_addr.sin_addr, ip_str, sizeof(ip_str));
  printf("target connected from %s\n", ip_str);
  // TODO: error handling?
  int rc = listen_for_requests(target_fd, arg);
  close(target_fd);

  // DONE: clear the global variable
  pthread_mutex_lock(&arg->mutex);
  memset(&arg->saddr, 0, sizeof(struct sockaddr_in));
  arg->fd = 0;
  pthread_mutex_unlock(&arg->mutex);

  return NULL;
}

static int
listen_for_requests(int target_fd, arg_pack_t *arg) {
  char success;
  int rc, request_fd, sock_fd;
  socklen_t request_addr_len;
  in_port_t request_port;
  struct sockaddr_in sock_addr, request_addr;
  union client_request request;
  char ip_str[INET_ADDRSTRLEN];

  rc = sock_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    perror("socket");
    goto early_fail;
  }

  // Record this socket into the table
  arg->listen_fd = sock_fd;

  rc = 1;
  rc = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
  if (rc < 0) {
    perror("setsockopt");
    goto closefd_fail;
  }

  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.s_addr = INADDR_ANY;
  sock_addr.sin_port = htons(MASTER_REQUEST_PORT);

  rc = bind(sock_fd, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("bind");
    goto closefd_fail;
  }

  rc = listen(sock_fd, 8);
  if (rc < 0) {
    perror("listen");
    goto closefd_fail;
  }

  running = 1;
  while (running) {
    request_addr_len = sizeof(struct sockaddr_in);
    rc = request_fd =
        accept(sock_fd, (struct sockaddr*)&request_addr, &request_addr_len);
    if (rc < 0) {
      if (!running) {
        rc = 0;
        break;
      } else
        continue;
    }

    // Record the fd into the table, so we can clear it when SIGINT
    arg->request_fd = request_fd;

    inet_ntop(AF_INET, &request_addr.sin_addr, ip_str, sizeof(ip_str));
    printf("incoming request from %s\n", ip_str);

    rc = read(request_fd, &request_port, sizeof(in_port_t));
    if (rc < 0) {
      perror("read");
      goto end_connection;
    }

    request.client_ip = request_addr.sin_addr.s_addr;
    request.client_port = request_port;

    write(target_fd, &request, sizeof(union client_request));
    rc = read(target_fd, &success, 1);
    if (rc < 0) {
      perror("read");
      success = 0;
    }
    write(request_fd, &success, 1);

  end_connection:
    close(request_fd);
    arg->request_fd = 0;
  }

  // send close request to payload
  memcpy(request.bytes, close_magic, sizeof(close_magic));
  write(target_fd, &request, sizeof(union client_request));
  rc = read(target_fd, &success, 1);
  if (rc < 0)
    perror("read");
  else if (!success)
    rc = -1;
  else
    rc = 0;

closefd_fail:
  close(sock_fd);
  arg->listen_fd = 0;
early_fail:
  return rc;
}

int
main(void) {
  int rc, master_fd, target_fd;
  socklen_t target_addr_len;
  struct sockaddr_in master_addr, target_addr;
  struct sigaction sig_int, sig_pipe;
  size_t i, tries;
  //char ip_str[INET_ADDRSTRLEN];

  sig_pipe.sa_flags = 0;
  sig_pipe.sa_handler = SIG_IGN;
  sigemptyset(&sig_pipe.sa_mask);

  rc = sigaction(SIGPIPE, &sig_pipe, NULL);
  if (rc < 0) {
    perror("sigaction");
    goto early_fail;
  }

  sig_int.sa_flags = 0;
  sig_int.sa_handler = &sigint_handler;
  sigemptyset(&sig_int.sa_mask);

  rc = sigaction(SIGINT, &sig_int, NULL);
  if (rc < 0) {
    perror("sigaction");
    goto early_fail;
  }

  rc = master_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    perror("socket");
    goto early_fail;
  }

  rc = 1;
  rc = setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
  if (rc < 0) {
    perror("setsockopt");
    goto close_masterfd;
  }

  master_addr.sin_family = AF_INET;
  master_addr.sin_addr.s_addr = INADDR_ANY;
  master_addr.sin_port = htons(MASTER_TARGET_PORT);

  rc = bind(
      master_fd,
      (struct sockaddr*)&master_addr,
      sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("bind");
    goto close_masterfd;
  }

  fprintf(stdout, "[!] Bound on port %d. Listening for targets\n", MASTER_TARGET_PORT);

  // Initialize locks
  for (i=0; i<MAX_CONNS; ++i)
    pthread_mutex_init(&args[i].mutex, NULL);

  rc = listen(master_fd, MAX_CONNS);
  if (rc < 0) {
    perror("listen");
    goto close_masterfd;
  }

  target_addr_len = sizeof(struct sockaddr_in);
  
  // WE LOOP UNTIL SIGINT
  while (true) {
    rc = target_fd =
        accept(master_fd, (struct sockaddr*)&target_addr, &target_addr_len);
    if (rc < 0) {
      perror("accept");
      // Call sigint on all threads
      kill(0, SIGINT);
      goto close_masterfd;
    }

    // We try to acquire the lock for a number of slot, before renouncing
    for (tries = 0; tries < MAX_CONNS; ++tries) {
      if (pthread_mutex_trylock(&args[pool_index].mutex) == 0) {
        if (args[pool_index].fd == 0)
          break;
        pthread_mutex_unlock(&args[pool_index].mutex);
      }

      pool_index = (pool_index+1) % MAX_CONNS;
    }

    // No slots, discard connection (sorry pal)
    if (tries == MAX_CONNS)
      continue;

    // We have handled sync, now let's launch the thread
    args[pool_index].fd = target_fd;
    args[pool_index].saddr = target_addr;
    pthread_create(&args[pool_index].thread, NULL, &target_conn_handler, (void*) &args[pool_index]);
    pthread_mutex_unlock(&args[pool_index].mutex);
    
    // We can no longer use this slot
    pool_index = (pool_index+1) % MAX_CONNS;

    fprintf(stdout, "[*] Accepted target connection");
  }
  
close_masterfd:
  close(master_fd);
early_fail:
  return rc;
}
