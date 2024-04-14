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
  struct sockaddr_in request_addr;
  pthread_t thread;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
} arg_pack_t;
/* ****************************************** */

// PROTOS
static int
wait_and_handle_requests(int target_fd, arg_pack_t *arg);
static int
send_close_magic(int target_fd, char *success);
/* ****************************************** */

// GLOBAL VARS
static arg_pack_t args[MAX_CONNS] = {0};
static int running;
static pthread_t listen_thread;
static int listen_fd = 0;
/* ****************************************** */

// SIGNAL HANDLERS
static void
sigint_handler(int signo) {
  running = 0;
  pthread_kill(listen_thread, SIGTERM);

  size_t i;
  for (i=0; i<MAX_CONNS; ++i) {
    if (args[i].thread != 0)
    {
      pthread_kill(args[i].thread, SIGTERM);
    }
    if (args[i].fd != 0)
    {
      (void) send_close_magic(args[i].fd, NULL);
      close(args[i].fd);
    }
    if (args[i].request_fd != 0)
      close(args[i].request_fd);
    memset(&args[i], 0, sizeof(arg_pack_t));
  }
}

static void
sigint_target_threads_handler(int signo) {
  pthread_exit(NULL);
}

static void
sigint_listen_thread_handler(int signo) {
  if (listen_fd != 0)
  {
      close(listen_fd);
      listen_fd = 0;
  }
  pthread_exit(NULL);
}

/* ****************************************** */

static int
send_close_magic(int target_fd, char *success) {
  union client_request request;
  memcpy(request.bytes, close_magic, sizeof(close_magic));
  write(target_fd, &request, sizeof(union client_request));
  if (success != NULL)  
    return read(target_fd, success, 1);
  else return 0;
}

static void
*listen_conn_handler(void *_) {
  struct sigaction sa;
  struct sockaddr_in sock_addr, request_addr;
  in_addr_t target_addr;
  int request_fd, rc, match;
  socklen_t request_addr_len;
  size_t i;

  // Install signal handler
  sa.sa_handler = &sigint_listen_thread_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGTERM, &sa, NULL) == -1) {
      perror("listener sigaction");
      return (void*)-1;
  }

  listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listen_fd < 0) {
    perror("listener socket");
    goto early_fail;
  }

  rc = 1;
  rc = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
  if (rc < 0) {
    perror("listener setsockopt");
    goto closefd_fail;
  }

  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.s_addr = INADDR_ANY;
  sock_addr.sin_port = htons(MASTER_REQUEST_PORT);

  rc = bind(listen_fd, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("listener bind");
    goto closefd_fail;
  }

  rc = listen(listen_fd, MAX_CONNS);
  if (rc < 0) {
    perror("listener listen");
    goto closefd_fail;
  }

  fprintf(stderr, "[LISTENER] Bound on port %d. Listening for clients\n", MASTER_REQUEST_PORT);

  while (true) {
    request_addr_len = sizeof(struct sockaddr_in);
    rc = request_fd =
        accept(listen_fd, (struct sockaddr*)&request_addr, &request_addr_len);
    if (rc < 0) {
      perror("listener accept");
      goto closefd_fail;
    }
    // Let's try and read 4 bytes from request_fd to get the target
    rc = read(request_fd, &target_addr, sizeof(in_addr_t));
    if (rc < 0) {
      perror("listener read target address");
      continue;
    }

    // Let's search the args array for this address
    match = 0;
    for (i=0; i<MAX_CONNS; ++i) {
      pthread_mutex_lock(&args[i].mutex);
      if (args[i].saddr.sin_addr.s_addr == target_addr)
      {
        args[i].request_fd = request_fd;
        args[i].request_addr = request_addr;
        pthread_mutex_unlock(&args[i].mutex);
        pthread_cond_signal(&args[i].cond);
        match = 1;
        break;
      }
      pthread_mutex_unlock(&args[i].mutex);
    }

    if (!match)
    {
      fputs("[LISTENER] Client asked for an IP I don't have", stderr);
      close(request_fd);
    }
  }
  return NULL;

closefd_fail:
  close(listen_fd);
  listen_fd = 0;
early_fail:
  return (void*)-1;
}

static void
*target_conn_handler(void *_) {

  // Install signal handler
  struct sigaction sa;
  sa.sa_handler = &sigint_target_threads_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGTERM, &sa, NULL) == -1) {
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
  fprintf(stderr, "[*] target connected from %s\n", ip_str);
  // TODO: error handling?
  int rc = wait_and_handle_requests(target_fd, arg);
  close(target_fd);

  // DONE: clear the global variable
  pthread_mutex_lock(&arg->mutex);
  memset(&arg->saddr, 0, sizeof(struct sockaddr_in));
  arg->fd = 0;
  arg->thread = 0;
  pthread_mutex_unlock(&arg->mutex);

  return NULL;
}

static int
wait_and_handle_requests(int target_fd, arg_pack_t *arg) {
  char success;
  int rc, request_fd;
  pthread_t tid = arg->thread;
  in_port_t request_port;
  struct sockaddr_in request_addr;
  union client_request request;
  char ip_str[INET_ADDRSTRLEN];

  while (true) {
    // Wait for listener thread to hand us a client conn
    pthread_mutex_lock(&arg->mutex);
    pthread_cond_wait(&arg->cond, &arg->mutex);
    request_fd = arg->request_fd;
    request_addr = arg->request_addr;
    arg->request_fd = 0;
    memset(&arg->request_addr, 0, sizeof(struct sockaddr_in));
    pthread_mutex_unlock(&arg->mutex);
    
    if (request_fd <= 0)
    {
      fprintf(stderr, "[%lu] Received invalid request_fd\n", tid);
      continue;
    }

    inet_ntop(AF_INET, &request_addr.sin_addr, ip_str, sizeof(ip_str));
    fprintf(stdout, "[%lu] Incoming request from %s\n", tid, ip_str);

    rc = read(request_fd, &request_port, sizeof(in_port_t));
    if (rc < 0) {
      fprintf(stderr, "[%lu] Read fail!\n", tid);
      perror("read");
      goto end_connection;
    }

    request.client_ip = request_addr.sin_addr.s_addr;
    request.client_port = request_port;

    write(target_fd, &request, sizeof(union client_request));
    rc = read(target_fd, &success, 1);
    if (rc < 0) {
      fprintf(stderr, "[%lu] Read fail!\n", tid);
      perror("read");
      success = 0;
    }
    write(request_fd, &success, 1);

  end_connection:
    close(request_fd);
    arg->request_fd = 0;
  }

  return rc;
}

int
main(void) {
  int rc, master_fd, target_fd;
  socklen_t target_addr_len;
  struct sockaddr_in master_addr, target_addr;
  struct sigaction sig_int, sig_pipe;
  size_t i, tries, pool_index = 0;
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

  // Initialize locks and conds
  for (i=0; i<MAX_CONNS; ++i)
  {
    pthread_mutex_init(&args[i].mutex, NULL);
    pthread_cond_init(&args[i].cond, NULL);
  }
  rc = listen(master_fd, MAX_CONNS);
  if (rc < 0) {
    perror("listen");
    goto close_masterfd;
  }
  
  // We launch the listener thread
  pthread_create(&listen_thread, NULL, &listen_conn_handler, NULL);

  // WE LOOP UNTIL SIGINT
  while (true) {
    target_addr_len = sizeof(struct sockaddr_in);
    rc = target_fd =
        accept(master_fd, (struct sockaddr*)&target_addr, &target_addr_len);
    if (rc < 0) {
      perror("accept");
      // Call sigint on all threads
      if (running)
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

    //fprintf(stdout, "[*] Accepted target connection");
  }
  
close_masterfd:
  close(master_fd);
early_fail:
  return rc;
}
