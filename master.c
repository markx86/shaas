#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <shaas/request.h>
#include <shaas/config.h>

#define info(fmt, ...) \
  printf("[*] " fmt "\n", ##__VA_ARGS__)
#define success(fmt, ...) \
  printf("[+] " fmt "\n", ##__VA_ARGS__)
#define error(fmt, ...) \
  fprintf(stderr, "[!] " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#define POLLRDHUP 0x2000

union pollfds {
  struct pollfd all[MASTER_TARGETS_MAX + 1];  
  struct {
    struct pollfd socket;
    struct pollfd targets[MASTER_TARGETS_MAX];
  };
};

struct target {
  int fd;
};

static int running;
static pthread_mutex_t m_targets;
static struct target targets[MASTER_TARGETS_MAX];

#ifdef MASTER_PROXY
struct __attribute__((packed)) proxy {
  struct pollfd target_pfd;
  struct pollfd client_pfd;
};

static int proxy_sock_fd;
static size_t n_proxies;
static pthread_mutex_t m_proxies;
static struct proxy proxies[MASTER_CLIENTS_MAX];
static struct sockaddr_in proxy_addr;
#endif

static void
sigint_handler(int _) {
  (void)_;
  running = 0;
  putchar('\n');
}

static int
find_first_free_target_id(target_id_t* out) {
  target_id_t i;
  assert(out != NULL);
  for (i = 0; i < MASTER_TARGETS_MAX; ++i) {
    if (targets[i].fd == 0) {
      *out = i;
      return 0;
    }
  }
  return -1;
}

static target_id_t
get_target_id_from_fd(int fd) {
  target_id_t i;
  for (i = 0; i < MASTER_TARGETS_MAX; ++i) {
    if (targets[i].fd == fd)
      return i;
  }
  assert(0 && "unreachable");
}

static int
create_and_bind_socket(struct sockaddr_in* addr) {
  int rc, sock_fd;

  rc = sock_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    error("could not create socket");
    goto early_fail;
  }

  rc = 1;
  rc = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc));
  if (rc < 0) {
    error("could not set SO_REUSEADDR on socket");
    goto close_fail;
  }

  addr->sin_family = AF_INET;

  rc = bind(sock_fd, (struct sockaddr*)addr, sizeof(*addr));
  if (rc < 0) {
    error("could not bind socket to %d", ntohs(addr->sin_port));
    goto close_fail;
  }

  rc = listen(sock_fd, 5);
  if (rc < 0) {
    error("could not listen on socket");
    goto close_fail;
  }

  success("bound socket with fd %d on port %d", sock_fd, ntohs(addr->sin_port));
  return sock_fd;
close_fail:
  close(sock_fd);
early_fail:
  return rc;
}

#ifdef MASTER_PROXY
static int
transfer_data(int from, int to) {
  int n, chunk_size, rc;
  char buf[4096];

  rc = ioctl(from, FIONREAD, &n);
  if (rc < 0) {
    perror("ioctl");
    goto fail;
  }

  while (n > 0) {
    chunk_size = n > sizeof(buf) ? sizeof(buf) : n;
    rc = chunk_size = read(from, buf, chunk_size);
    if (rc < 0)
      goto fail;
    rc = write(to, buf, rc);
    if (rc < 0)
      goto fail;
    n -= chunk_size;
  }

fail:
  return rc;
}

static int
create_and_connect_socket(struct sockaddr_in* addr) {
  int rc, sock_fd;
  char ip_str[INET_ADDRSTRLEN];

  rc = sock_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    error("could not create socket");
    goto early_fail;
  }

  inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
  addr->sin_family = AF_INET;

  rc = connect(sock_fd, (struct sockaddr*)addr, sizeof(*addr));
  if (rc < 0) {
    error("could not connect socket to %s:%d", ip_str, ntohs(addr->sin_port));
    goto close_fail;
  }

  success("connected socket with fd %d to %s:%d", sock_fd, ip_str, ntohs(addr->sin_port));
  return sock_fd;
close_fail:
  close(sock_fd);
early_fail:
  return rc;
}

static struct proxy*
get_next_proxy_slot(void) {
  if (n_proxies < MASTER_CLIENTS_MAX)
    return &proxies[n_proxies++];
  return NULL;
}

static int
open_proxy_socket(void) {
  int rc;
  socklen_t proxy_addr_len;

  proxy_addr.sin_addr.s_addr = INADDR_ANY;
  proxy_addr.sin_port = htons(0);

  rc = proxy_sock_fd = create_and_bind_socket(&proxy_addr);
  if (rc < 0) {
    info("could not create proxy socket");
    goto early_fail;
  }

  proxy_addr_len = sizeof(proxy_addr);
  rc = getsockname(proxy_sock_fd, (struct sockaddr*)&proxy_addr, &proxy_addr_len);
  if (rc < 0) {
    error("could not get proxy socket port");
    goto close_fail;
  }

  success("created proxy socket on port %d", ntohs(proxy_addr.sin_port));
  return 0;
close_fail:
  close(proxy_sock_fd);
early_fail:
  return rc;
}

static struct proxy*
setup_proxy(union client_request* req, struct sockaddr_in* req_addr) {
  int rc;
  struct proxy* proxy;
  
  req_addr->sin_port = req->connect_port;

  pthread_mutex_lock(&m_proxies);

  proxy = get_next_proxy_slot();
  if (proxy == NULL) {
    info("could not find a free proxy slot");
    return NULL;
  }

  rc = proxy->client_pfd.fd = create_and_connect_socket(req_addr);
  if (rc < 0) {
    info("could not connect to client socket for proxying");
    goto fail;
  }

  pthread_mutex_unlock(&m_proxies);

  inet_pton(AF_INET, MASTER_IP, &req->connect_ip);
  req->connect_port = proxy_addr.sin_port;

  return proxy;
fail:
  memset(proxy, 0, sizeof(struct proxy));
  return NULL;
}

#endif

static int
handle_request(int request_fd, struct sockaddr_in* request_addr) {
  char success;
  target_id_t target_id;
  int rc, target_fd;
  union client_request req;
#ifdef MASTER_PROXY
  socklen_t target_addr_len;
  struct sockaddr_in target_addr;
  struct proxy* proxy;
#endif

  success = 0;
#ifdef MASTER_PROXY
  proxy = NULL;
#endif

  rc = read(request_fd, &target_id, sizeof(target_id));
  if (rc < 0) {
    error("could not read target id from client");
    goto out;
  }

  rc = read(request_fd, &req.connect_ip, sizeof(in_addr_t));
  if (rc < 0) {
    error("could not read client ip from client");
    goto out;
  }

  rc = read(request_fd, &req.connect_port, sizeof(in_port_t));
  if (rc < 0) {
    error("could not read client port from client");
    goto out;
  }

#ifdef MASTER_PROXY
  proxy = setup_proxy(&req, request_addr);
  if (proxy == NULL) {
    info("could not setup a proxy");
    rc = -1;
    goto out;
  }
#endif
  
  if (target_id < MASTER_TARGETS_MAX) {
    pthread_mutex_lock(&m_targets);
    target_fd = targets[target_id].fd;
    if (target_fd <= 0)
      goto fail;
    pthread_mutex_unlock(&m_targets);

    rc = write(target_fd, &req, sizeof(req));
    if (rc < 0) {
      error("could not fufill client request to connect to target %u", target_id);
      goto fail;
    }

    rc = read(target_fd, &success, sizeof(success));
    if (rc < 0) {
      error("could not read ACK response from target");
      goto fail;
    }

#ifdef MASTER_PROXY
    target_addr_len = sizeof(target_addr);
    rc = proxy->target_pfd.fd = accept(proxy_sock_fd, (struct sockaddr*)&target_addr, &target_addr_len);
    if (rc < 0) {
      error("could not accept connection from target");
      goto fail;
    }
    proxy->client_pfd.events = proxy->target_pfd.events = POLLIN | POLLRDHUP;

    success("created proxy between sockets %d <-> %d", proxy->client_pfd.fd, proxy->target_pfd.fd);
#endif
    
    success = 1;
  }

fail:
  write(request_fd, &success, sizeof(success));
#ifdef MASTER_PROXY
  if (!success && proxy != NULL)
    proxy->client_pfd.fd = proxy->target_pfd.fd = 0;
#endif
out:
  return rc;
}

static void*
request_listener_routine(void* arg) {
  int rc, sock_fd, request_fd;
  socklen_t request_addr_len;
  struct pollfd pfd;
  struct sockaddr_in request_addr, request_listener_addr;
  char ip_str[INET_ADDRSTRLEN];

  request_listener_addr.sin_addr.s_addr = INADDR_ANY;
  request_listener_addr.sin_port = htons(MASTER_REQUEST_PORT);

  rc = sock_fd = create_and_bind_socket(&request_listener_addr);
  if (rc < 0) {
    info("could not initialize client listener");
    goto out;
  }

  pfd.fd = sock_fd;
  pfd.events = POLLIN;
  while (running) {
    rc = poll(&pfd, 1, 1000);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      error("could not poll request socket");
      break;
    }
    if (rc == 0)
      continue;

    request_addr_len = sizeof(request_addr);
    rc = request_fd = accept(sock_fd, (struct sockaddr*)&request_addr, &request_addr_len);
    if (rc < 0) {
      error("could not accept client connection");
      continue;
    }
    inet_ntop(AF_INET, &request_addr.sin_addr, ip_str, sizeof(ip_str));
    success("accepted client connection from %s:%d", ip_str, ntohs(request_addr.sin_port));
    rc = handle_request(request_fd, &request_addr);
    if (rc < 0)
      info("could not handle request from client %s:%d", ip_str, ntohs(request_addr.sin_port));
    close(request_fd);
  }

  close(sock_fd);
out:
  running = 0;
  return NULL;
}

static void*
target_listener_routine(void* arg) {
  target_id_t id;
  size_t i, j, n_targets;
  int rc, sock_fd, target_fd;
  socklen_t target_addr_len;
  struct pollfd* pfd;
  union pollfds pfds;
  struct sockaddr_in target_addr, target_listener_addr;
  char ip_str[INET_ADDRSTRLEN];

  target_listener_addr.sin_addr.s_addr = INADDR_ANY;
  target_listener_addr.sin_port = htons(MASTER_TARGET_PORT);

  rc = sock_fd = create_and_bind_socket(&target_listener_addr);
  if (rc < 0) {
    info("could not initialize target listener");
    goto out;
  }

  n_targets = 0;
  pfds.socket.fd = sock_fd;
  pfds.socket.events = POLLIN;
  while (running) {
    rc = poll(pfds.all, n_targets + 1, 1000);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      error("could not poll targets");
      break;
    }
    if (rc == 0)
      continue;

    // check if a target is trying to connect
    if (pfds.socket.revents & POLLIN) {
      target_addr_len = sizeof(target_addr);
      rc = target_fd = accept(sock_fd, (struct sockaddr*)&target_addr, &target_addr_len);
      if (rc < 0) {
        error("could not accept target connection");
        continue;
      }

      pthread_mutex_lock(&m_targets);
      
      rc = find_first_free_target_id(&id);
      if (rc < 0) {
        close(target_fd);
        info("could not accept target connection: too many targets");
        continue;
      }
      
      pfds.targets[n_targets].fd = targets[id].fd = target_fd;
      pfds.targets[n_targets].events = POLLRDHUP;

      inet_ntop(AF_INET, &target_addr.sin_addr, ip_str, sizeof(ip_str));
      success("accepted target (%zu) connection from %s:%d", n_targets, ip_str, ntohs(target_addr.sin_port));

      ++n_targets;
      
      pthread_mutex_unlock(&m_targets);
    }

    // check if a target has disconnected
    pthread_mutex_lock(&m_targets);
    for (i = 0; i < n_targets; ++i) {
      pfd = pfds.targets + i;
      if (pfd->revents & POLLRDHUP) {
        id = get_target_id_from_fd(pfd->fd);
        info("target (%d) disconnected", id);
        close(targets[id].fd);
        targets[id].fd = 0;
        --n_targets;
        for (j = i--; j < n_targets; ++j)
          pfds.targets[j] = pfds.targets[j+1];
      }
    }
    pthread_mutex_unlock(&m_targets);
  }

  for (i = 0; i < n_targets; ++i)
    close(pfds.targets[i].fd);

  close(sock_fd);
out:
  running = 0;
  return NULL;
}

int
main(void) {
  int rc;
  struct sigaction sigint;
  pthread_t client_listener, target_listener;
#ifdef MASTER_PROXY
  size_t i, j;
  struct proxy* proxy;
#endif

  sigint.sa_handler = &sigint_handler;
  sigint.sa_flags = 0;
  sigemptyset(&sigint.sa_mask);
  rc = sigaction(SIGINT, &sigint, NULL);
  if (rc < 0) {
    error("could not set SIGINT handler");
    goto out;
  }

  memset(targets, 0, sizeof(targets));
#ifdef MASTER_PROXY
  memset(proxies, 0, sizeof(proxies));

  rc = open_proxy_socket();
  if (rc < 0)
    goto out;
  
  n_proxies = 0;
  
  pthread_mutex_init(&m_proxies, NULL);
#endif
  pthread_mutex_init(&m_targets, NULL);

  running = 1;

  rc = pthread_create(&client_listener, NULL, &request_listener_routine, NULL);
  if (rc < 0) {
    error("could not create client listener thread");
    goto out;
  }

  rc = pthread_create(&target_listener, NULL, &target_listener_routine, NULL);
  if (rc < 0) {
    error("could not create client listener thread");
    goto out;
  }

#ifdef MASTER_PROXY
  while (running) {
    rc = poll((struct pollfd*)proxies, n_proxies << 1, 1000);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      error("could not poll proxies");
      break;
    }
    if (rc == 0)
      continue;

    for (i = 0; i < n_proxies; ++i) {
      proxy = proxies + i;      
      // check if either the client or the target has disconnected
      if ((proxy->target_pfd.revents | proxy->client_pfd.revents) & (POLLRDHUP | POLLERR)) {
        pthread_mutex_lock(&m_proxies);
        
        close(proxy->target_pfd.fd);
        close(proxy->client_pfd.fd);
        
        --n_proxies;
        for (j = i--; j < n_proxies; ++j)
          proxies[j] = proxies[j+1];

        info("closing proxy between sockets %d <-> %d", proxy->client_pfd.fd, proxy->target_pfd.fd);

        pthread_mutex_unlock(&m_proxies);
        continue;
      }

      if (proxy->target_pfd.revents & POLLIN)
        transfer_data(proxy->target_pfd.fd, proxy->client_pfd.fd);
      if (proxy->client_pfd.revents & POLLIN)
        transfer_data(proxy->client_pfd.fd, proxy->target_pfd.fd);
    }
  }
#endif

  pthread_join(client_listener, NULL);
  pthread_join(target_listener, NULL);

out:
  return rc;
}
