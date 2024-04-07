#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <shaas/request.h>
#include <shaas/config.h>

static int running;

static void
sigint_handler(int signo) {
  running = 0;
}

static int
listen_for_requests(int target_fd) {
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
    if (rc < 0)
      success = 0;
    write(request_fd, &success, 1);

  end_connection:
    close(request_fd);
  }

closefd_fail:
  close(sock_fd);
early_fail:
  return rc;
}

int
main(void) {
  int rc, master_fd, target_fd;
  socklen_t target_addr_len;
  struct sockaddr_in master_addr, target_addr;
  struct sigaction sig_int, sig_pipe;
  char ip_str[INET_ADDRSTRLEN];

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
    goto closefd_fail;
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
    goto closefd_fail;
  }

  rc = listen(master_fd, 1);
  if (rc < 0) {
    perror("listen");
    goto closefd_fail;
  }

  target_addr_len = sizeof(struct sockaddr_in);
  rc = target_fd =
      accept(master_fd, (struct sockaddr*)&target_addr, &target_addr_len);
  if (rc < 0) {
    perror("accept");
    goto closefd_fail;
  }

  inet_ntop(AF_INET, &target_addr.sin_addr, ip_str, sizeof(ip_str));
  printf("target connected from %s\n", ip_str);

  rc = listen_for_requests(target_fd);

  close(target_fd);
closefd_fail:
  close(master_fd);
early_fail:
  return rc;
}
