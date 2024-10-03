#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <shaas/config.h>

static int running;

static void
sigint_handler(int signo) {
  running = 0;
}

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

int
main(int argc, char **argv) {
  char success, *invalid_ptr, *master_ip;
  int rc, listen_fd, shell_fd, master_fd;
  size_t target_id;
  socklen_t target_addr_len;
  struct sockaddr_in listen_addr, master_addr, target_addr;
  struct sigaction sig_alrm, sig_int;
  struct pollfd pfds[2];
  char ip_str[INET_ADDRSTRLEN];
  struct in_addr target_ip;

  if (argc < 3) {
    fputs("Please specify a target IP: ./shaas TARGET_ID CLIENT_IP [MASTER_IP]\n", stderr);
    return -1;
  }

  target_id = strtoul(argv[1], &invalid_ptr, 10);
  if (invalid_ptr == NULL || invalid_ptr[0] != '\0') {
    fputs("Invalid target ID\n", stderr);
    return -1;
  }

  rc = inet_pton(AF_INET, argv[2], &target_ip);
  if (rc != 1) {
    fputs("Invalid target IP\n", stderr);
    return -1;
  }

  sig_alrm.sa_flags = 0;
  sig_alrm.sa_handler = SIG_IGN;
  sigemptyset(&sig_alrm.sa_mask);

  rc = sigaction(SIGALRM, &sig_alrm, NULL);
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

  rc = listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    perror("socket");
    goto early_fail;
  }

  rc = 1;
  rc = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(int));
  if (rc < 0) {
    perror("setsockopt");
    goto close_listenfd;
  }

  listen_addr.sin_family = AF_INET;
  listen_addr.sin_addr.s_addr = INADDR_ANY;
  listen_addr.sin_port = htons(CLIENT_PORT);

  rc = bind(
      listen_fd,
      (struct sockaddr*)&listen_addr,
      sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("bind");
    goto close_listenfd;
  }

  rc = listen(listen_fd, 1);
  if (rc < 0) {
    perror("listen");
    goto close_listenfd;
  }

  rc = master_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (rc < 0) {
    perror("socket");
    goto close_listenfd;
  }

  master_addr.sin_family = AF_INET;
  master_ip = argc == 4 ? argv[3] : MASTER_IP;
  inet_pton(master_addr.sin_family, master_ip, &master_addr.sin_addr);
  master_addr.sin_port = htons(MASTER_REQUEST_PORT);

  rc = connect(
      master_fd,
      (struct sockaddr*)&master_addr,
      sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("connect");
    goto close_masterfd;
  }
  
  write(master_fd, &target_id, sizeof(size_t));
  write(master_fd, &target_ip.s_addr, sizeof(in_addr_t));
  write(master_fd, &listen_addr.sin_port, sizeof(in_port_t));
  rc = read(master_fd, &success, 1);
  if (rc < 0) {
    perror("read");
    goto close_masterfd;
  }
  if (!success) {
    fprintf(stderr, "the target refused the connection\n");
    goto close_masterfd;
  }
  close(master_fd);

  target_addr_len = sizeof(struct sockaddr_in);
  alarm(5);
  rc = shell_fd =
      accept(listen_fd, (struct sockaddr*)&target_addr, &target_addr_len);
  if (rc < 0) {
    perror("accept");
    goto close_listenfd;
  }
  alarm(0);

  inet_ntop(
      target_addr.sin_family,
      &target_addr.sin_addr,
      ip_str,
      sizeof(ip_str));
  printf("target connected from %s\n", ip_str);

  close(listen_fd);

  running = 1;
  pfds[0].fd = 0;
  pfds[0].events = POLLIN;
  pfds[1].fd = shell_fd;
  pfds[1].events = POLLIN;
  while (running) {
    rc = poll(pfds, 2, 1000);
    if (rc == 0)
      continue;
    else if (rc < 0) {
      if (errno == EINTR)
        continue;
      perror("poll");
      break;
    }
    if (pfds[0].revents & POLLIN)
      transfer_data(0, shell_fd);
    if (pfds[1].revents & POLLIN)
      transfer_data(shell_fd, 1);
  }

  close(shell_fd);
  return 0;
close_masterfd:
  close(master_fd);
close_listenfd:
  close(listen_fd);
early_fail:
  return rc;
}
