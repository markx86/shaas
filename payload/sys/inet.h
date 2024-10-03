#ifndef __INET_H__
#define __INET_H__

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

#ifndef SOL_SCOKET
#define SOL_SOCKET 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef PF_INET
#define PF_INET 2
#endif

#define AF_INET PF_INET

typedef unsigned short sa_family_t;
typedef unsigned short in_port_t;
typedef unsigned int in_addr_t;

struct in_addr {
  in_addr_t s_addr;
};

struct sockaddr {
  sa_family_t sa_family;
  char data[14];
};

struct sockaddr_in {
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
  unsigned char sin_zero
      [sizeof(struct sockaddr) - sizeof(sa_family_t) - sizeof(in_port_t) -
       sizeof(struct in_addr)];
};

#endif
