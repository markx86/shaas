#ifndef __REQUEST_H__
#define __REQUEST_H__

typedef unsigned char target_id_t;

#define CLOSE_MAGIC {0xde, 0xad, 0xbe, 0xef}

union client_request {
  __attribute__((packed)) struct {
    in_addr_t connect_ip;
    in_port_t connect_port;
    unsigned short zero;
  };
  unsigned char bytes[8];
};

#endif
