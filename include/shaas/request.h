#ifndef __REQUEST_H__
#define __REQUEST_H__

#define CLOSE_MAGIC {0xde, 0xad, 0xbe, 0xef}

union client_request {
  __attribute__((packed)) struct {
    in_addr_t client_ip;
    in_port_t client_port;
    unsigned short zero;
  };
  unsigned char bytes[8];
};

#endif
