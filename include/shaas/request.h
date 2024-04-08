#ifndef __REQUEST_H__
#define __REQUEST_H__

const unsigned char close_magic[] =
    {0xde, 0xad, 0xbe, 0xef, 0xba, 0xbe, 0x00, 0x00};

union client_request {
  __attribute__((packed)) struct {
    in_addr_t client_ip;
    in_port_t client_port;
    unsigned short zero;
  };
  unsigned char bytes[8];
};

#endif
