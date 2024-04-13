#ifndef __CONFIG_H__
#define __CONFIG_H__

#ifndef TARGET_SHELL
#define TARGET_SHELL "/bin/sh"
#endif

#ifndef TARGET_ARGV
#define TARGET_ARGV "-i"
#endif

#ifndef TARGET_ENVP
#define TARGET_ENVP "TERM=linux"
#endif

#ifndef MASTER_IP
#define MASTER_IP "127.0.0.1"
#endif

#ifndef MASTER_TARGET_PORT
#define MASTER_TARGET_PORT 1337
#endif

#ifndef MASTER_REQUEST_PORT
#define MASTER_REQUEST_PORT 6969
#endif

#ifndef CLIENT_PORT
#define CLIENT_PORT 4200
#endif

#ifndef MAX_CONNS
#define MAX_CONNS 128
#endif

#endif
