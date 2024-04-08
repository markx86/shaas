#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#ifndef __PLATFORM_H__
#error "Include platform.h before this file"
#endif

#ifndef SYS_READ
#error "SYS_READ not defined for the selected architecture"
#endif
#ifndef SYS_WRITE
#error "SYS_WRITE not defined for the selected architecture"
#endif
#ifndef SYS_CLOSE
#error "SYS_CLOSE not defined for the selected architecture"
#endif
#ifndef SYS_DUP2
#error "SYS_DUP2 not defined for the selected architecture"
#endif
#ifndef SYS_SOCKET
#error "SYS_SOCKET not defined for the selected architecture"
#endif
#ifndef SYS_CONNECT
#error "SYS_CONNECT not defined for the selected architecture"
#endif
#ifndef SYS_FORK
#error "SYS_FORK not defined for the selected architecture"
#endif
#ifndef SYS_EXECVE
#error "SYS_EXECVE not defined for the selected architecture"
#endif
#ifndef SYS_EXIT
#error "SYS_EXIT not defined for the selected architecture"
#endif

#define read(fd, buf, count) syscall3(SYS_READ, fd, (long)buf, (long)count)
#define write(fd, buf, count) syscall3(SYS_WRITE, fd, (long)buf, (long)count)
#define close(fd) syscall1(SYS_CLOSE, fd)
#define dup2(oldfd, newfd) syscall2(SYS_DUP2, oldfd, newfd)
#define socket(domain, type, protocol) \
  syscall3(SYS_SOCKET, domain, type, protocol)
#define connect(sockfd, addr, addrlen) \
  syscall3(SYS_CONNECT, sockfd, (long)addr, addrlen)
#define fork() syscall0(SYS_FORK)
#define execve(filename, argv, envp) \
  syscall3(SYS_EXECVE, (long)filename, (long)argv, (long)envp)
#define exit(code) syscall1(SYS_EXIT, code)

#endif
