#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#ifndef __PLATFORM_H__
#	error "Include platform.h before this file"
#endif

#define read(fd, buf, count) \
	syscall3(SYS_READ, fd, (long)buf, (long)count)
#define write(fd, buf, count) \
	syscall3(SYS_WRITE, fd, (long)buf, (long)count)
#define close(fd) \
	syscall1(SYS_CLOSE, fd)
#define dup2(oldfd, newfd) \
	syscall2(SYS_DUP2, oldfd, newfd)
#define socket(domain, type, protocol) \
	syscall3(SYS_SOCKET, domain, type, protocol)
#define connect(sockfd, addr, addrlen) \
	syscall3(SYS_CONNECT, sockfd, (long)addr, addrlen)
#define fork() \
	syscall0(SYS_FORK)
#define execve(filename, argv, envp) \
	syscall3(SYS_EXECVE, (long)filename, (long)argv, (long)envp)
#define exit(code) \
	syscall1(SYS_EXIT, code)

#endif
