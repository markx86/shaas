#ifndef __PLATFORM_H__
#error "Do not include this file directly"
#endif

#define BYTEORDER_MSB

// Override SOCK_STREAM because Linux
#define SOCK_STREAM 2

#define SYS_READ 4003
#define SYS_WRITE 4004
#define SYS_CLOSE 4006
#define SYS_DUP2 4063
#define SYS_SOCKET 4183
#define SYS_CONNECT 4170
#define SYS_SETSOCKOPT 4181
#define SYS_FORK 4002
#define SYS_EXECVE 4011
#define SYS_EXIT 4001

extern long syscall0(long n); 
asm(".global syscall0;"
    "syscall0:"
    "move $v0, $a0;"
    "syscall;"
    "jr $ra");

extern long syscall1(long n, long a); 
asm(".global syscall1;"
    "syscall1:"
    "move $v0, $a0;"
    "move $a0, $a1;"
    "syscall;"
    "jr $ra");

extern long syscall2(long n, long a, long b); 
asm(".global syscall2;"
    "syscall2:"
    "move $v0, $a0;"
    "move $a0, $a1;"
    "move $a1, $a2;"
    "syscall;"
    "jr $ra");

extern long syscall3(long n, long a, long b, long c); 
asm(".global syscall3;"
    "syscall3:"
    "move $v0, $a0;"
    "move $a0, $a1;"
    "move $a1, $a2;"
    "move $a2, $a3;"
    "syscall;"
    "jr $ra");
