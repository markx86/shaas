#ifndef __PLATFORM_H__
#error "Do not include this file directly"
#endif

#define BYTEORDER_LSB

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_DUP2 33
#define SYS_SOCKET 41
#define SYS_CONNECT 42
#define SYS_SETSOCKOPT 54
#define SYS_FORK 57
#define SYS_EXECVE 59
#define SYS_EXIT 60

static __attribute__((naked)) long
syscall0(long n) {
  asm("movq %rdi, %rax;"
      "syscall;"
      "ret");
}

static __attribute__((naked)) long
syscall1(long n, long a) {
  asm("movq %rdi, %rax;"
      "movq %rsi, %rdi;"
      "syscall;"
      "ret");
}

static __attribute__((naked)) long
syscall2(long n, long a, long b) {
  asm("movq %rdi, %rax;"
      "movq %rsi, %rdi;"
      "movq %rdx, %rsi;"
      "movq %rcx, %rdx;"
      "syscall;"
      "ret");
}

static __attribute__((naked)) long
syscall3(long n, long a, long b, long c) {
  asm("movq %rdi, %rax;"
      "movq %rsi, %rdi;"
      "movq %rdx, %rsi;"
      "movq %rcx, %rdx;"
      "syscall;"
      "ret");
}
