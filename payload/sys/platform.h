#ifndef __PLATFORM_H__
#define __PLATFORM_H__

extern long syscall0(long);
extern long syscall1(long, long);
extern long syscall2(long, long, long);
extern long syscall3(long, long, long, long);

#if defined(TARGET_ARCH_x86_64)
#include "platform/platform-x86_64.h"
#elif defined(TARGET_ARCH_mips32)
#include "platform/platform-mips32.h"
#else
#error "No target platform specified"
#endif

#if !defined(BYTEORDER_LSB) && !defined(BYTEORDER_MSB)
#error "No platform byteorder defined"
#endif

#endif
