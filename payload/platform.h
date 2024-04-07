#ifndef __PLATFORM_H__
#define __PLATFORM_H__

static long syscall0(long);
static long syscall1(long, long);
static long syscall2(long, long, long);
static long syscall3(long, long, long, long);

#if defined(TARGET_x86_64)
#include "platform/platform-x86_64.h"
#else
#error "No target platform specified"
#endif

#if !defined(BYTEORDER_LSB) && !defined(BYTEORDER_MSB)
#error "No platform byteorder defined"
#endif

#endif
