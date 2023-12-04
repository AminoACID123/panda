#ifndef _COMPILER_H
#define _COMPILER_H

#if !defined(likely)
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#if !defined(unlikely)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define __packed __attribute__((packed))
#define __ctor __attribute__((constructor))
#define __hot __attribute__((hot))

#endif