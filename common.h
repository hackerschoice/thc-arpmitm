#ifndef THC_ARPMITM_COMMON_H_
#define THC_ARPMITM_COMMON_H_

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
   //define something for Windows (32-bit and 64-bit, this part is common)
   #ifdef _WIN64
      //define something for Windows (64-bit only)
   #else
      //define something for Windows (32-bit only)
   #endif
#elif __APPLE__
    #include <TargetConditionals.h>
    #if TARGET_IPHONE_SIMULATOR
         // iOS Simulator
    #elif TARGET_OS_IPHONE
        // iOS device
    #elif TARGET_OS_MAC
        // Other kinds of Mac OS
    #else
    #   error "Unknown Apple platform"
    #endif
#elif __linux__
    // linux
#elif __unix__ // all unices not caught above
    // Unix
#elif defined(_POSIX_VERSION)
    // POSIX
#else
#   error "Unknown compiler"
#endif

#define WITH_DEBUG
#ifdef WITH_DEBUG
# define DEBUGF(a...)	do { \
	fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
	fprintf(stderr, a); \
	fflush(stderr); \
} while (0)
#else
# define DEBUGF(a...)	do { } while (0)
#endif

#define ERREXIT(a...)	do { \
	fprintf(stderr, "%s():%d ", __func__, __LINE__); \
	fprintf(stderr, a); \
	exit(-1); \
} while (0)

#define XFREE(ptr) do { \
	if (ptr) \
		free(ptr); \
	ptr = NULL; \
} while (0)

#ifndef ntohll
# define ntohll(xip) (((uint64_t)(ntohl((uint32_t)((xip << 32) >> 32))) << 32) | (uint32_t)ntohl(((uint32_t)(xip >> 32))))
#endif

#endif /* COMMON_H_ */
