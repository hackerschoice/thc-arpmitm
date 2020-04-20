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

#define ntohll(xip) (((uint64_t)(ntohl((uint32_t)((xip << 32) >> 32))) << 32) | (uint32_t)ntohl(((uint32_t)(xip >> 32))))

#endif /* COMMON_H_ */
