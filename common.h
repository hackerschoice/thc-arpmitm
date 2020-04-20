#ifndef COMMON_H_
#define COMMON_H_

#include <stdint.h>

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

//#define int_ntoa(xip)	inet_ntoa(*((struct in_addr *)&(xip)))
#define ntohll(xip) (((uint64_t)(ntohl((uint32_t)((xip << 32) >> 32))) << 32) | (uint32_t)ntohl(((uint32_t)(xip >> 32))))

#endif /* COMMON_H_ */
