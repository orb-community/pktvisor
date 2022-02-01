#ifndef MY_ALLOC_H
#define MY_ALLOC_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static inline void *
my_calloc(size_t nmemb, size_t size)
{
	void *ptr = calloc(nmemb, size);
	assert(ptr != NULL);
	return (ptr);
}

static inline void *
my_malloc(size_t size)
{
	void *ptr = malloc(size);
	assert(ptr != NULL);
	return (ptr);
}

static inline void *
my_realloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	assert(ptr != NULL);
	return (ptr);
}

static inline char *
my_strdup(const char *s)
{
	char *ptr = strdup(s);
	assert(ptr != NULL);
	return (ptr);
}

#define my_free(ptr) do { free(ptr); (ptr) = NULL; } while (0)

#if defined(MY_ALLOC_WARN_DEPRECATED)

static inline void *my_calloc_deprecated(size_t, size_t)
	__attribute__ ((deprecated("use my_calloc, not calloc")));

static inline void *my_malloc_deprecated(size_t)
	__attribute__ ((deprecated("use my_malloc, not malloc")));

static inline void *my_realloc_deprecated(void *, size_t)
	__attribute__ ((deprecated("use my_realloc, not realloc")));

static inline void *
my_calloc_deprecated(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

static inline void *
my_malloc_deprecated(size_t size)
{
	return malloc(size);
}

static inline void *
my_realloc_deprecated(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

#define calloc	my_calloc_deprecated
#define malloc	my_malloc_deprecated
#define realloc	my_realloc_deprecated

#endif /* MY_ALLOC_WARN_DEPRECATED */

#endif /* MY_ALLOC_H */
