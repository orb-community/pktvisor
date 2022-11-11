/*
 * Copyright (c) 2013-2016 by Farsight Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef FSTRM_PRIVATE_H
#define FSTRM_PRIVATE_H

#include <arpa/inet.h>
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fstrm.h"

#include "libmy/my_alloc.h"
#include "libmy/my_memory_barrier.h"
#include "libmy/my_queue.h"
#include "libmy/my_time.h"
#include "libmy/read_bytes.h"
#include "libmy/vector.h"

#if defined(__GNUC__)
# define likely(x)		__builtin_expect(!!(x), 1)
# define unlikely(x)		__builtin_expect(!!(x), 0)
# define warn_unused_result	__attribute__ ((warn_unused_result))
#else
# define likely(x)
# define unlikely(x)
# define warn_unused_result
#endif

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif

#ifndef IOV_MAX
# define IOV_MAX 1024
#endif

/* fs_buf, fs_bufvec */

typedef struct {
	size_t		len;
	uint8_t		*data;
} fs_buf;

VECTOR_GENERATE(fs_bufvec, fs_buf)

/* buffer helpers */

warn_unused_result
static inline bool
fs_load_be32(const uint8_t **buf, size_t *len, uint32_t *val)
{
	uint32_t be32_val;

	if (*len < sizeof(be32_val))
		return false;
	memmove(&be32_val, *buf, sizeof(be32_val));
	*val = ntohl(be32_val);
	*len -= sizeof(be32_val);
	*buf += sizeof(be32_val);
	return true;
}

warn_unused_result
static inline bool
fs_store_be32(uint8_t **buf, size_t *len, const uint32_t val)
{
	uint32_t be32_val;

	be32_val = ntohl(val);
	if (*len < sizeof(be32_val))
		return false;
	memmove(*buf, &be32_val, sizeof(be32_val));
	*len -= sizeof(be32_val);
	*buf += sizeof(be32_val);
	return true;
}

warn_unused_result
static inline bool
fs_load_bytes(uint8_t *bytes, size_t len_bytes,
	      const uint8_t **buf, size_t *len)
{
	if (*len < len_bytes)
		return false;
	memmove(bytes, *buf, len_bytes);
	*len -= len_bytes;
	*buf += len_bytes;
	return true;
}

warn_unused_result
static inline bool
fs_store_bytes(uint8_t **buf, size_t *len,
	       const uint8_t *bytes, size_t len_bytes)
{
	if (*len < len_bytes)
		return false;
	memmove(*buf, bytes, len_bytes);
	*len -= len_bytes;
	*buf += len_bytes;
	return true;
}

/* rdwr */

struct fstrm_rdwr_ops {
	fstrm_rdwr_destroy_func		destroy;
	fstrm_rdwr_open_func		open;
	fstrm_rdwr_close_func		close;
	fstrm_rdwr_read_func		read;
	fstrm_rdwr_write_func		write;
};

struct fstrm_rdwr {
	struct fstrm_rdwr_ops		ops;
	void				*obj;
	bool				opened;
};

fstrm_res
fstrm__rdwr_read_control_frame(struct fstrm_rdwr *,
			       struct fstrm_control *,
			       fstrm_control_type *,
			       const bool with_escape);

fstrm_res
fstrm__rdwr_read_control(struct fstrm_rdwr *,
			 struct fstrm_control **,
			 fstrm_control_type wanted_type);

fstrm_res
fstrm__rdwr_write_control_frame(struct fstrm_rdwr *,
				const struct fstrm_control *);

fstrm_res
fstrm__rdwr_write_control(struct fstrm_rdwr *,
			  fstrm_control_type type,
			  const fs_buf *content_type);

/* time */

#if HAVE_CLOCK_GETTIME
bool fstrm__get_best_monotonic_clock_gettime(clockid_t *);

bool fstrm__get_best_monotonic_clock_pthread(clockid_t *);

bool fstrm__get_best_monotonic_clocks(clockid_t *clkid_gettime,
				      clockid_t *clkid_pthread,
				      char **errstr_out);
#endif

/* queue */

#ifdef MY_HAVE_MEMORY_BARRIERS
extern const struct my_queue_ops my_queue_mb_ops;
#endif

extern const struct my_queue_ops my_queue_mutex_ops;

#endif /* FSTRM_PRIVATE_H */
