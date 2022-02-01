/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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

#ifndef MY_UBUF_H
#define MY_UBUF_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vector.h"

VECTOR_GENERATE(ubuf, uint8_t)

static inline ubuf *
ubuf_new(void)
{
	return (ubuf_init(64));
}

static inline ubuf *
ubuf_dup_cstr(const char *s)
{
	size_t len = strlen(s);
	ubuf *u = ubuf_init(len + 1);
	ubuf_append(u, (const uint8_t *) s, len);
	return (u);
}

static inline void
ubuf_add_cstr(ubuf *u, const char *s)
{
	if (ubuf_size(u) > 0 && ubuf_value(u, ubuf_size(u) - 1) == '\x00')
		ubuf_clip(u, ubuf_size(u) - 1);
	ubuf_append(u, (const uint8_t *) s, strlen(s));
}

static inline void
ubuf_cterm(ubuf *u)
{
	if (ubuf_size(u) == 0 ||
	    (ubuf_size(u) > 0 && ubuf_value(u, ubuf_size(u) - 1) != '\x00'))
	{
		ubuf_append(u, (const uint8_t *) "\x00", 1);
	}
}

static inline char *
ubuf_cstr(ubuf *u)
{
	ubuf_cterm(u);
	return ((char *) ubuf_data(u));
}

static inline void
ubuf_add_fmt(ubuf *u, const char *fmt, ...)
{
	va_list args, args_copy;
	int status, needed;

	if (ubuf_size(u) > 0 && ubuf_value(u, ubuf_size(u) - 1) == '\x00')
		ubuf_clip(u, ubuf_size(u) - 1);

	va_start(args, fmt);

	va_copy(args_copy, args);
	needed = vsnprintf(NULL, 0, fmt, args_copy);
	assert(needed >= 0);
	va_end(args_copy);

	ubuf_reserve(u, ubuf_size(u) + needed + 1);
	status = vsnprintf((char *) ubuf_ptr(u), needed + 1, fmt, args);
	assert(status >= 0);
	ubuf_advance(u, needed);

	va_end(args);
}

static inline void
ubuf_rstrip(ubuf *u, char s)
{
	if (ubuf_size(u) > 0 &&
	    ubuf_value(u, ubuf_size(u) - 1) == ((uint8_t) s))
	{
		ubuf_clip(u, ubuf_size(u) - 1);
	}
}

#endif /* MY_UBUF_H */
