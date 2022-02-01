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

#ifndef MY_PRINT_STRING_H
#define MY_PRINT_STRING_H

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>

static inline void
print_string(const void *data, size_t len, FILE *out)
{
	uint8_t *str = (uint8_t *) data;
	fputc('"', out);
	while (len-- != 0) {
		unsigned c = *(str++);
		if (isprint(c)) {
			if (c == '"')
				fputs("\\\"", out);
			else
				fputc(c, out);
		} else {
			fprintf(out, "\\x%02x", c);
		}
	}
	fputc('"', out);
}

#endif /* MY_PRINT_STRING_H */
