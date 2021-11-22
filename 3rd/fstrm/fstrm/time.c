/*
 * Copyright (c) 2013-2014, 2016-2017 by Farsight Security, Inc.
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

#include "fstrm-private.h"

#if HAVE_CLOCK_GETTIME

#if HAVE_PTHREAD_CONDATTR_SETCLOCK
bool
fstrm__get_best_monotonic_clock_pthread(clockid_t *c)
{
	bool res = false;
	int rc;
	struct timespec ts;
	pthread_condattr_t ca;

	rc = pthread_condattr_init(&ca);
	assert(rc == 0);

#if defined(CLOCK_MONOTONIC_COARSE)
	*c = CLOCK_MONOTONIC_COARSE;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

#if defined(CLOCK_MONOTONIC_RAW)
	*c = CLOCK_MONOTONIC_RAW;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

#if defined(CLOCK_MONOTONIC_FAST)
	*c = CLOCK_MONOTONIC_FAST;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

#if defined(CLOCK_MONOTONIC)
	*c = CLOCK_MONOTONIC;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

out:
	rc = pthread_condattr_destroy(&ca);
	assert(rc == 0);
	return res;
}
#endif /* HAVE_PTHREAD_CONDATTR_SETCLOCK */

bool
fstrm__get_best_monotonic_clock_gettime(clockid_t *c)
{
	struct timespec ts;

#if defined(CLOCK_MONOTONIC_COARSE)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC_COARSE, &ts))
		return true;
#endif

#if defined(CLOCK_MONOTONIC_RAW)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC_RAW, &ts))
		return true;
#endif

#if defined(CLOCK_MONOTONIC_FAST)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC_FAST, &ts))
		return true;
#endif

#if defined(CLOCK_MONOTONIC)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC, &ts))
		return true;
#endif

	return false;
}

bool
fstrm__get_best_monotonic_clocks(clockid_t *clkid_gettime,
				 clockid_t *clkid_pthread,
				 char **err)
{
	if (clkid_gettime != NULL && 
	    !fstrm__get_best_monotonic_clock_gettime(clkid_gettime))
	{
		if (err != NULL)
			*err = my_strdup("no clock available for clock_gettime()");
		return false;
	}

#if HAVE_PTHREAD_CONDATTR_SETCLOCK
	if (clkid_pthread != NULL &&
	    !fstrm__get_best_monotonic_clock_pthread(clkid_pthread))
	{
		if (err != NULL)
			*err = my_strdup("no clock available for pthread_cond_timedwait()");
		return false;
	}
#endif

	return true;
}

#endif /* HAVE_CLOCK_GETTIME */
