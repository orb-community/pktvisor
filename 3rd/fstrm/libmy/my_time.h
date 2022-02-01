#ifndef MY_TIME_H
#define MY_TIME_H

#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#if HAVE_CLOCK_GETTIME
static inline void
my_gettime(clockid_t clk_id, struct timespec *ts)
{
	int res;
	res = clock_gettime(clk_id, ts);
	assert(res == 0);
}
#else
static inline void
my_gettime(int clk_id __attribute__((unused)), struct timespec *ts)
{
	struct timeval tv;
	int res;

	res = gettimeofday(&tv, NULL);
	assert(res == 0);

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
}
#endif

static inline void
my_timespec_add(const struct timespec *a, struct timespec *b) {
	b->tv_sec += a->tv_sec;
	b->tv_nsec += a->tv_nsec;
	while (b->tv_nsec >= 1000000000) {
		b->tv_sec += 1;
		b->tv_nsec -= 1000000000;
	}
}

static inline void
my_timespec_sub(const struct timespec *a, struct timespec *b)
{
	b->tv_sec -= a->tv_sec;
	b->tv_nsec -= a->tv_nsec;
	if (b->tv_nsec < 0) {
		b->tv_sec -= 1;
		b->tv_nsec += 1000000000;
	}
}

static inline double
my_timespec_to_double(const struct timespec *ts)
{
	return (ts->tv_sec + ts->tv_nsec / 1E9);
}

static inline void
my_timespec_from_double(double seconds, struct timespec *ts) {
	ts->tv_sec = (time_t) seconds;
	ts->tv_nsec = (long) ((seconds - ((int) seconds)) * 1E9);
}

static inline void
my_nanosleep(const struct timespec *ts)
{
	struct timespec rqt, rmt;

	for (rqt = *ts; nanosleep(&rqt, &rmt) < 0 && errno == EINTR; rqt = rmt)
		;
}

#endif /* MY_TIME_H */
