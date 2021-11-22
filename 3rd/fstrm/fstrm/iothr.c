/*
 * Copyright (c) 2013, 2014, 2016-2017 by Farsight Security, Inc.
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

static void *fstrm__iothr_thr(void *);

struct fstrm_iothr_options {
	unsigned			buffer_hint;
	unsigned			flush_timeout;
	unsigned			input_queue_size;
	unsigned			num_input_queues;
	unsigned			output_queue_size;
	unsigned			queue_notify_threshold;
	unsigned			reopen_interval;
	fstrm_iothr_queue_model		queue_model;
};

static const struct fstrm_iothr_options default_fstrm_iothr_options = {
	.buffer_hint			= FSTRM_IOTHR_BUFFER_HINT_DEFAULT,
	.flush_timeout			= FSTRM_IOTHR_FLUSH_TIMEOUT_DEFAULT,
	.input_queue_size		= FSTRM_IOTHR_INPUT_QUEUE_SIZE_DEFAULT,
	.num_input_queues		= FSTRM_IOTHR_NUM_INPUT_QUEUES_DEFAULT,
	.output_queue_size		= FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_DEFAULT,
	.queue_model			= FSTRM_IOTHR_QUEUE_MODEL_DEFAULT,
	.queue_notify_threshold		= FSTRM_IOTHR_QUEUE_NOTIFY_THRESHOLD_DEFAULT,
	.reopen_interval		= FSTRM_IOTHR_REOPEN_INTERVAL_DEFAULT,
};

struct fstrm_iothr_queue {
	struct my_queue			*q;
};

struct fstrm__iothr_queue_entry {
	/* The deallocation callback. */
	void				(*free_func)(void *, void *);
	void				*free_data;

	/* The actual payload bytes, allocated by the caller. */
	void				*data;

	/* Number of bytes in 'data'. */
	uint32_t			len_data;
};

struct fstrm_iothr {
	/* The I/O thread. */
	pthread_t			thr;

	/* Copy of options. supplied by caller. */
	struct fstrm_iothr_options	opt;

	/* Queue implementation. */
	const struct my_queue_ops	*queue_ops;

	/* Writer. */
	struct fstrm_writer		*writer;

	/* Whether the writer is opened or not. */
	bool				opened;

	/* Last time the writer's 'open' method was called. */
	time_t				last_open_attempt;

	/* Allocated array of input queues, size opt.num_input_queues. */
	struct fstrm_iothr_queue	*queues;

	/* Whether the I/O thread is shutting down. */
	volatile bool			shutting_down;

#if HAVE_CLOCK_GETTIME
	/* Optimal clockid_t's. */
	clockid_t			clkid_gettime;
	clockid_t			clkid_pthread;
#endif

	/*
	 * Conditional variable and lock, used by producer thread
	 * (fstrm_iothr_submit) to signal sleeping I/O thread that the low
	 * watermark (opt.queue_notify_threshold) has been reached.
	 */
	pthread_cond_t			cv;
	pthread_mutex_t			cv_lock;

	/* Used to return unique queues from fstrm_iothr_get_queue(). */
	pthread_mutex_t			get_queue_lock;
	unsigned			get_queue_idx;

	/* Output queue. */
	unsigned			outq_idx;
	struct iovec			*outq_iov;
	struct fstrm__iothr_queue_entry	*outq_entries;
	unsigned			outq_nbytes;
};

struct fstrm_iothr_options *
fstrm_iothr_options_init(void)
{
	struct fstrm_iothr_options *opt;
	opt = my_malloc(sizeof(*opt));
	memmove(opt, &default_fstrm_iothr_options, sizeof(*opt));
	return opt;
}

void
fstrm_iothr_options_destroy(struct fstrm_iothr_options **opt)
{
	if (*opt != NULL)
		my_free(*opt);
}

fstrm_res
fstrm_iothr_options_set_buffer_hint(struct fstrm_iothr_options *opt,
				    unsigned buffer_hint)
{
	if (buffer_hint < FSTRM_IOTHR_BUFFER_HINT_MIN ||
	    buffer_hint > FSTRM_IOTHR_BUFFER_HINT_MAX)
	{
		return fstrm_res_failure;
	}
	opt->buffer_hint = buffer_hint;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_flush_timeout(struct fstrm_iothr_options *opt,
				      unsigned flush_timeout)
{
	if (flush_timeout < FSTRM_IOTHR_FLUSH_TIMEOUT_MIN ||
	    flush_timeout > FSTRM_IOTHR_FLUSH_TIMEOUT_MAX)
	{
		return fstrm_res_failure;
	}
	opt->flush_timeout = flush_timeout;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_input_queue_size(struct fstrm_iothr_options *opt,
					 unsigned input_queue_size)
{
	if (input_queue_size < FSTRM_IOTHR_INPUT_QUEUE_SIZE_MIN ||
	    input_queue_size > FSTRM_IOTHR_INPUT_QUEUE_SIZE_MAX ||
	    input_queue_size & 1)
	{
		return fstrm_res_failure;
	}
	opt->input_queue_size = input_queue_size;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_num_input_queues(struct fstrm_iothr_options *opt,
					 unsigned num_input_queues)
{
	if (num_input_queues < FSTRM_IOTHR_NUM_INPUT_QUEUES_MIN)
		return fstrm_res_failure;
	opt->num_input_queues = num_input_queues;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_output_queue_size(struct fstrm_iothr_options *opt,
					  unsigned output_queue_size)
{
	if (output_queue_size < FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_MIN ||
	    output_queue_size > FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_MAX)
	{
		return fstrm_res_failure;
	}
	opt->output_queue_size = output_queue_size;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_queue_model(struct fstrm_iothr_options *opt,
				    fstrm_iothr_queue_model queue_model)
{
	if (queue_model != FSTRM_IOTHR_QUEUE_MODEL_SPSC &&
	    queue_model != FSTRM_IOTHR_QUEUE_MODEL_MPSC)
	{
		return fstrm_res_failure;
	}
	opt->queue_model = queue_model;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_queue_notify_threshold(struct fstrm_iothr_options *opt,
					       unsigned queue_notify_threshold)
{
	if (queue_notify_threshold < FSTRM_IOTHR_QUEUE_NOTIFY_THRESHOLD_MIN)
		return fstrm_res_failure;
	opt->queue_notify_threshold = queue_notify_threshold;
	return fstrm_res_success;
}

fstrm_res
fstrm_iothr_options_set_reopen_interval(struct fstrm_iothr_options *opt,
					unsigned reopen_interval)
{
	if (reopen_interval < FSTRM_IOTHR_REOPEN_INTERVAL_MIN ||
	    reopen_interval > FSTRM_IOTHR_REOPEN_INTERVAL_MAX)
	{
		return fstrm_res_failure;
	}
	opt->reopen_interval = reopen_interval;
	return fstrm_res_success;
}

struct fstrm_iothr *
fstrm_iothr_init(const struct fstrm_iothr_options *opt,
		 struct fstrm_writer **writer)
{
	struct fstrm_iothr *iothr = NULL;

	int res;
	pthread_condattr_t ca;

	/* Initialize fstrm_iothr and copy options. */
	iothr = my_calloc(1, sizeof(*iothr));
	if (opt == NULL)
		opt = &default_fstrm_iothr_options;
	memmove(&iothr->opt, opt, sizeof(iothr->opt));

	/*
	 * Some platforms have a ridiculously low IOV_MAX, literally the lowest
	 * value even allowed by POSIX, which is lower than our conservative
	 * FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_DEFAULT. Accommodate these platforms by
	 * silently clamping output_queue_size to IOV_MAX.
	 */
	if (iothr->opt.output_queue_size > IOV_MAX)
		iothr->opt.output_queue_size = IOV_MAX;

	/*
	 * Set the queue implementation.
	 *
	 * The memory barrier based queue implementation is the only one of our
	 * queue implementations that supports SPSC, so if it is not available,
	 * use the mutex based queue implementation instead. The mutex
	 * implementation is technically MPSC, but MPSC is strictly stronger
	 * than SPSC.
	 */
	if (iothr->opt.queue_model == FSTRM_IOTHR_QUEUE_MODEL_SPSC) {
#ifdef MY_HAVE_MEMORY_BARRIERS
		iothr->queue_ops = &my_queue_mb_ops;
#else
		iothr->queue_ops = &my_queue_mutex_ops;
#endif
	} else {
		iothr->queue_ops = &my_queue_mutex_ops;
	}

#if HAVE_CLOCK_GETTIME
	/* Detect best clocks. */
	if (!fstrm__get_best_monotonic_clocks(&iothr->clkid_gettime,
					      &iothr->clkid_pthread,
					      NULL))
	{
		goto fail;
	}
#endif

	/* Initialize the input queues. */
	iothr->queues = my_calloc(iothr->opt.num_input_queues,
				  sizeof(struct fstrm_iothr_queue));
	for (size_t i = 0; i < iothr->opt.num_input_queues; i++) {
		iothr->queues[i].q = iothr->queue_ops->init(iothr->opt.input_queue_size,
			sizeof(struct fstrm__iothr_queue_entry));
		if (iothr->queues[i].q == NULL)
			goto fail;
	}

	/* Initialize the output queue. */
	iothr->outq_iov = my_calloc(iothr->opt.output_queue_size,
				    sizeof(struct iovec));
	iothr->outq_entries = my_calloc(iothr->opt.output_queue_size,
					sizeof(struct fstrm__iothr_queue_entry));

	/* Initialize the condition variable. */
	res = pthread_condattr_init(&ca);
	assert(res == 0);

#if HAVE_CLOCK_GETTIME && HAVE_PTHREAD_CONDATTR_SETCLOCK
	res = pthread_condattr_setclock(&ca, iothr->clkid_pthread);
	assert(res == 0);
#endif

	res = pthread_cond_init(&iothr->cv, &ca);
	assert(res == 0);

	res = pthread_condattr_destroy(&ca);
	assert(res == 0);

	/* Initialize the mutex protecting the condition variable. */
	res = pthread_mutex_init(&iothr->cv_lock, NULL);
	assert(res == 0);

	/* Initialize the mutex protecting fstrm_iothr_get_queue(). */
	res = pthread_mutex_init(&iothr->get_queue_lock, NULL);
	assert(res == 0);

	/* Take the caller's writer. */
	iothr->writer = *writer;
	*writer = NULL;

	/* Start the I/O thread. */
	res = pthread_create(&iothr->thr, NULL, fstrm__iothr_thr, iothr);
	assert(res == 0);

	return iothr;
fail:
	fstrm_iothr_destroy(&iothr);
	return NULL;
}

static inline void
fstrm__iothr_queue_entry_free_bytes(struct fstrm__iothr_queue_entry *entry)
{
	if (entry->free_func != NULL)
		entry->free_func(entry->data, entry->free_data);
}

static void
fstrm__iothr_free_queues(struct fstrm_iothr *iothr)
{
	size_t i;
	for (i = 0; i < iothr->opt.num_input_queues; i++) {
		struct my_queue *queue;
		struct fstrm__iothr_queue_entry entry;

		queue = iothr->queues[i].q;
		while (iothr->queue_ops->remove(queue, &entry, NULL))
			fstrm__iothr_queue_entry_free_bytes(&entry);
		iothr->queue_ops->destroy(&queue);
	}
	my_free(iothr->queues);
}

void
fstrm_iothr_destroy(struct fstrm_iothr **iothr)
{
	if (*iothr != NULL) {
		/*
		 * Signal the I/O thread that a shutdown is in progress.
		 * This waits for the I/O thread to finish.
		 */
		(*iothr)->shutting_down = true;
		pthread_cond_signal(&(*iothr)->cv);
		pthread_join((*iothr)->thr, NULL);
		pthread_cond_destroy(&(*iothr)->cv);
		pthread_mutex_destroy(&(*iothr)->cv_lock);
		pthread_mutex_destroy(&(*iothr)->get_queue_lock);

		/* Destroy the writer by calling its 'destroy' method. */
		(void)fstrm_writer_destroy(&(*iothr)->writer);

		/* Cleanup our allocations. */
		fstrm__iothr_free_queues(*iothr);
		my_free((*iothr)->outq_iov);
		my_free((*iothr)->outq_entries);
		my_free(*iothr);
	}
}

struct fstrm_iothr_queue *
fstrm_iothr_get_input_queue(struct fstrm_iothr *iothr)
{
	struct fstrm_iothr_queue *q = NULL;

	pthread_mutex_lock(&iothr->get_queue_lock);
	if (iothr->get_queue_idx < iothr->opt.num_input_queues) {
		q = &iothr->queues[iothr->get_queue_idx];
		iothr->get_queue_idx++;
	}
	pthread_mutex_unlock(&iothr->get_queue_lock);

	return q;
}

struct fstrm_iothr_queue *
fstrm_iothr_get_input_queue_idx(struct fstrm_iothr *iothr, size_t idx)
{
	struct fstrm_iothr_queue *q = NULL;

	if (idx < iothr->opt.num_input_queues)
		q = &iothr->queues[idx];

	return q;
}

void
fstrm_free_wrapper(void *data,
		   void *free_data __attribute__((__unused__)))
{
	free(data);
}

fstrm_res
fstrm_iothr_submit(struct fstrm_iothr *iothr, struct fstrm_iothr_queue *ioq,
		   void *data, size_t len,
		   void (*free_func)(void *, void *), void *free_data)
{
	unsigned space = 0;
	struct fstrm__iothr_queue_entry entry;

	if (unlikely(iothr->shutting_down))
		return fstrm_res_failure;

	if (unlikely(len < 1 || len >= UINT32_MAX || data == NULL))
		return fstrm_res_invalid;

	entry.data = data;
	entry.len_data = (uint32_t) len;
	entry.free_func = free_func;
	entry.free_data = free_data;

	if (likely(len > 0) && iothr->queue_ops->insert(ioq->q, &entry, &space)) {
		if (space == iothr->opt.queue_notify_threshold)
			pthread_cond_signal(&iothr->cv);
		return fstrm_res_success;
	} else {
		return fstrm_res_again;
	}
}

static void
fstrm__iothr_close(struct fstrm_iothr *iothr)
{
	if (iothr->opened) {
		iothr->opened = false;
		fstrm_writer_close(iothr->writer);
	}
}

static void
fstrm__iothr_flush_output(struct fstrm_iothr *iothr)
{
	fstrm_res res;

	/* Do the actual write. */
	if (likely(iothr->opened && iothr->outq_idx > 0)) {
		res = fstrm_writer_writev(iothr->writer, iothr->outq_iov,
					  iothr->outq_idx);
		if (res != fstrm_res_success)
			fstrm__iothr_close(iothr);
	}

	/* Perform the deferred deallocations. */
	for (unsigned i = 0; i < iothr->outq_idx; i++)
		fstrm__iothr_queue_entry_free_bytes(&iothr->outq_entries[i]);

	/* Zero counters and indices. */
	iothr->outq_idx = 0;
	iothr->outq_nbytes = 0;
}

static void
fstrm__iothr_maybe_flush_output(struct fstrm_iothr *iothr, size_t nbytes)
{
	assert(iothr->outq_idx <= iothr->opt.output_queue_size);
	if (iothr->outq_idx > 0) {
		if (iothr->outq_idx >= iothr->opt.output_queue_size ||
		    iothr->outq_nbytes + nbytes >= iothr->opt.buffer_hint)
		{
			/*
			 * If the output queue is full, or there are more than
			 * 'buffer_hint' bytes of data ready to be sent, flush
			 * the output.
			 */
			fstrm__iothr_flush_output(iothr);
		}
	}
}

static void
fstrm__iothr_process_queue_entry(struct fstrm_iothr *iothr,
				 struct fstrm__iothr_queue_entry *entry)
{
	if (likely(iothr->opened)) {
		size_t nbytes = sizeof(uint32_t) + entry->len_data;

		fstrm__iothr_maybe_flush_output(iothr, nbytes);

		/* Copy the entry to the array of outstanding queue entries. */
		iothr->outq_entries[iothr->outq_idx] = *entry;

		/* Add an iovec for the entry. */
		iothr->outq_iov[iothr->outq_idx].iov_base = (void *)entry->data;
		iothr->outq_iov[iothr->outq_idx].iov_len = (size_t)entry->len_data;

		/* Increment the number of output queue entries. */
		iothr->outq_idx++;

		/* There are now nbytes more data waiting to be sent. */
		iothr->outq_nbytes += nbytes;
	} else {
		/* Writer is closed, just discard the payload. */
		fstrm__iothr_queue_entry_free_bytes(entry);
	}
}

static unsigned
fstrm__iothr_process_queues(struct fstrm_iothr *iothr)
{
	struct fstrm__iothr_queue_entry entry;
	unsigned total = 0;

	/*
	 * Remove input queue entries from each thread's circular queue, and
	 * add them to our output queue.
	 */
	for (unsigned i = 0; i < iothr->opt.num_input_queues; i++) {
		if (iothr->queue_ops->remove(iothr->queues[i].q, &entry, NULL)) {
			fstrm__iothr_process_queue_entry(iothr, &entry);
			total++;
		}
	}

	return total;
}

static fstrm_res
fstrm__iothr_open(struct fstrm_iothr *iothr)
{
	fstrm_res res;

	res = fstrm_writer_open(iothr->writer);
	if (res == fstrm_res_success)
		iothr->opened = true;
	else
		iothr->opened = false;
	return res;
}

static void
fstrm__iothr_maybe_open(struct fstrm_iothr *iothr)
{
	/* If we're already connected, there's nothing to do. */
	if (likely(iothr->opened))
		return;

	time_t since;
	struct timespec ts;

	/* Check if the reopen interval has expired yet. */
#if HAVE_CLOCK_GETTIME
	int rv = clock_gettime(iothr->clkid_gettime, &ts);
	assert(rv == 0);
#else
	my_gettime(-1, &ts);
#endif
	since = ts.tv_sec - iothr->last_open_attempt;
	if (since < (time_t) iothr->opt.reopen_interval)
		return;

	/* Attempt to open the transport. */
	iothr->last_open_attempt = ts.tv_sec;
	if (fstrm__iothr_open(iothr) != fstrm_res_success)
		return;
}

static void
fstrm__iothr_thr_setup(void)
{
	sigset_t set;
	int s;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	s = pthread_sigmask(SIG_BLOCK, &set, NULL);
	assert(s == 0);
}

static void *
fstrm__iothr_thr(void *arg)
{
	struct fstrm_iothr *iothr = (struct fstrm_iothr *)arg;

	fstrm__iothr_thr_setup();
	fstrm__iothr_maybe_open(iothr);

	for (;;) {
		int res;
		unsigned count;

		if (unlikely(iothr->shutting_down)) {
			while (fstrm__iothr_process_queues(iothr));
			fstrm__iothr_flush_output(iothr);
			fstrm__iothr_close(iothr);
			break;
		}

		fstrm__iothr_maybe_open(iothr);

		count = fstrm__iothr_process_queues(iothr);
		if (count != 0)
			continue;

		struct timespec ts;
#if HAVE_CLOCK_GETTIME
#if HAVE_PTHREAD_CONDATTR_SETCLOCK
		int rv = clock_gettime(iothr->clkid_pthread, &ts);
#else
		int rv = clock_gettime(CLOCK_REALTIME, &ts);
#endif
		assert(rv == 0);
#else
		my_gettime(-1, &ts);
#endif
		ts.tv_sec += iothr->opt.flush_timeout;

		pthread_mutex_lock(&iothr->cv_lock);
		res = pthread_cond_timedwait(&iothr->cv, &iothr->cv_lock, &ts);
		pthread_mutex_unlock(&iothr->cv_lock);

		if (res == ETIMEDOUT)
			fstrm__iothr_flush_output(iothr);
	}

	return NULL;
}
