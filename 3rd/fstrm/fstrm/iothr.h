/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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

#ifndef FSTRM_IOTHR_H
#define FSTRM_IOTHR_H

/**
 * \defgroup fstrm_iothr fstrm_iothr
 *
 * The `fstrm_iothr` interface creates a background I/O thread which writes
 * Frame Streams encapsulated data frames into an output stream specified by an
 * \ref fstrm_writer object. It exposes non-blocking input queues that can be
 * used by worker threads to asynchronously write data frames to the output
 * stream. A deferred deallocation callback is invoked after the I/O thread has
 * disposed of a queued data frame.
 *
 * In order to create an `fstrm_iothr` object, the caller must first configure
 * and instantiate an `fstrm_writer` object and pass this instance to the
 * fstrm_iothr_init() function. The `fstrm_iothr` object then takes ownership of
 * the `fstrm_writer` object. It is responsible for serializing writes and will
 * take care of destroying the captive `fstrm_writer` object at the same time
 * the `fstrm_iothr` object is destroyed. The caller should not perform any
 * operations on the captive `fstrm_writer` object after it has been passed to
 * `fstrm_iothr_init()`.
 *
 * Parameters used to configure the I/O thread are passed through an
 * `fstrm_iothr_options` object. These options have to be specified in advance
 * and are mostly performance knobs which have reasonable defaults.
 *
 * Once the `fstrm_iothr` object has been created, handles to the input queues
 * used to submit data frames can be obtained by calling
 * `fstrm_iothr_get_input_queue()`. This function can be called up to
 * **num_input_queues** times, and can be safely called concurrently. For
 * instance, in an application with a fixed number of worker threads, an input
 * queue can be dedicated to each worker thread by setting the
 * **num_input_queues** option to the number of worker threads, and then calling
 * `fstrm_iothr_get_input_queue()` from each worker thread's startup function to
 * obtain a per-thread input queue.
 *
 * @{
 */

/**
 * Initialize an `fstrm_iothr_options` object. This is needed to pass
 * configuration parameters to fstrm_iothr_init().
 *
 * \return
 *	`fstrm_iothr_options` object.
 */
struct fstrm_iothr_options *
fstrm_iothr_options_init(void);

/**
 * Destroy an `fstrm_iothr_options` object.
 *
 * \param opt
 *	Pointer to `fstrm_iothr_options` object.
 */
void
fstrm_iothr_options_destroy(struct fstrm_iothr_options **opt);

/**
 * Set the `buffer_hint` parameter. This is the threshold number of bytes to
 * accumulate in the output buffer before forcing a buffer flush.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param buffer_hint
 *	New `buffer_hint` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_buffer_hint(
	struct fstrm_iothr_options *opt,
	unsigned buffer_hint);

/** Minimum `buffer_hint` value. */
#define FSTRM_IOTHR_BUFFER_HINT_MIN			1024

/** Default `buffer_hint` value. */
#define FSTRM_IOTHR_BUFFER_HINT_DEFAULT			8192

/** Maximum `buffer_hint` value. */
#define FSTRM_IOTHR_BUFFER_HINT_MAX			65536

/**
 * Set the `flush_timeout` parameter. This is the number of seconds to allow
 * unflushed data to remain in the output buffer.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param flush_timeout
 *	New `flush_timeout` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_flush_timeout(
	struct fstrm_iothr_options *opt,
	unsigned flush_timeout);

/** Minimum `flush_timeout` value. */
#define FSTRM_IOTHR_FLUSH_TIMEOUT_MIN			1

/** Default `flush_timeout` value. */
#define FSTRM_IOTHR_FLUSH_TIMEOUT_DEFAULT		1

/** Maximum `flush_timeout` value. */
#define FSTRM_IOTHR_FLUSH_TIMEOUT_MAX			600

/**
 * Set the `input_queue_size` parameter. This is the number of queue entries to
 * allocate per each input queue. This option controls the number of outstanding
 * data frames per input queue that can be outstanding for deferred processing
 * by the `fstrm_iothr` object and thus affects performance and memory usage.
 *
 * This parameter must be a power-of-2.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param input_queue_size
 *	New `input_queue_size` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_input_queue_size(
	struct fstrm_iothr_options *opt,
	unsigned input_queue_size);

/** Minimum `input_queue_size` value. */
#define FSTRM_IOTHR_INPUT_QUEUE_SIZE_MIN		2

/** Default `input_queue_size` value. */
#define FSTRM_IOTHR_INPUT_QUEUE_SIZE_DEFAULT		512

/** Maximum `input_queue_size` value. */
#define FSTRM_IOTHR_INPUT_QUEUE_SIZE_MAX		16384

/**
 * Set the `num_input_queues` parameter. This is the number of input queues to
 * create and must match the number of times that fstrm_iothr_get_input_queue()
 * is called on the corresponding `fstrm_iothr` object.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param num_input_queues
 *	New `num_input_queues` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_num_input_queues(
	struct fstrm_iothr_options *opt,
	unsigned num_input_queues);

/** Minimum `num_input_queues` value. */
#define FSTRM_IOTHR_NUM_INPUT_QUEUES_MIN		1

/** Default `num_input_queues` value. */
#define FSTRM_IOTHR_NUM_INPUT_QUEUES_DEFAULT		1

/**
 * Set the `output_queue_size` parameter. This is the number of queue entries to
 * allocate for the output queue. This option controls the maximum number of
 * data frames that can be accumulated in the output queue before a buffer flush
 * must occur and thus affects performance and memory usage.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param output_queue_size
 *	New `output_queue_size` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_output_queue_size(
	struct fstrm_iothr_options *opt,
	unsigned output_queue_size);

/** Minimum `output_queue_size` value. */
#define FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_MIN		2

/** Default `output_queue_size` value. */
#define FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_DEFAULT		64

/** Maximum `output_queue_size` value. */
#define FSTRM_IOTHR_OUTPUT_QUEUE_SIZE_MAX		IOV_MAX

/**
 * Queue models.
 * \see fstrm_iothr_options_set_queue_model()
 */
typedef enum {
	/** Single Producer, Single Consumer. */
	FSTRM_IOTHR_QUEUE_MODEL_SPSC,

	/** Multiple Producer, Single Consumer. */
	FSTRM_IOTHR_QUEUE_MODEL_MPSC,
} fstrm_iothr_queue_model;


/**
 * Set the `queue_model` parameter. This controls what queueing semantics to use
 * for `fstrm_iothr_queue` objects. Single Producer queues
 * (#FSTRM_IOTHR_QUEUE_MODEL_SPSC) may only have a single thread at a time
 * calling fstrm_iothr_submit() on a given `fstrm_iothr_queue` object, while
 * Multiple Producer queues (#FSTRM_IOTHR_QUEUE_MODEL_MPSC) may have multiple
 * threads concurrently calling fstrm_iothr_submit() on a given
 * `fstrm_iothr_queue` object.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param queue_model
 *	New `queue_model` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_queue_model(
	struct fstrm_iothr_options *opt,
	fstrm_iothr_queue_model queue_model);

/** Default `queue_model` value. */
#define FSTRM_IOTHR_QUEUE_MODEL_DEFAULT			FSTRM_IOTHR_QUEUE_MODEL_SPSC

/**
 * Set the `queue_notify_threshold` parameter. This controls the number of
 * outstanding queue entries to allow on an input queue before waking the I/O
 * thread, which will cause the outstanding queue entries to begin draining.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param queue_notify_threshold
 *	New `queue_notify_threshold` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_queue_notify_threshold(
	struct fstrm_iothr_options *opt,
	unsigned queue_notify_threshold);

/** Minimum `queue_notify_threshold` value. */
#define FSTRM_IOTHR_QUEUE_NOTIFY_THRESHOLD_MIN		1

/** Default `queue_notify_threshold` value. */
#define FSTRM_IOTHR_QUEUE_NOTIFY_THRESHOLD_DEFAULT	32

/**
 * Set the `reopen_interval` parameter. This controls the number of seconds to
 * wait between attempts to reopen a closed `fstrm_writer` output stream.
 *
 * \param opt
 *	`fstrm_iothr_options` object.
 * \param reopen_interval
 *	New `queue_notify_threshold` value.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_iothr_options_set_reopen_interval(
	struct fstrm_iothr_options *opt,
	unsigned reopen_interval);

/** Minimum `reopen_interval` value. */
#define FSTRM_IOTHR_REOPEN_INTERVAL_MIN			1

/** Default `reopen_interval` value. */
#define FSTRM_IOTHR_REOPEN_INTERVAL_DEFAULT		5

/** Maximum `reopen_interval` value. */
#define FSTRM_IOTHR_REOPEN_INTERVAL_MAX			600

/**
 * Initialize an `fstrm_iothr` object. This creates a background I/O thread
 * which asynchronously writes data frames submitted by other threads which call
 * fstrm_iothr_submit().
 *
 * \param opt
 *	`fstrm_iothr_options` object. May be NULL, in which case default values
 *	will be used.
 *
 * \param writer
 *	Pointer to `fstrm_writer` object. Must be non-NULL.
 *
 * \return
 *	`fstrm_iothr` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_iothr *
fstrm_iothr_init(
	const struct fstrm_iothr_options *opt,
	struct fstrm_writer **writer);

/**
 * Destroy an `fstrm_iothr` object. This signals the background I/O thread to
 * flush or discard any queued data frames and deallocates any resources used
 * internally. This function blocks until the I/O thread has terminated.
 *
 * \param iothr
 *	Pointer to `fstrm_iothr` object.
 */
void
fstrm_iothr_destroy(struct fstrm_iothr **iothr);

/**
 * Obtain an `fstrm_iothr_queue` object for submitting data frames to the
 * `fstrm_iothr` object. `fstrm_iothr_queue` objects are child objects of their
 * parent `fstrm_iothr` object and will be destroyed when fstrm_iothr_destroy()
 * is called on the parent `fstrm_iothr` object.
 *
 * This function is thread-safe and may be called simultaneously from any
 * thread. For example, in a program which employs a fixed number of worker
 * threads to handle requests, fstrm_iothr_get_input_queue() may be called from
 * a thread startup routine without synchronization.
 *
 * `fstrm_iothr` objects allocate a fixed total number of `fstrm_iothr_queue`
 * objects during the call to fstrm_iothr_init(). To adjust this parameter, use
 * fstrm_iothr_options_set_num_input_queues().
 *
 * This function will fail if it is called more than **num_input_queues** times.
 * By default, only one input queue is initialized per `fstrm_iothr` object.
 *
 * For optimum performance in a threaded program, each worker thread submitting
 * data frames should have a dedicated `fstrm_iothr_queue` object. This allows
 * each worker thread to have its own queue which is processed independently by
 * the I/O thread. If the queue model for the `fstrm_iothr` object is set to
 * #FSTRM_IOTHR_QUEUE_MODEL_SPSC, this results in contention-free access to the
 * input queue.
 *
 * \param iothr
 *	`fstrm_iothr` object.
 *
 * \return
 *	`fstrm_iothr_queue` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_iothr_queue *
fstrm_iothr_get_input_queue(struct fstrm_iothr *iothr);

/**
 * Obtain an `fstrm_iothr_queue` object for submitting data frames to the
 * `fstrm_iothr` object. This function is like fstrm_iothr_get_input_queue()
 * except it indexes into the `fstrm_iothr_queue`'s array of input queues.
 *
 * \param iothr
 *	`fstrm_iothr` object.
 * \param idx
 *	Index of the `fstrm_iothr_queue` object to retrieve. This value is
 *	limited by the **num_input_queues** option.
 *
 * \return
 *	`fstrm_iothr_queue` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_iothr_queue *
fstrm_iothr_get_input_queue_idx(struct fstrm_iothr *iothr, size_t idx);

/**
 * Submit a data frame to the background I/O thread. If successfully queued and
 * the I/O thread has an active output stream opened, the data frame will be
 * asynchronously written to the output stream.
 *
 * When this function returns #fstrm_res_success, responsibility for
 * deallocating the data frame specified by the `data` parameter passes to the
 * `fstrm` library. The caller **MUST** ensure that the `data` object remains
 * valid after fstrm_iothr_submit() returns. The callback function specified by
 * the `free_func` parameter will be invoked once the data frame is no longer
 * needed by the `fstrm` library. For example, if the data frame is dynamically
 * allocated, the data frame may be deallocated in the callback function.
 *
 * Note that if this function returns #fstrm_res_failure, the responsibility for
 * deallocating the data frame remains with the caller.
 *
 * As a convenience, if `data` is allocated with the system's `malloc()`,
 * `fstrm_free_wrapper` may be provided as the `free_func` parameter with the
 * `free_data` parameter set to `NULL`. This will cause the system's `free()` to
 * be invoked to deallocate `data`.
 *
 * `free_func` may be NULL, in which case no callback function will be invoked
 * to dispose of `buf`. This behavior may be useful if `data` is a global,
 * statically allocated object.
 *
 * \param iothr
 *      `fstrm_iothr` object.
 * \param ioq
 *      `fstrm_iothr_queue` object.
 * \param data
 *      Data frame bytes.
 * \param len
 *      Number of bytes in `data`.
 * \param free_func
 *      Callback function to deallocate the data frame. The `data` and
 *      `free_data` parameters passed to this callback will be the same values
 *      originally supplied in the call to fstrm_iothr_submit().
 * \param free_data
 *      Parameter to pass to `free_func`.
 *
 * \retval #fstrm_res_success
 *      The data frame was successfully queued.
 * \retval #fstrm_res_again
 *      The queue is full.
 * \retval #fstrm_res_failure
 *      Permanent failure.
 */
fstrm_res
fstrm_iothr_submit(
	struct fstrm_iothr *iothr, struct fstrm_iothr_queue *ioq,
	void *data, size_t len,
	void (*free_func)(void *buf, void *free_data), void *free_data);

/**
 * Wrapper function for the system's `free()`, suitable for use as the
 * `free_func` callback for fstrm_iothr_submit().
 *
 * \param data
 *	Object to call `free()` on.
 * \param free_data
 *	Unused.
 */
void
fstrm_free_wrapper(void *data, void *free_data);

/**@}*/

#endif /* FSTRM_IOTHR_H */
