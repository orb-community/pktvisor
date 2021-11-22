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

#ifndef FSTRM_READER_H
#define FSTRM_READER_H

/**
 * \defgroup fstrm_reader fstrm_reader
 *
 * `fstrm_reader` is an interface for reading Frame Streams data from a byte
 * stream. The underlying byte stream I/O operations are abstracted by the
 * \ref fstrm_rdwr interface. Thus, the `fstrm_reader` interface can be used to
 * read Frame Streams data from any source whose read/write operations are
 * wrapped by an `fstrm_rdwr` object.
 *
 * Some basic `fstrm_reader` implementations are already provided in the `fstrm`
 * library. See fstrm_file_reader_init() to create an `fstrm_reader` object that
 * reads Frame Streams data from a regular file.
 *
 * @{
 */

/**
 * The default `max_frame_size` value.
 */
#define FSTRM_READER_MAX_FRAME_SIZE_DEFAULT	1048576

/**
 * Initialize an `fstrm_reader_options` object.
 *
 * \return
 *	`fstrm_reader_options` object.
 */
struct fstrm_reader_options *
fstrm_reader_options_init(void);

/**
 * Destroy an `fstrm_reader_options` object.
 *
 * \param ropt
 *	Pointer to `fstrm_reader_options` object.
 */
void
fstrm_reader_options_destroy(
	struct fstrm_reader_options **ropt);

/**
 * Add a "Content Type" value to the set of content types accepted by the
 * `fstrm_reader`. This function makes a copy of the provided string. This
 * function may be called multiple times, in which case multiple "Content Type"
 * values will be accepted by the reader.
 *
 * If the reader has no content types set, it will accept any content type.
 *
 * \param ropt
 *	`fstrm_reader_options` object.
 * \param content_type
 *	The "Content Type" string to copy. Note that this string is not
 *	NUL-terminated and may contain embedded NULs.
 * \param len_content_type
 *	The number of bytes in `content_type`.
 *
 * \retval #fstrm_res_success
 *	The "Content Type" field was successfully added.
 * \retval #fstrm_res_failure
 *	The "Content Type" string is too long.
 */
fstrm_res
fstrm_reader_options_add_content_type(
	struct fstrm_reader_options *ropt,
	const void *content_type,
	size_t len_content_type);

/**
 * Set the maximum frame size that the reader is willing to accept. This
 * enforces an upper limit on the amount of memory used to buffer incoming data
 * from the reader's byte stream.
 *
 * If this option is not set, it defaults to
 * #FSTRM_READER_MAX_FRAME_SIZE_DEFAULT.
 *
 * \param ropt
 *	`fstrm_reader_options` object.
 * \param max_frame_size
 *	The maximum frame size value.
 *
 * \retval #fstrm_res_success
 *	The `max_frame_size` value was successfully set.
 * \retval #fstrm_res_failure
 *	The `max_frame_size` value was too large or too small.
 */
fstrm_res
fstrm_reader_options_set_max_frame_size(
	struct fstrm_reader_options *ropt,
	size_t max_frame_size);

/**
 * Initialize a new `fstrm_reader` object based on an underlying `fstrm_rdwr`
 * object and an `fstrm_reader_options` object.
 *
 * The underlying `fstrm_rdwr` object MUST have a `read` method. It MAY
 * optionally have a `write` method, in which case the stream will be treated as
 * a bi-directional, handshaked stream. Otherwise, if there is no `write` method
 * the stream will be treated as a uni-directional stream.
 *
 * This function is useful for implementing functions that return new types of
 * `fstrm_reader` objects, such as fstrm_file_reader_init().
 *
 * After a successful call to this function, the ownership of the `fstrm_rdwr`
 * object passes from the caller to the `fstrm_reader` object. The caller
 * should perform no further calls on the `fstrm_rdwr` object. The `fstrm_rdwr`
 * object will be cleaned up on a call to fstrm_reader_destroy().
 *
 * \param ropt
 *	`fstrm_reader_options` object. May be NULL, in which case default values
 *	will be used.
 *
 * \param rdwr
 *	Pointer to `fstrm_rdwr` object. Must be non-NULL. The `fstrm_rdwr`
 *	object must have a `read` method, and may optionally have a `write`
 *	method.
 *
 * \return
 *	`fstrm_reader` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_reader *
fstrm_reader_init(
	const struct fstrm_reader_options *ropt,
	struct fstrm_rdwr **rdwr);

/**
 * Destroy an `fstrm_reader` object. This implicitly calls fstrm_reader_close()
 * if necessary.
 *
 * \param r
 *	Pointer to `fstrm_reader` object.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_reader_destroy(struct fstrm_reader **r);

/**
 * Open an `fstrm_reader` object and prepare it to read data.
 *
 * This checks that the content type in the byte stream, if specified, matches
 * one of the content types specified in the `fstrm_reader_options` object used
 * to initialize the `fstrm_reader` object.
 *
 * This function may fail if there was an underlying problem opening the input
 * stream.
 *
 * \param r
 *	`fstrm_reader` object.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_reader_open(struct fstrm_reader *r);

/**
 * Close an `fstrm_reader` object. Once it has been closed, no data frames may
 * subsequently be read.
 *
 * Calling this function is optional; it may be implicitly invoked by a call to
 * fstrm_reader_destroy().
 *
 * \param r
 *	`fstrm_reader` object.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_reader_close(struct fstrm_reader *r);

/**
 * Read a data frame from an `fstrm_reader` object. This frame is held in an
 * internal buffer owned by the `fstrm_reader` object and should not be modified
 * by the caller. The contents of this buffer will be overwritten by a
 * subsequent call to fstrm_reader_read().
 *
 * This function implicitly calls fstrm_reader_open() if necessary.
 *
 * \param r
 *	`fstrm_reader` object.
 * \param[out] data
 *	Pointer to buffer containing the data frame payload.
 * \param[out] len_data
 *	The number of bytes available in `data`.
 *
 * \retval #fstrm_res_success
 *	A data frame was successfully read.
 * \retval #fstrm_res_stop
 *	The end of the stream has been reached.
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_reader_read(
	struct fstrm_reader *r,
	const uint8_t **data,
	size_t *len_data);

/**
 * Obtain a pointer to an `fstrm_control` object used during processing. Objects
 * returned by this function are owned by the `fstrm_reader` object and must not
 * be modified by the caller. After a call to fstrm_reader_destroy() these
 * pointers will no longer be valid.
 *
 * For example, this function can be used to obtain a pointer to the START
 * control frame, which can be queried to see which "Content Type" was
 * negotiated during the opening of the reader.
 *
 * This function implicitly calls fstrm_reader_open() if necessary.
 *
 * \param r
 *	`fstrm_reader` object.
 * \param type
 *	Which control frame to return.
 * \param[out] control
 *	The `fstrm_control` object.
 *
 * \retval #fstrm_res_success
 *	If an `fstrm_control` object was returned.
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_reader_get_control(
	struct fstrm_reader *r,
	fstrm_control_type type,
	const struct fstrm_control **control);

/**@}*/

#endif /* FSTRM_READER_H */
