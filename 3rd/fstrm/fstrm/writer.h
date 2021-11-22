/*
 * Copyright (c) 2014, 2018 by Farsight Security, Inc.
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

#ifndef FSTRM_WRITER_H
#define FSTRM_WRITER_H

/**
 * \defgroup fstrm_writer fstrm_writer
 *
 * `fstrm_writer` is an interface for writing Frame Streams data into a byte
 * stream. The underlying byte stream I/O operations are abstracted by the
 * \ref fstrm_rdwr interface. Thus, the `fstrm_writer` interface can be used to
 * write Frame Streams data to any type of output whose read/write operations
 * are wrapped by an `fstrm_rdwr` object.
 *
 * Some basic `fstrm_writer` implementations are already provided in the `fstrm`
 * library. See fstrm_file_writer_init() for an implementation that writes to
 * a regular file, fstrm_tcp_writer_init() for an implementation that writes to
 * a TCP socket, and fstrm_unix_writer_init() for an implementation that writes
 * to a Unix socket.
 *
 * @{
 */

/**
 * Initialize an `fstrm_writer_options` object.
 *
 * \return
 *	`fstrm_writer_options` object.
 */
struct fstrm_writer_options *
fstrm_writer_options_init(void);

/**
 * Destroy an `fstrm_writer_options` object.
 *
 * \param wopt
 *	Pointer to `fstrm_writer_options` object.
 */
void
fstrm_writer_options_destroy(
	struct fstrm_writer_options **wopt);

/**
 * Add a "Content Type" value to the set of content types that can be negotiated
 * by the writer. This function makes a copy of the provided string. This
 * function may be called multiple times, in which case multiple "Content Type"
 * values will be accepted by the reader.
 *
 * For uni-directional streams like regular files, the negotiated content type
 * will simply be the first content type provided to this function. For
 * bi-directional streams like sockets, a handshake occurs and the remote end
 * determines which content type should be sent. In the latter case, after the
 * writer has been successfully opened with a call to fstrm_writer_open(), the
 * fstrm_writer_get_control() function should be called with `type` set to
 * `FSTRM_CONTROL_ACCEPT` and the control frame queried in order to determine
 * the negotiated content type.
 *
 * \param wopt
 *	`fstrm_writer_options` object.
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
fstrm_writer_options_add_content_type(
	struct fstrm_writer_options *wopt,
	const void *content_type,
	size_t len_content_type);

/**
 * Initialize a new `fstrm_writer` object based on an underlying `fstrm_rdwr`
 * object and an `fstrm_writer_options` object.
 *
 * The underlying `fstrm_rdwr` object MUST have a `write` method. It MAY
 * optionally have a `read` method, in which case the stream will be treated as
 * a bi-directional, handshaked stream. Otherwise, if there is no `read` method
 * the stream will be treated as a uni-directional stream.
 *
 * This function is useful for implementing functions that return new types of
 * `fstrm_writer` objects, such as fstrm_file_writer_init() and
 * fstrm_unix_writer_init().
 *
 * After a successful call to this function, the ownership of the `fstrm_rdwr`
 * object passes from the caller to the `fstrm_writer` object. The caller
 * should perform no further calls on the `fstrm_rdwr` object. The `fstrm_rdwr`
 * object will be cleaned up on a call to fstrm_writer_destroy().
 *
 * \param wopt
 *      `fstrm_writer_options` object. May be NULL, in which case default values
 *      will be used.
 *
 * \param rdwr
 *      Pointer to `fstrm_rdwr` object. Must be non-NULL. The `fstrm_rdwr`
 *      object must have a `write` method, and may optionally have a `read`
 *      method.
 *
 * \return
 *      `fstrm_writer` object.
 * \retval
 *      NULL on failure.
 */
struct fstrm_writer *
fstrm_writer_init(
	const struct fstrm_writer_options *wopt,
	struct fstrm_rdwr **rdwr);

/**
 * Destroy an `fstrm_writer` object. This implicitly calls fstrm_writer_close()
 * if necessary.
 *
 * \param w
 *	Pointer to `fstrm_writer` object.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_writer_destroy(struct fstrm_writer **w);

/**
 * Open an `fstrm_writer` object and prepare it to write data. For
 * bi-directional writer implementations, this performs content type
 * negotiation.
 *
 * This function may fail if there was an underlying problem opening the output
 * stream.
 *
 * \param w
 *	`fstrm_writer` object.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_writer_open(struct fstrm_writer *w);

/**
 * Close an `fstrm_writer` object. Open it has been closed, no data frames may
 * subsequently be written.
 *
 * Calling this function is optional; it may be implicitly invoked by a call to
 * fstrm_writer_destroy().
 *
 * \param w
 *	`fstrm_writer` object.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_writer_close(struct fstrm_writer *w);

/**
 * Write a data frame to an `fstrm_writer` object.
 *
 * This function implicitly calls fstrm_writer_open() if necessary.
 *
 * \param w
 *	`fstrm_writer` object.
 * \param[in] data
 *	Buffer containing the data frame payload.
 * \param[in] len_data
 *	The number of bytes in `data`.
 *
 * \retval #fstrm_res_success
 *	The data frame was successfully written.
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_writer_write(
	struct fstrm_writer *w,
	const void *data,
	size_t len_data);

/**
 * Write multiple data frames to an `fstrm_writer` object.
 *
 * This function implicitly calls fstrm_writer_open() if necessary.
 * 
 * Data frames are passed similarly to the `writev()` system call, with an array
 * of `struct iovec` objects describing the data frame payloads and their
 * lengths. The complete set of data frames will be written to the output
 * stream after a successful call.
 *
 * \param w
 *	`fstrm_writer` object.
 * \param iov
 *	Array of `struct iovec` objects.
 * \param iovcnt
 *	Number of `struct iovec` objects in `iov`.
 *
 * \retval #fstrm_res_success
 *	The data frames were successfully written.
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_writer_writev(
	struct fstrm_writer *w,
	const struct iovec *iov,
	int iovcnt);

/**
 * Obtain a pointer to an `fstrm_control` object used during processing. Objects
 * returned by this function are owned by the `fstrm_reader` object and must not
 * be modified by the caller. After a call to fstrm_reader_destroy() these
 * pointers will no longer be valid.
 *
 * For example, with bi-directional streams this function can be used to obtain
 * a pointer to the ACCEPT control frame, which can be queried to see which
 * "Content Type" was negotiated during the opening of the writer.
 *
 * This function implicitly calls fstrm_writer_open() if necessary.
 *
 * \param w
 *      `fstrm_writer` object.
 * \param type
 *      Which control frame to return.
 * \param[out] control
 *      The `fstrm_control` object.
 *
 * \retval #fstrm_res_success
 *      If an `fstrm_control` object was returned.
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_writer_get_control(
	struct fstrm_writer *w,
	fstrm_control_type type,
	struct fstrm_control **control);

/**@}*/

#endif /* FSTRM_WRITER_H */
