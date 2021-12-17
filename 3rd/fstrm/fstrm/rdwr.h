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

#ifndef FSTRM_RDWR_H
#define FSTRM_RDWR_H

/**
 * \defgroup fstrm_rdwr fstrm_rdwr
 *
 * `fstrm_rdwr` is an interface for abstracting the process of reading and
 * writing data to byte streams. It allows extending the `fstrm` library to
 * support reading and writing Frame Streams data to new kinds of byte stream
 * transports. (It also allows building mock interfaces for testing the correct
 * functioning of the library.)
 *
 * `fstrm_rdwr` is a low-level interface that is used in conjunction with the
 * higher level \ref fstrm_reader and \ref fstrm_writer interfaces. The
 * following methods need to be defined for `fstrm_rdwr` implementations:
 *
 * Method name  | Method type                   | Method description
 * ------------ | ----------------------------- | ------------------
 * `destroy`    | #fstrm_rdwr_destroy_func      | Destroys the instance.
 * `open`       | #fstrm_rdwr_open_func         | Opens the stream.
 * `close`      | #fstrm_rdwr_close_func        | Closes the stream.
 * `read`       | #fstrm_rdwr_read_func         | Reads bytes from the stream.
 * `write`      | #fstrm_rdwr_write_func        | Writes bytes to the stream.
 *
 * The `destroy` method is optional. It cleans up any remaining resources
 * associated with the instance.
 *
 * The `open` method is required. It should perform the actual opening of the
 * byte stream and prepare it to read or write data.
 *
 * The `close` method is required. It should perform the actual closing of the
 * byte stream.
 *
 * If the `fstrm_rdwr` object is to be used in an `fstrm_reader` object, it must
 * have a `read` method. If the `fstrm_rdwr` object embedded in an
 * `fstrm_reader` object also has a `write` method, the stream will be
 * considered bi-directional (that is, it supports both reading and writing) and
 * handshaking will be performed. If a `read` method is supplied but a `write`
 * method is not, the reader's stream will instead be considered
 * uni-directional. See \ref fstrm_reader for details.
 *
 * If the `fstrm_rdwr` object is to be used in an `fstrm_writer` object, it must
 * have a `write` method. If the `fstrm_rdwr` object embedded in an
 * `fstrm_writer` object also has a `read` method, the stream will be considered
 * bi-directional and shaking will be performed. If a `write` method is supplied
 * but a `read` method is not, the writer's stream will instead be considered
 * uni-directional. See \ref fstrm_writer for details.
 *
 * An `fstrm_rdwr` instance is created with a call to `fstrm_rdwr_init()`,
 * optionally passing a pointer to some state object associated with the
 * instance. This pointer will be passed as the first argument to each of the
 * methods described above. Then, the various `fstrm_rdwr_set_*()` functions
 * should be used to configure the functions to be used to invoke the methods
 * required for the `fstrm_rdwr` object.
 *
 * @{
 */

/**
 * `destroy` method function type. This method is invoked to deallocate any
 * per-stream resources used by an `fstrm_rdwr` implementation.
 *
 * \see fstrm_rdwr_set_destroy()
 *
 * \param obj
 *      The `obj` value passed to `fstrm_rdwr_init()`.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
typedef fstrm_res
(*fstrm_rdwr_destroy_func)(void *obj);

/**
 * `open` method function type. This method is invoked to open the stream and
 * prepare it for reading or writing. For example, if an `fstrm_rdwr`
 * implementation is backed by file I/O, this method might be responsible for
 * opening a file descriptor.
 *
 * \see fstrm_rdwr_set_open()
 *
 * \param obj
 *      The `obj` value passed to `fstrm_rdwr_init()`.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
typedef fstrm_res
(*fstrm_rdwr_open_func)(void *obj);

/**
 * `close` method function type. This method is invoked to close the stream. For
 * example, if an `fstrm_rdwr` implementation is backed by file I/O, this method
 * might be responsible for closing a file descriptor.
 *
 * \see fstrm_rdwr_set_close()
 *
 * \param obj
 *      The `obj` value passed to `fstrm_rdwr_init()`.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
typedef fstrm_res
(*fstrm_rdwr_close_func)(void *obj);

/**
 * `read` method function type. This method is used to read data from a stream.
 * It must satisfy the full amount of data requested, unless the stream has
 * ended.
 *
 * \see fstrm_rdwr_set_read()
 *
 * \param obj
 *      The `obj` value passed to `fstrm_rdwr_init()`.
 * \param data
 *      The buffer in which to place the data read.
 * \param count
 *      The number of bytes requested.
 *
 * \retval #fstrm_res_success
 *      The data was read successfully.
 * \retval #fstrm_res_failure
 *      An unexpected failure occurred.
 * \retval #fstrm_res_stop
 *      The end of the stream has occurred.
 */
typedef fstrm_res
(*fstrm_rdwr_read_func)(void *obj, void *data, size_t count);

/**
 * `write` method function type. This method is used to write data to a stream.
 * It must perform the full write of all data, unless an error has occurred.
 *
 * \see fstrm_rdwr_set_write()
 *
 * \param obj
 *      The `obj` value passed to `fstrm_rdwr_init()`.
 * \param iov
 *      Array of `struct iovec` objects.
 * \param iovcnt
 *      Number of `struct iovec` objects in `iov`.
 *
 * \return #fstrm_res_success
 * \return #fstrm_res_failure
 */
typedef fstrm_res
(*fstrm_rdwr_write_func)(void *obj, const struct iovec *iov, int iovcnt);

/**
 * Initialize a new `fstrm_rdwr` object.
 *
 * \param obj
 *      Per-object state.
 *
 * \return
 *      `fstrm_rdwr` object.
 * \retval
 *      NULL on failure.
 */
struct fstrm_rdwr *
fstrm_rdwr_init(void *obj);

/**
 * Destroy an `fstrm_rdwr` object. This invokes the underlying `destroy` method
 * as well.
 *
 * \param rdwr
 *      Pointer to an `fstrm_rdwr` object.
 *
 * \return #fstrm_res_success
 * \return #fstrm_res_failure
 */
fstrm_res
fstrm_rdwr_destroy(struct fstrm_rdwr **rdwr);

/**
 * Invoke the `open` method on an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 *
 * \return #fstrm_res_success
 * \return #fstrm_res_failure
 */
fstrm_res
fstrm_rdwr_open(struct fstrm_rdwr *rdwr);

/**
 * Invoke the `close` method on an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 *
 * \return #fstrm_res_success
 * \return #fstrm_res_failure
 */
fstrm_res
fstrm_rdwr_close(struct fstrm_rdwr *rdwr);

/**
 * Invoke the `read` method on an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param data
 *      The buffer in which to place the data read.
 * \param count
 *      The number of bytes to read.
 *
 * \return #fstrm_res_success
 * \return #fstrm_res_failure
 * \return #fstrm_res_stop
 */
fstrm_res
fstrm_rdwr_read(struct fstrm_rdwr *rdwr, void *data, size_t count);

/**
 * Invoke the `write` method on an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param iov
 *      Array of `struct iovec` objects.
 * \param iovcnt
 *      Number of `struct iovec` objects in `iov`.
 *
 * \return #fstrm_res_success
 * \return #fstrm_res_failure
 */
fstrm_res
fstrm_rdwr_write(struct fstrm_rdwr *rdwr, const struct iovec *iov, int iovcnt);

/**
 * Set the `destroy` method for an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param fn
 *      Function to use.
 */
void
fstrm_rdwr_set_destroy(
	struct fstrm_rdwr *rdwr,
	fstrm_rdwr_destroy_func fn);

/**
 * Set the `open` method for an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param fn
 *      Function to use.
 */
void
fstrm_rdwr_set_open(
	struct fstrm_rdwr *rdwr,
	fstrm_rdwr_open_func fn);

/**
 * Set the `close` method for an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param fn
 *      Function to use.
 */
void
fstrm_rdwr_set_close(
	struct fstrm_rdwr *rdwr,
	fstrm_rdwr_close_func fn);

/**
 * Set the `read` method for an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param fn
 *      Function to use.
 */
void
fstrm_rdwr_set_read(
	struct fstrm_rdwr *rdwr,
	fstrm_rdwr_read_func fn);

/**
 * Set the `write` method for an `fstrm_rdwr` object.
 *
 * \param rdwr
 *      The `fstrm_rdwr` object.
 * \param fn
 *      Function to use.
 */
void
fstrm_rdwr_set_write(
	struct fstrm_rdwr *rdwr,
	fstrm_rdwr_write_func fn);

/**@}*/

#endif /* FSTRM_RDWR_H */
