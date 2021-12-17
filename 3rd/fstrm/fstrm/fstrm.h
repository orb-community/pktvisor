/*
 * Copyright (c) 2013-2014 by Farsight Security, Inc.
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

/*! \file
 * \mainpage Introduction
 *
 * This is `fstrm`, a C implementation of the Frame Streams data transport
 * protocol.
 *
 * Frame Streams is a light weight, binary clean protocol that allows for the
 * transport of arbitrarily encoded data payload sequences with minimal framing
 * overhead -- just four bytes per data frame. Frame Streams does not specify an
 * encoding format for data frames and can be used with any data serialization
 * format that produces byte sequences, such as [Protocol Buffers], [XML],
 * [JSON], [MessagePack], [YAML], etc. Frame Streams can be used as both a
 * streaming transport over a reliable byte stream socket (TCP sockets, TLS
 * connections, `AF_UNIX` sockets, etc.) for data in motion as well as a file
 * format for data at rest. A "Content Type" header identifies the type of
 * payload being carried over an individual Frame Stream and allows cooperating
 * programs to determine how to interpret a given sequence of data payloads.
 *
 * `fstrm` is an optimized C implementation of Frame Streams that includes a
 * fast, lockless circular queue implementation and exposes library interfaces
 * for setting up a dedicated Frame Streams I/O thread and asynchronously
 * submitting data frames for transport from worker threads. It was originally
 * written to facilitate the addition of high speed binary logging to DNS
 * servers written in C using the [dnstap] log format.
 *
 * This is the API documentation for the `fstrm` library. For the project
 * hosting site, see <https://github.com/farsightsec/fstrm>.
 *
 * \authors Farsight Security, Inc. and the `fstrm` authors.
 *
 * \copyright 2013-2018. Licensed under the terms of the [MIT] license.
 *
 * [Protocol Buffers]: https://developers.google.com/protocol-buffers/
 * [XML]:              http://www.w3.org/TR/xml11/
 * [JSON]:             http://www.json.org/
 * [MessagePack]:      http://msgpack.org/
 * [YAML]:             http://www.yaml.org/
 * [dnstap]:           http://dnstap.info/
 * [MIT]:              https://opensource.org/licenses/MIT
 *
 * \page overview Library overview
 *
 * \section init Initializing the library
 *
 * `fstrm` has no global library state. In most cases, only a single
 * \ref fstrm_iothr library context object will be needed for the entire process,
 * which will implicitly create a background I/O serialization thread. This I/O
 * thread is bound to a particular output writer (for example, an `AF_UNIX`
 * socket) and is fully buffered -- submitted data frames will be accumulated in
 * an output buffer and periodically flushed, minimizing the number of system
 * calls that need to be performed. This frees worker threads from waiting for a
 * write() to complete.
 *
 * `fstrm` abstracts the actual I/O operations needed to read or write a byte
 * stream. File and socket I/O implementations are included in the library, but
 * if necessary `fstrm` can be extended to support new types of byte stream
 * transports. See the \ref fstrm_reader, \ref fstrm_writer, and \ref fstrm_rdwr
 * interfaces for details.
 *
 * The following code example shows the initialization of an `fstrm_iothr`
 * library context object connected to an \ref fstrm_file writer.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        const char *file_path = "/tmp/output.fs";
        struct fstrm_file_options *fopt;
        struct fstrm_iothr *iothr;
        struct fstrm_writer *writer;

        fopt = fstrm_file_options_init();
        fstrm_file_options_set_file_path(fopt, file_path);

        writer = fstrm_file_writer_init(fopt, NULL);
        if (!writer) {
                fprintf(stderr, "Error: fstrm_file_writer_init() failed.\n");
                exit(EXIT_FAILURE);
        }

        iothr = fstrm_iothr_init(NULL, &writer);
        if (!iothr) {
                fprintf(stderr, "Error: fstrm_iothr_init() failed.\n");
                exit(EXIT_FAILURE);
        }

        fstrm_file_options_destroy(&fopt);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Since the I/O operations are abstracted through the `fstrm_writer` interface,
 * the `writer` variable in the above example could instead have been
 * initialized with a completely different implementation. For example,
 * \ref fstrm_unix_writer objects can be initialized as follows:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        const char *socket_path = "/tmp/output.sock";
        struct fstrm_writer *writer;
        struct fstrm_unix_writer_options *uwopt;

        uwopt = fstrm_unix_writer_options_init();
        fstrm_unix_writer_options_set_socket_path(uwopt, socket_path);

        writer = fstrm_unix_writer_init(uwopt, NULL);
        if (!writer) {
                fprintf(stderr, "Error: fstrm_unix_writer_init() failed.\n");
                exit(EXIT_FAILURE);
        }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \section queue Getting an input queue
 *
 * After the `fstrm_iothr` object has been created with fstrm_iothr_init(), an
 * input queue handle can be obtained with the fstrm_iothr_get_input_queue()
 * function, which returns an `fstrm_iothr_queue` object. This function is
 * thread-safe and returns a unique queue each time it is called, up to the
 * number of queues specified by fstrm_iothr_options_set_num_input_queues().
 * `fstrm_iothr_queue` objects belong to their parent `fstrm_iothr` object and
 * will be destroyed when the parent `fstrm_iothr` object is destroyed.
 *
 * The following code example shows a single `fstrm_iothr_queue` handle being
 * obtained from an already initialized `fstrm_iothr` library context object.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // 'iothr' is a struct fstrm_iothr *

        struct fstrm_iothr_queue *ioq;
        ioq = fstrm_iothr_get_input_queue(iothr);
        if (!ioq) {
                fprintf(stderr, "Error: fstrm_iothr_get_input_queue() failed.\n");
                exit(EXIT_FAILURE);
        }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \section submit Submitting data frames
 *
 * Once the `fstrm_iothr` object has been created and an `fstrm_iothr_queue`
 * handle is available, data frames can be submitted for asynchronous writing
 * using the fstrm_iothr_submit() function. A callback is passed to this
 * function which will be invoked to deallocate the data frame once the I/O
 * thread has completed processing it. In the common case where the data frame
 * is dynamically allocated with `malloc()`, the deallocation callback must call
 * `free()`. fstrm_free_wrapper() is provided as a convenience function which
 * does this and can be specified as the `free_func` parameter to
 * fstrm_iothr_submit().
 *
 * If space is available in the queue, fstrm_iothr_submit() will return
 * #fstrm_res_success, indicating that ownership of the memory allocation for the
 * data frame has passed from the caller to the library. The caller must not
 * reuse or deallocate the memory for the data frame after a successful call to
 * fstrm_iothr_submit().
 *
 * Callers must check the return value of fstrm_iothr_submit(). If this function
 * fails, that is, it returns any result code other than #fstrm_res_success, the
 * caller must deallocate or otherwise dispose of memory allocated for the data
 * frame, in order to avoid leaking memory. fstrm_iothr_submit() can fail with
 * #fstrm_res_again if there is currently no space in the circular queue for an
 * additional frame, in which case a later call to fstrm_iothr_submit() with the
 * same parameters may succeed. However, if fstrm_iothr_submit() fails with
 * #fstrm_res_invalid, then there is a problem with the parameters and a later
 * call will not succeed.
 *
 * The following code example shows data frames containing a short sequence of
 * bytes being created and submitted repeatedly, with appropriate error
 * handling. Note that the data frames in this example intentionally contain
 * embedded unprintable characters, showing that Frame Streams is binary clean.
 * This example follows from the previous examples, where the `iothr` and `ioq`
 * variables have already been initialized.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // 'iothr' is a struct fstrm_iothr *
        // 'ioq' is a struct fstrm_queue *

        const unsigned num_frames = 100;
        const uint8_t frame_template[] = {
                'H', 'e', 'l', 'l', 'o', 0x00, 0x01, 0x02, 0x03,
                'W', 'o', 'r', 'l', 'd', 0x04, 0x05, 0x06, 0x07,
        };

        for (unsigned i = 0; i < num_frames; i++) {
                // Allocate a new frame from the template.
                uint8_t *frame = malloc(sizeof(frame_template));
                if (!frame)
                        break;
                memcpy(frame, frame_template, sizeof(frame_template));

                // Submit the frame for writing.
                for (;;) {
                        fstrm_res res;
                        res = fstrm_iothr_submit(iothr, ioq, frame,
                                                 sizeof(frame_template),
                                                 fstrm_free_wrapper, NULL);
                        if (res == fstrm_res_success) {
                                // Frame successfully queued.
                                break;
                        } else if (res == fstrm_res_again) {
                                // Queue is full. Try again in a busy loop.
                                // Alternatively, if loss can be tolerated we
                                // could free the frame here and break out of
                                // the loop.
                                continue;
                        } else {
                                // Permanent failure.
                                free(frame);
                                fputs("fstrm_iothr_submit() failed.\n", stderr);
                                break;
                        }
                }
        }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \section shutdown Shutting down
 *
 * Calling fstrm_iothr_destroy() on the `fstrm_iothr` object will signal the I/O
 * thread to flush any outstanding data frames being written and will deallocate
 * all associated resources. This function is synchronous and does not return
 * until the I/O thread has terminated.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // 'iothr' is a struct fstrm_iothr *
        fstrm_iothr_destroy(&iothr);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef FSTRM_H
#define FSTRM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/uio.h>
#include <stddef.h>
#include <stdint.h>

/**
 * \defgroup fstrm_res fstrm_res
 *
 * Library result codes.
 * @{
 */

/**
 * Result codes for functions.
 */
typedef enum {
	/** Success. */
	fstrm_res_success,

	/** Failure. */
	fstrm_res_failure,

	/** Resource temporarily unavailable. */
	fstrm_res_again,

	/** Parameters were invalid. */
	fstrm_res_invalid,

	/** The end of a stream has been reached. */
	fstrm_res_stop,
} fstrm_res;

/**@}*/

struct fstrm_control;
struct fstrm_file_options;
struct fstrm_iothr;
struct fstrm_iothr_options;
struct fstrm_iothr_queue;
struct fstrm_rdwr;
struct fstrm_reader_options;
struct fstrm_unix_writer_options;
struct fstrm_writer;
struct fstrm_writer_options;

#include <fstrm/control.h>
#include <fstrm/file.h>
#include <fstrm/iothr.h>
#include <fstrm/rdwr.h>
#include <fstrm/reader.h>
#include <fstrm/tcp_writer.h>
#include <fstrm/unix_writer.h>
#include <fstrm/writer.h>

#ifdef __cplusplus
}
#endif

#endif /* FSTRM_H */
