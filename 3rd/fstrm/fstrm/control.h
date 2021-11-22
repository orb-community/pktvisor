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

#ifndef FSTRM_CONTROL_H
#define FSTRM_CONTROL_H

/**
 * \defgroup fstrm_control fstrm_control
 *
 * `fstrm_control` is an interface for encoding and decoding Frame Streams
 * control frames.
 *
 * Two types of frames are possible in a Frame Streams byte stream: **data
 * frames** and **control frames**. Both are variable length byte sequences
 * prefixed by a 32-bit big endian unsigned integer (the **frame length**)
 * specifying the length of the following byte sequence. If this frame length
 * value is greater than zero, the **frame length** specifies the **data frame
 * length**, and a data frame follows it. If the frame length is zero (i.e., it
 * is the four byte sequence `00 00 00 00`), this is an **escape sequence**,
 * which means that a control frame follows. The control frame itself is
 * prefixed by a 32-bit big endian unsigned integer (the **control frame
 * length**) specifying the length of the following **control frame payload**.
 *
 * There are two types of control frames used for uni-directional streams:
 * `START` and `STOP`. These control frame types bracket the stream of data
 * frames. `START` indicates the beginning of the stream and communicates
 * metadata about the stream to follow, and `STOP` indicates the end of the
 * stream.
 *
 * Bi-directional streams make use of three additional control frame types:
 * `READY`, `ACCEPT`, and `FINISH`. These control frame types are used in a
 * simple handshake protocol between sender and receiver.
 *
 * A uni-directional Frame Streams byte stream normally consists of the
 * following:
 *
 * 1. The `START` control frame.
 * 2. A sequence of zero or more data frames or control frames that are not of
 *      the control frame types `START`, `STOP`, `ACCEPT`, `READY`, or
 *      `FINISH`.
 * 3. The `STOP` control frame.
 *
 * The `START` and `STOP` control frames are not optional. The `START` control
 * frame must appear at the beginning of the byte stream, and the `STOP` control
 * frame must appear at the end of the byte stream. (If the byte stream has an
 * end.) `START` control frames must not appear anywhere other than at the
 * beginning of the byte stream, and `STOP` control frames must not appear
 * anywhere other than at the end of the byte stream. Only one `START` control
 * frame and only one `STOP` control frame may appear in a Frame Streams byte
 * stream.
 *
 * Control frames may optionally include zero or more **control frame fields**.
 * There is currently one type of control frame field defined: `CONTENT_TYPE`.
 * This field specifies a variable length byte sequence describing the encoding
 * of data frames that appear in the Frame Streams byte stream. This field is
 * used by cooperating programs to unambiguously identify how to interpret the
 * data frames in a particular Frame Streams byte stream. For instance, this
 * field may specify a particular schema to use to interpret the data frames
 * appearing in the byte stream. Zero, one, or more `CONTENT_TYPE` fields may
 * appear in `READY` or `ACCEPT` control frames. Zero or one `CONTENT_TYPE`
 * fields may appear in `START` control frames. No `CONTENT_TYPE` fields may
 * appear in `STOP` or `FINISH` control frames.
 *
 * A uni-directional Frame Streams encoder would normally produce a byte stream
 * as follows:
 *
 * 1. Write the `START` **control frame**.
 *      + At the start of the byte stream, write the four byte **escape
 *      sequence** `00 00 00 00` that precedes control frames.
 *      + Write the **control frame length** as a 32-bit big endian unsigned
 *      integer.
 *      + Write the **control frame payload**. It must be a `START` control
 *      frame. It may optionally specify a `CONTENT_TYPE` field.
 * 2. Write zero or more **data frames**.
 * 3. Write the `STOP` **control frame**.
 *      + At the start of the byte stream, write the four byte **escape
 *      sequence** `00 00 00 00` that precedes control frames.
 *      + Write the **control frame length** as a 32-bit big endian unsigned
 *      integer.
 *      + Write the **control frame payload**. It must be a `STOP` control
 *      frame.
 *
 * A uni-directional Frame Streams decoder would normally process the byte
 * stream as follows:
 *
 * 1. Read the `START` control frame.
 *      + At the start of the byte stream, read the four byte **escape
 *      sequence** `00 00 00 00` that precedes control frames.
 *      + Read the 32-bit big endian unsigned integer specifying the **control
 *      frame length**.
 *      + Decode the **control frame payload**. It must be a `START` control
 *      frame. It may optionally specify a `CONTENT_TYPE` field.
 * 2. Repeatedly read data frames or control frames following the `START`
 * control frame.
 *      + Read the **frame length**, a 32-bit big endian unsigned integer.
 *      + If the **frame length** is zero, a control frame follows:
 *              + Read the 32-bit big endian unsigned integer specifying the
 *              **control frame length**.
 *              + Decode the **control frame payload**. If it is a `STOP`
 *              control frame, the end of the Frame Streams byte stream has
 *              occurred, and no frames follow. Break out of the decoding loop
 *              and halt processing. (`READY`, `ACCEPT`, `START`, and `FINISH`
 *              may not occur here. For forward compatibility, control frames of
 *              types other than the types `READY`, `ACCEPT`, `START`, `STOP`,
 *              and `FINISH` must be ignored here. No control frames specified
 *              in the future may alter the encoding of succeeding frames.)
 *      + If the **frame length** is non-zero, it specifies the number of bytes
 *      in the following **data frame**. Consume these bytes from the byte
 *      stream.
 *
 * The functions fstrm_control_encode() and fstrm_control_decode() are provided
 * to encode and decode control frames. See the detailed descriptions of those
 * functions for code examples showing their usage.
 *
 * @{
 */

/**
 * The maximum length in bytes of an "Accept", "Start", or "Stop" control frame
 * payload. This excludes the escape sequence and the control frame length.
 */
#define FSTRM_CONTROL_FRAME_LENGTH_MAX			512

/**
 * The maximum length in bytes of a "Content Type" control frame field payload.
 * This excludes the field type and payload length.
 */
#define FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX	256

/**
 * Control frame types.
 */
typedef enum {
	/** Control frame type value for "Accept" control frames. */
	FSTRM_CONTROL_ACCEPT	= 0x01,

	/** Control frame type value for "Start" control frames. */
	FSTRM_CONTROL_START	= 0x02,

	/** Control frame type value for "Stop" control frames. */
	FSTRM_CONTROL_STOP	= 0x03,

	/** Control frame type value for "Ready" control frames. */
	FSTRM_CONTROL_READY	= 0x04,

	/** Control frame type value for "Finish" control frames. */
	FSTRM_CONTROL_FINISH	= 0x05,
} fstrm_control_type;

/**
 * Control frame field types. These are optional fields that can appear in
 * control frames.
 */
typedef enum {
	/**
	 * Control frame field type value for the "Content Type" control frame
	 * option.
	 */
	FSTRM_CONTROL_FIELD_CONTENT_TYPE	= 0x01,
} fstrm_control_field;

/**
 * Flags for controlling the behavior of the encoding and decoding functions.
 */
typedef enum {
	/**
	 * Set to control whether to include the control frame header in
	 * encoding/decoding operations.
	 *
	 * Causes fstrm_control_encode() and fstrm_control_encoded_size() to
	 * include the control frame header containing the escape sequence and
	 * control frame payload length in the encoded output. Otherwise, only
	 * the control frame payload itself is encoded.
	 *
	 * Tells fstrm_control_decode() that the input buffer to be decoded
	 * begins with the control frame header containing the escape sequence
	 * and control frame payload length. (Note that this requires the caller
	 * to peek at the input buffer to calculate the right buffer length.)
	 * Otherwise, the input buffer begins with the control frame payload.
	 */
	FSTRM_CONTROL_FLAG_WITH_HEADER		= (1 << 0),
} fstrm_control_flag;

/**
 * Convert an `fstrm_control_type` enum value to a string representation.
 * Unknown values are represented as `"FSTRM_CONTROL_UNKNOWN"`.
 *
 * \param type The `fstrm_control_type` enum value.
 * \return The string representation of the enum value. (Always non-NULL.)
 */
const char *
fstrm_control_type_to_str(fstrm_control_type type);

/**
 * Convert an `fstrm_control_field` enum value to a string representation.
 * Unknown values are represented as `"FSTRM_CONTROL_FIELD_UNKNOWN"`.
 *
 * \param f_type The `fstrm_control_field` enum value.
 * \return The string representation of the enum value. (Always non-NULL.)
 */
const char *
fstrm_control_field_type_to_str(fstrm_control_field f_type);

/**
 * Initialize an `fstrm_control` object. This object represents Frame Streams
 * control frames and is used for encoding and decoding control frames.
 *
 * \return
 *	An `fstrm_control` object.
 */
struct fstrm_control *
fstrm_control_init(void);

/**
 * Destroy an `fstrm_control` object.
 *
 * \param[in] c
 *	Pointer to an `fstrm_control` object.
 */
void
fstrm_control_destroy(struct fstrm_control **c);

/**
 * Reinitialize an `fstrm_control` object. This resets the internal state to
 * default values.
 *
 * \param c
 *	`fstrm_control` object.
 */
void
fstrm_control_reset(struct fstrm_control *c);

/**
 * Retrieve the type of the control frame.
 *
 * \param c
 *	`fstrm_control` object.
 * \param[out] type
 *	Type of the control frame.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_control_get_type(
	const struct fstrm_control *c,
	fstrm_control_type *type);

/**
 * Set the type of the control frame.
 *
 * \param c
 *	`fstrm_control` object.
 * \param[in] type
 *	Type of the control frame.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_control_set_type(
	struct fstrm_control *c,
	fstrm_control_type type);

/**
 * Retrieve the number of "Content Type" fields present in the control frame.
 *
 * \param c
 *	`fstrm_control` object.
 * \param[out] n_content_type
 *	The number of "Content Type" fields.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_control_get_num_field_content_type(
	const struct fstrm_control *c,
	size_t *n_content_type);

/**
 * Retrieve a "Content Type" field from the control frame. This function
 * returns a reference which must not be modified. Control frames may contain
 * zero, one, or more "Content Type" fields.
 *
 * \see fstrm_control_get_num_field_content_type()
 *
 * \param c
 *	`fstrm_control` object.
 * \param[in] idx
 *	The index of the "Content Type" field to retrieve.
 * \param[out] content_type
 *	Pointer to where the reference to the "Content Type" string will be
 *	stored. Note that this string is not NUL-terminated and may contain
 *	embedded NULs.
 * \param[out] len_content_type
 *	The number of bytes in `content_type`.
 *
 * \retval #fstrm_res_success
 *	The control frame has a "Content Type" field.
 * \retval #fstrm_res_failure
 *	The control frame does not have a "Content Type" field.
 */
fstrm_res
fstrm_control_get_field_content_type(
	const struct fstrm_control *c,
	const size_t idx,
	const uint8_t **content_type,
	size_t *len_content_type);

/**
 * Add a "Content Type" field to the control frame. This function makes a copy
 * of the provided string. This function may be called multiple times, in which
 * case multiple "Content Type" fields will be added to the control frame.
 *
 * The "Content Type" fields are removed on a call to fstrm_control_reset().
 *
 * \param c
 *	`fstrm_control` object.
 * \param[in] content_type
 *	The "Content Type" string to copy. Note that this string is not
 *	NUL-terminated and may contain embedded NULs.
 * \param[in] len_content_type
 *	The number of bytes in `content_type`.
 *
 * \retval #fstrm_res_success
 *	The "Content Type" field was successfully added.
 * \retval #fstrm_res_failure
 *	The "Content Type" string is too long.
 */
fstrm_res
fstrm_control_add_field_content_type(
	struct fstrm_control *c,
	const uint8_t *content_type,
	size_t len_content_type);

/**
 * Check if the control frame matches a particular content type value. That is,
 * the content type given in the `match` and `len_match` parameters is checked
 * for compatibility with the content types (if any) specified in the control
 * frame.
 *
 * \param c
 *	`fstrm_control` object.
 * \param match
 *	The "Content Type" string to match. Note that this string is not
 *	NUL-terminated and may contain embedded NULs. May be NULL, in which case
 *	the control frame must not have any content type fields in order to
 *	match.
 * \param len_match
 *	The number of bytes in `match`.
 *
 * \retval #fstrm_res_success
 *	A match was found.
 * \retval #fstrm_res_failure
 *	A match was not found.
 */
fstrm_res
fstrm_control_match_field_content_type(
	const struct fstrm_control *c,
	const uint8_t *match,
	const size_t len_match);

/**
 * Decode a control frame from a buffer. The buffer starts with either the
 * escape sequence or the control frame payload depending on whether the
 * `FSTRM_CONTROL_FLAG_WITH_HEADER` flag is set or not. In either case, the
 * 'len_control_frame' parameter must be exact. Underflow or overflow is not
 * permitted.
 *
 * The following code example shows a function that decodes a control frame
 * payload:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
static fstrm_res
decode_control_frame(const void *control_frame, size_t len_control_frame)
{
        fstrm_res res;
        fstrm_control_type c_type;
        struct fstrm_control *c;
        uint32_t flags = 0;

        c = fstrm_control_init();

        res = fstrm_control_decode(c, control_frame, len_control_frame, flags);
        if (res != fstrm_res_success) {
                puts("fstrm_control_decode() failed.");
                fstrm_control_destroy(&c);
                return res;
        }

        res = fstrm_control_get_type(c, &c_type);
        if (res != fstrm_res_success) {
                puts("fstrm_control_get_type() failed.");
                fstrm_control_destroy(&c);
                return res;
        }
        printf("The control frame is of type %s (%u).\n",
               fstrm_control_type_to_str(c_type), c_type);

	size_t n_content_type;
	res = fstrm_control_get_num_field_content_type(c, &n_content_type);
	if (res != fstrm_res_success) {
		puts("fstrm_control_get_num_field_content_type() failed.");
		fstrm_control_destroy(&c);
		return res;
	}

        const uint8_t *content_type;
        size_t len_content_type;
	for (size_t idx = 0; idx < n_content_type; idx++) {
		res = fstrm_control_get_field_content_type(c, idx,
			&content_type, &len_content_type);
		if (res == fstrm_res_success) {
			printf("The control frame has a CONTENT_TYPE field of length %zd.\n",
			       len_content_type);
		}
	}

        fstrm_control_destroy(&c);
        return fstrm_res_success;
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \param c
 *	`fstrm_control` object. Its state will be overwritten.
 * \param[in] control_frame
 *	Buffer containing the serialized control frame.
 * \param[in] len_control_frame
 *	The number of bytes in `control_frame`. This parameter must specify the
 *	exact number of bytes in the control frame.
 * \param flags
 *	Flags controlling the decoding process. See #fstrm_control_flag.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_control_decode(
	struct fstrm_control *c,
	const void *control_frame,
	size_t len_control_frame,
	const uint32_t flags);

/**
 * Calculate the number of bytes needed to serialize the control frame.
 *
 * \param c
 *	`fstrm_control` object.
 * \param[out] len_control_frame
 *	The number of bytes needed to encode `c`.
 * \param flags
 *	Flags controlling the encoding process. See #fstrm_control_flag.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_control_encoded_size(
	const struct fstrm_control *c,
	size_t *len_control_frame,
	const uint32_t flags);

/**
 * Encode a control frame into a buffer. Since a Frame Streams control frame is
 * a variable length byte sequence of up to #FSTRM_CONTROL_FRAME_LENGTH_MAX
 * bytes, this function can be used in two different ways. The first way is to
 * call fstrm_control_encoded_size() to obtain the exact number of bytes needed
 * to encode the frame, and then pass a buffer of this exact size to
 * fstrm_control_encode(). The following example shows this usage:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	fstrm_res res;
	struct fstrm_control *c;
	uint8_t *control_frame;
	size_t len_control_frame;
	uint32_t flags = 0;

	c = fstrm_control_init();
	res = fstrm_control_set_type(c, FSTRM_CONTROL_START);
	if (res != fstrm_res_success) {
		// Error handling goes here.
	}

	// Calculate the number of bytes needed.
	res = fstrm_control_encoded_size(c, &len_control_frame, flags);
	if (res != fstrm_res_success) {
		// Error handling goes here.
	}

	// 'len_control_frame' now specifies the number of bytes required for
	// the control frame. Allocate the needed space.
	control_frame = malloc(len_control_frame);
	if (!control_frame) {
		// Error handling goes here.
	}

	// Serialize the control frame into the allocated buffer.
	res = fstrm_control_encode(c, control_frame, &len_control_frame, 0);
	if (res != fstrm_res_success) {
		// Error handling goes here.
	}

	// Do something with 'control_frame' and 'len_control_frame'.

	// Clean up.
	free(control_frame);
	fstrm_control_destroy(&c);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The second way to use fstrm_control_encode() is to allocate a statically
 * sized buffer of #FSTRM_CONTROL_FRAME_LENGTH_MAX bytes. The exact number of
 * bytes serialized by the encoder will be returned in the `len_control_frame`
 * parameter. The following example shows this usage:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	fstrm_res res;
	struct fstrm_control *c;
	uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_control_frame = sizeof(control_frame);

	c = fstrm_control_init();
	res = fstrm_control_set_type(c, FSTRM_CONTROL_START);
	if (res != fstrm_res_success) {
		// Error handling.
	}

	// Serialize the control frame.
	res = fstrm_control_encode(c, control_frame, &len_control_frame, 0);
	if (res != fstrm_res_success) {
		// Error handling goes here.
	}

	// Do something with 'control_frame' and 'len_control_frame'.

	// Clean up.
	fstrm_control_destroy(&c);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \param c
 *	`fstrm_control` object.
 * \param[out] control_frame
 *	The buffer in which to serialize the control frame.
 * \param[in,out] len_control_frame
 *	The size in bytes of `control_frame`. On a successful return, contains
 *	the number of bytes actually written into `control_frame`.
 * \param flags
 *	Flags controlling the encoding process. See #fstrm_control_flag.
 *
 * \retval #fstrm_res_success
 * \retval #fstrm_res_failure
 */
fstrm_res
fstrm_control_encode(
	const struct fstrm_control *c,
	void *control_frame,
	size_t *len_control_frame,
	const uint32_t flags);

/**@}*/

#endif /* FSTRM_CONTROL_H */
