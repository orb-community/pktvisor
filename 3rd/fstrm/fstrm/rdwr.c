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

#include "fstrm-private.h"

struct fstrm_rdwr *
fstrm_rdwr_init(void *obj)
{
	struct fstrm_rdwr *rdwr;
	rdwr = my_calloc(1, sizeof(*rdwr));
	rdwr->obj = obj;
	return rdwr;
}

fstrm_res
fstrm_rdwr_destroy(struct fstrm_rdwr **rdwr)
{
	fstrm_res res = fstrm_res_success;
	if (*rdwr != NULL) {
		if ((*rdwr)->ops.destroy != NULL)
			res = (*rdwr)->ops.destroy((*rdwr)->obj);
		my_free(*rdwr);
	}
	return res;
}

fstrm_res
fstrm_rdwr_open(struct fstrm_rdwr *rdwr)
{
	fstrm_res res;
	if (unlikely(rdwr->ops.open == NULL))
		return fstrm_res_failure;
	res = rdwr->ops.open(rdwr->obj);
	if (res == fstrm_res_success)
		rdwr->opened = true;
	return res;
}

fstrm_res
fstrm_rdwr_close(struct fstrm_rdwr *rdwr)
{
	if (unlikely(rdwr->ops.close == NULL))
		return fstrm_res_failure;
	if (rdwr->opened) {
		rdwr->opened = false;
		return rdwr->ops.close(rdwr->obj);
	}
	return fstrm_res_success;
}

fstrm_res
fstrm_rdwr_read(struct fstrm_rdwr *rdwr, void *data, size_t count)
{
	fstrm_res res;
	
	/* If the rdwr is not opened, it cannot be read from. */
	if (unlikely(!rdwr->opened))
		return fstrm_res_failure;

	/* This should never be called on a rdwr without a read method. */
	if (unlikely(rdwr->ops.read == NULL))
		return fstrm_res_failure;

	/*
	 * Invoke the rdwr's read method. If this fails we need to clean up by
	 * invoking the close method.
	 */
	res = rdwr->ops.read(rdwr->obj, data, count);
	if (unlikely(res != fstrm_res_success))
		(void)fstrm_rdwr_close(rdwr);
	return res;
}

fstrm_res
fstrm_rdwr_write(struct fstrm_rdwr *rdwr, const struct iovec *iov, int iovcnt)
{
	fstrm_res res;

	/* If the rdwr is not opened, it cannot be written to. */
	if (unlikely(!rdwr->opened))
		return fstrm_res_failure;

	/* This should never be called on a rdwr without a write method. */
	if (unlikely(rdwr->ops.write == NULL))
		return fstrm_res_failure;

	/*
	 * Invoke the rdwr's write method. If this fails we need to clean up by
	 * invoking the close method.
	 */
	res = rdwr->ops.write(rdwr->obj, iov, iovcnt);
	if (unlikely(res != fstrm_res_success))
		(void)fstrm_rdwr_close(rdwr);
	return res;
}

void
fstrm_rdwr_set_destroy(struct fstrm_rdwr *rdwr,
		       fstrm_rdwr_destroy_func fn)
{
	rdwr->ops.destroy = fn;
}

void
fstrm_rdwr_set_open(struct fstrm_rdwr *rdwr,
		    fstrm_rdwr_open_func fn)
{
	rdwr->ops.open = fn;
}

void
fstrm_rdwr_set_close(struct fstrm_rdwr *rdwr,
		     fstrm_rdwr_close_func fn)
{
	rdwr->ops.close = fn;
}

void
fstrm_rdwr_set_read(struct fstrm_rdwr *rdwr,
		    fstrm_rdwr_read_func fn)
{
	rdwr->ops.read = fn;
}

void
fstrm_rdwr_set_write(struct fstrm_rdwr *rdwr,
		     fstrm_rdwr_write_func fn)
{
	rdwr->ops.write = fn;
}

fstrm_res
fstrm__rdwr_read_control_frame(struct fstrm_rdwr *rdwr,
			       struct fstrm_control *control,
			       fstrm_control_type *type,
			       const bool with_escape)
{
	const uint32_t flags = 0;
	uint32_t tmp;
	fstrm_res res;

	if (with_escape) {
		/* Read the escape sequence. */
		res = fstrm_rdwr_read(rdwr, &tmp, sizeof(tmp));
		if (res != fstrm_res_success)
			return res;
		if (ntohl(tmp) != 0)
			return fstrm_res_failure;
	}

	/* Read the control frame length. */
	res = fstrm_rdwr_read(rdwr, &tmp, sizeof(tmp));
	if (res != fstrm_res_success)
		return res;
	const size_t len_control_frame = ntohl(tmp);

	/* Sanity check the control frame length. */
	if (len_control_frame > FSTRM_CONTROL_FRAME_LENGTH_MAX)
		return fstrm_res_failure;

	/* Read the control frame. */
	uint8_t control_frame[len_control_frame];
	res = fstrm_rdwr_read(rdwr, control_frame, sizeof(control_frame));
	if (res != fstrm_res_success)
		return res;

	/* Decode the control frame. */
	assert(control != NULL);
	res = fstrm_control_decode(control,
				   control_frame, len_control_frame,
				   flags);
	if (res != fstrm_res_success)
		return res;

	/* Get the type. */
	if (type != NULL) {
		res = fstrm_control_get_type(control, type);
		if (res != fstrm_res_success)
			return res;
	}

	return fstrm_res_success;
}

fstrm_res
fstrm__rdwr_read_control(struct fstrm_rdwr *rdwr,
			 struct fstrm_control **control,
			 fstrm_control_type wanted_type)
{
	fstrm_res res;
	fstrm_control_type actual_type;

	if (*control == NULL)
		*control = fstrm_control_init();

	res = fstrm__rdwr_read_control_frame(rdwr, *control, &actual_type, true);
	if (res != fstrm_res_success)
		return res;

	if (actual_type != wanted_type)
		return fstrm_res_failure;

	return fstrm_res_success;
}

fstrm_res
fstrm__rdwr_write_control_frame(struct fstrm_rdwr *rdwr,
				const struct fstrm_control *control)
{
	const uint32_t flags = FSTRM_CONTROL_FLAG_WITH_HEADER;
	size_t len_control_frame = 0;
	fstrm_res res;

	/* Calculate the length of the control frame. */
	res = fstrm_control_encoded_size(control, &len_control_frame, flags);
	if (res != fstrm_res_success)
		return res;

	/* Serialize the control frame. */
	uint8_t control_frame[len_control_frame];
	res = fstrm_control_encode(control, control_frame, &len_control_frame, flags);
	if (res != fstrm_res_success)
		return res;

	/* Write the control frame. */
	struct iovec control_iov = {
		.iov_base = (void *) &control_frame[0],
		.iov_len = len_control_frame,
	};
	return fstrm_rdwr_write(rdwr, &control_iov, 1);
}

fstrm_res
fstrm__rdwr_write_control(struct fstrm_rdwr *rdwr,
			  fstrm_control_type type,
			  const fs_buf *content_type)
{
	fstrm_res res = fstrm_res_failure;
	struct fstrm_control *control = fstrm_control_init();

	res = fstrm_control_set_type(control, type);
	if (res != fstrm_res_success)
		goto out;

	if (content_type != NULL && content_type->data != NULL) {
		res = fstrm_control_add_field_content_type(control,
			content_type->data, content_type->len);
		if (res != fstrm_res_success)
			goto out;
	}

	res = fstrm__rdwr_write_control_frame(rdwr, control);
out:
	fstrm_control_destroy(&control);
	return res;
}
