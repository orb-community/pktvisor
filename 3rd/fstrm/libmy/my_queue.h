#ifndef MY_QUEUE_H
#define MY_QUEUE_H

#include <stdbool.h>

/**
 * \file
 *
 * Fixed-size single-producer / single-consumer queue.
 *
 * This is a generic queue that supports a single producer thread and a
 * single consumer thread. The implementation uses a fixed power-of-2 size
 * circular buffer.
 *
 * The my_queue_insert() and my_queue_remove() functions are "non-blocking";
 * that is, the policies for queue full / queue empty conditions are left to
 * the caller.  These functions return a boolean indicating whether the queue
 * operation succeeded or not. For example, a producer that spins until an
 * element is successfully enqueued might look like:
 *
 *	void *item;
 *	produce_item(&item);
 *	while (!my_queue_insert(q, item, NULL));
 *
 * And a consumer that spins until an element is successfully dequeued
 * might look like:
 *
 *	void *item;
 *	while (!my_queue_remove(q, &item, NULL));
 *	consume_item(item);
 *
 * The my_queue_insert() and my_queue_remove() functions take an optional third
 * parameter for returning the spaces remaining in the queue or the count of
 * elements remaining, respectively. This allows for more complicated
 * coordination between producer and consumer, for instance a consumer thread
 * that sleeps when the queue is empty and is woken by the producer when it
 * adds an element to an empty queue.
 */

struct my_queue;

/**
 * Initialize a new queue.
 *
 * \param[in] num_entries Number of elements in the queue. Must be >=2, and a power-of-2.
 * \param[in] size_entry Size in bytes of each queue entry.
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
struct my_queue *
my_queue_init(unsigned num_entries, unsigned size_entry);

/**
 * Destroy a queue.
 */
void
my_queue_destroy(struct my_queue **q);

/**
 * Describe the queue implementation type.
 */
const char *
my_queue_impl_type(void);

/**
 * Insert an element into the queue.
 *
 * \param[in] q Queue object.
 * \param[in] elem Element object.
 * \param[out] space If non-NULL, pointer to store the number of remaining
 *	spaces in the queue.
 * \return true if the element was inserted into the queue,
 *	false if the queue is full.
 */
bool
my_queue_insert(struct my_queue *q, void *elem, unsigned *space);

/**
 * Remove an element from the queue.
 *
 * \param[in] q Queue object.
 * \param[out] elem Where the element object will be copied.
 * \param[out] count If non-NULL, pointer to store the count of elements
 *	remaining in the queue.
 * \return true if an element was removed from the queue,
 *	false if the queue is empty.
 */
bool
my_queue_remove(struct my_queue *q, void *elem, unsigned *count);

struct my_queue_ops {
	struct my_queue *(*init)(unsigned, unsigned);
	void (*destroy)(struct my_queue **);
	const char *(*impl_type)(void);
	bool (*insert)(struct my_queue *, void *, unsigned *);
	bool (*remove)(struct my_queue *, void *, unsigned *);
};

#endif /* MY_QUEUE_H */
