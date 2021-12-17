#ifndef MY_MEMORY_BARRIER_H
#define MY_MEMORY_BARRIER_H

#if defined(__GNUC__)
# if defined(__x86_64__)
#  define MY_HAVE_MEMORY_BARRIERS 1
#  define smp_mb()	asm volatile("mfence" ::: "memory")
#  define smp_rmb()	asm volatile("" ::: "memory")
#  define smp_wmb()	asm volatile("" ::: "memory")
# elif defined(__ia64__)
#  define MY_HAVE_MEMORY_BARRIERS 1
#  define smp_mb()	asm volatile ("mf" ::: "memory")
#  define smp_rmb()	asm volatile ("mf" ::: "memory")
#  define smp_wmb()	asm volatile ("mf" ::: "memory")
# endif
#endif

#endif /* MY_MEMORY_BARRIER_H */
