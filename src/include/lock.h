#ifndef __LOCK_H__
#define __LOCK_H__

#include <stdatomic.h>

typedef _Atomic int lock_t;

//   we use setLock(), release() in circumstances where we don't care of race.
// program use setLock() to set a lock without blocking, then use spin*() to 
// wait for it to release. here we ensure that the wait process won't end 
// before release() is called. the race conditions will result in at most one
// redundant isLocked() call.
//   we use lock(), release() in circumstances where we care of race. it's 
// actually a standard spin lock.

static inline void release(lock_t *plock)
{
    atomic_thread_fence(memory_order_seq_cst);
    atomic_signal_fence(memory_order_seq_cst);

    atomic_store(plock, 0);
}
static inline int tryLock(lock_t *plock)
{
    lock_t ex = 0, de = 1;
    return atomic_compare_exchange_strong(plock, &ex, de);
}
static inline void lock(lock_t *plock)
{
    while (!tryLock(plock));
}
static inline int isLocked(lock_t *plock)
{
    atomic_thread_fence(memory_order_seq_cst);
    atomic_signal_fence(memory_order_seq_cst);

    return atomic_load(plock);
}
static inline void setLock(lock_t *plock)
{
    atomic_thread_fence(memory_order_seq_cst);
    atomic_signal_fence(memory_order_seq_cst);

    atomic_store(plock, 1);
}
static inline void spin(lock_t *plock)
{
    while (isLocked(plock));
}
static inline void spinAND(lock_t *plock1, lock_t *plock2)
{
    while (isLocked(plock1) && isLocked(plock2));
}
static inline void spinAND3(lock_t *plock1, lock_t *plock2, lock_t *plock3)
{
    while (isLocked(plock1) && isLocked(plock2) && isLocked(plock3));
}

#endif