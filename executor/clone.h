#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <syscall.h>


#if SYZ_EXECUTOR
// The slowdown multiplier is already taken into account.
#define USLEEP_FORKED_CHILD (3 * syscall_timeout_ms * 1000)
static long handle_clone_ret(long ret)
{
	if (ret != 0) {
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
		__atomic_store_n(&clone_ongoing, 0, __ATOMIC_RELAXED);
#endif
		return ret;
	}
	// Exit if we're in the child process - not all kernels provide the proper means
	// to prevent fork-bombs.
	// But first sleep for some time. This will hopefully foster IPC fuzzing.
	usleep(USLEEP_FORKED_CHILD);
	// Note that exit_group is a bad choice here because if we created just a thread, then
	// the whole process will be killed. A plain exit will work fine in any case.
	syscall(__NR_exit, 0);
	while (1) {
	}
}
#endif

#if SYZ_EXECUTOR || __NR_syz_clone
// syz_clone is mostly needed on kernels which do not suport clone3.
static long syz_clone(volatile long flags, volatile long stack, volatile long stack_len,
		      volatile long ptid, volatile long ctid, volatile long tls)
{
	// ABI requires 16-byte stack alignment.
	long sp = (stack + stack_len) & ~15;
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
	__atomic_store_n(&clone_ongoing, 1, __ATOMIC_RELAXED);
#endif
	// Clear the CLONE_VM flag. Otherwise it'll very likely corrupt syz-executor.
	long ret = (long)syscall(__NR_clone, flags & ~CLONE_VM, sp, ptid, ctid, tls);
	return handle_clone_ret(ret);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_clone3
#include <linux/sched.h>
#include <sched.h>
#define MAX_CLONE_ARGS_BYTES 256
static long syz_clone3(volatile long a0, volatile long a1)
{
	unsigned long copy_size = a1;
	if (copy_size < sizeof(uint64) || copy_size > MAX_CLONE_ARGS_BYTES)
		return -1;
	// The structure may have different sizes on different kernel versions, so copy it as raw bytes.
	char clone_args[MAX_CLONE_ARGS_BYTES];
	memcpy(&clone_args, (void*)a0, copy_size);

	// As in syz_clone, clear the CLONE_VM flag. Flags are in the first 8-byte integer field.
	uint64* flags = (uint64*)&clone_args;
	*flags &= ~CLONE_VM;
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
	__atomic_store_n(&clone_ongoing, 1, __ATOMIC_RELAXED);
#endif
	return handle_clone_ret((long)syscall(__NR_clone3, &clone_args, copy_size));
}
#endif