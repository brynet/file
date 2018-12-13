/* $OpenBSD: sandbox.c,v 1.9 2015/08/23 18:31:41 guenther Exp $ */

/*
 * Copyright (c) 2012 Will Drewry <wad@dataspill.org>
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Linux seccomp_filter sandbox */

#ifdef HAVE_PRCTL
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <stddef.h> /* offsetof */

/* XXX: */
#ifndef SECCOMP_AUDIT_ARCH
#if defined __arm__
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined __i386__
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined __x86_64__ || defined __amd64__
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#endif
#endif /* SECCOMP_AUDIT_ARCH */

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#include <errno.h>
#include <err.h>

/* Syscall filtering set */
static const struct sock_filter filt_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, nr)),

	/* Syscalls to non-fatally deny. */
#ifdef __NR_open
	SC_DENY(__NR_open, EACCES),
#endif
#ifdef __NR_openat
	SC_DENY(__NR_openat, EACCES),
#endif
	/*
	 * Newer glibc versions do ioctl(.., TCGETS) internally.
	 * OpenBSD 5.8 replaced isatty(3) with a fcntl(2) implementation
	 * to avoid ioctl(2) calls for libc stdio.
	 */
#ifdef __NR_ioctl
	SC_DENY(__NR_ioctl, ENOTTY),
#endif

	/* Syscalls to permit. */
#ifdef __NR_brk
	SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_close
	SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_fstat
	SC_ALLOW(__NR_fstat),
#endif
#ifdef __NR_fstat64
	SC_ALLOW(__NR_fstat64),
#endif
#ifdef __NR_getpid
	SC_ALLOW(__NR_getpid),
#endif
#ifdef __NR_mmap
	SC_ALLOW(__NR_mmap),
#endif
#ifdef __NR_mmap2
	SC_ALLOW(__NR_mmap2),
#endif
#ifdef __NR_munmap
	SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_read
	SC_ALLOW(__NR_read),
#endif
#ifdef __NR_recvmsg
	SC_ALLOW(__NR_recvmsg),
#endif
#ifdef __NR_sendmsg
	SC_ALLOW(__NR_sendmsg),
#endif
#ifdef __NR_wait
	SC_ALLOW(__NR_wait),
#endif
#ifdef __NR_write
	SC_ALLOW(__NR_write),
#endif

	/* Default deny. */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};

static const struct sock_fprog filt_program = {
	.len = (unsigned short)(sizeof(filt_insns)/sizeof(filt_insns[0])),
	.filter = (struct sock_filter *)filt_insns,
};

void
sandbox_seccomp(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		err(1, "prctl(PR_SET_NO_NEW_PRIVS)");
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
	    &filt_program) == -1)
		err(1, "prctl(PR_SET_SECCOMP/SECCOMP_MODE_FILTER)");
}

#endif /* HAVE_PRCTL */
