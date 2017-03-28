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

#ifdef HAVE_PRCTL
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <stddef.h> /* offsetof */

/* Linux seccomp_filter sandbox */
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ifdef SANDBOX_DEBUG
#undef SECCOMP_FILTER_FAIL
#define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#endif

/* XXX: */
#ifndef SECCOMP_AUDIT_ARCH
#if defined __i386__
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
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <err.h>

#include "file.h"
#include "magic.h"
#include "xmalloc.h"

/* Syscall filtering set for child. */
static const struct sock_filter child_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, nr)),
	SC_DENY(__NR_open, EACCES),
	SC_ALLOW(__NR_brk),
	SC_ALLOW(__NR_close),
	SC_ALLOW(__NR_exit_group),
	SC_ALLOW(__NR_fstat),
#ifdef SYS_fstat64
	SC_ALLOW(__NR_fstat64),
#endif
#ifdef SYS_getpagesize
	SC_ALLOW(__NR_getpagesize),
#endif
#if defined(SANDBOX_DEBUG)
#ifdef SYS_lseek
	SC_ALLOW(__NR_lseek),
#endif
#ifdef SYS__llseek
	SC_ALLOW(__NR__llseek),
#endif
#endif /* SANDBOX_DEBUG */
#ifdef SYS_mmap
	SC_ALLOW(__NR_mmap),
#endif
#ifdef SYS_mmap2
	SC_ALLOW(__NR_mmap2),
#endif
	SC_ALLOW(__NR_munmap),
	SC_ALLOW(__NR_read),
	SC_ALLOW(__NR_recvmsg),
	SC_ALLOW(__NR_sendmsg),
	SC_ALLOW(__NR_write),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_fprog child_program = {
	.len = (unsigned short)(sizeof(child_insns)/sizeof(child_insns[0])),
	.filter = (struct sock_filter *)child_insns,
};

#ifdef SANDBOX_DEBUG
static void
sandbox_violation(int signum, siginfo_t *info, void *void_context)
{
	dprintf(STDOUT_FILENO,
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)\n",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	_exit(1);
}
#endif /* SANDBOX_DEBUG */

static void
sandbox_child_debugging(void)
{
#ifdef SANDBOX_DEBUG
	struct sigaction act;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &act, NULL) == -1)
		err(1, "sigaction(SIGSYS)");
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
		err(1, "sigprocmask(SIGSYS)");
#endif /* SANDBOX_DEBUG */
}

void
sandbox_child(void)
{
	sandbox_child_debugging();
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		err(1, "prctl(PR_SET_NO_NEW_PRIVS)");
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
	    &child_program) == -1)
		err(1, "prctl(PR_SET_SECCOMP/SECCOMP_MODE_FILTER)");
}

#endif /* HAVE_PRCTL */
