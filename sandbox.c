/* $OpenBSD: sandbox.c,v 1.2 2015/04/29 06:37:14 deraadt Exp $ */

/*
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifdef __OpenBSD__
#include <dev/systrace.h>
#elif __linux
#include <sys/resource.h>
#include <sys/prctl.h>

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
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ ## _nr, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ ## _nr, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#endif

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include "file.h"
#include "magic.h"
#include "xmalloc.h"

#ifdef __OpenBSD__
static const struct
{
	int syscallnum;
	int action;
} allowed_syscalls[] = {
	{ SYS_open, SYSTR_POLICY_NEVER }, /* for strerror */

	{ SYS_close, SYSTR_POLICY_PERMIT },
	{ SYS_exit, SYSTR_POLICY_PERMIT },
	{ SYS_getdtablecount, SYSTR_POLICY_PERMIT },
	{ SYS_getentropy, SYSTR_POLICY_PERMIT },
	{ SYS_getpid, SYSTR_POLICY_PERMIT },
	{ SYS_getrlimit, SYSTR_POLICY_PERMIT },
	{ SYS_issetugid, SYSTR_POLICY_PERMIT },
	{ SYS_madvise, SYSTR_POLICY_PERMIT },
	{ SYS_mmap, SYSTR_POLICY_PERMIT },
	{ SYS_mprotect, SYSTR_POLICY_PERMIT },
	{ SYS_mquery, SYSTR_POLICY_PERMIT },
	{ SYS_munmap, SYSTR_POLICY_PERMIT },
	{ SYS_read, SYSTR_POLICY_PERMIT },
	{ SYS_recvmsg, SYSTR_POLICY_PERMIT },
	{ SYS_sendmsg, SYSTR_POLICY_PERMIT },
	{ SYS_sigprocmask, SYSTR_POLICY_PERMIT },
	{ SYS_write, SYSTR_POLICY_PERMIT },

	{ -1, -1 }
};

static int
sandbox_find(int syscallnum)
{
	int	i;

	for (i = 0; allowed_syscalls[i].syscallnum != -1; i++) {
		if (allowed_syscalls[i].syscallnum == syscallnum)
			return (allowed_syscalls[i].action);
	}
	return (SYSTR_POLICY_KILL);
}
#elif __linux
/* Syscall filtering set for preauth. */
static const struct sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, nr)),
	SC_DENY(open, EACCES),
	SC_ALLOW(brk),
	SC_ALLOW(close),
	SC_ALLOW(exit_group),
	SC_ALLOW(fstat),
	SC_ALLOW(getpid),
	SC_ALLOW(mmap),
	SC_ALLOW(munmap),
	SC_ALLOW(read),
	SC_ALLOW(recvmsg),
	SC_ALLOW(sendmsg),
	SC_ALLOW(write),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_fprog preauth_program = {
	.len = (unsigned short)(sizeof(preauth_insns)/sizeof(preauth_insns[0])),
	.filter = (struct sock_filter *)preauth_insns,
};

#ifdef SANDBOX_DEBUG
static void
sandbox_violation(int signum, siginfo_t *info, void *void_context)
{
	char msg[256];

	snprintf(msg, sizeof(msg),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)\n",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	write(STDOUT_FILENO, msg, strlen(msg));
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
#endif /* __OpenBSD__ */

static int
sandbox_child(const char *user)
{
	struct passwd	*pw;

	/*
	 * If we don't set streams to line buffered explicitly, stdio uses
	 * isatty() which means ioctl() - too nasty to let through the systrace
	 * policy.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	if (geteuid() == 0) {
		pw = getpwnam(user);
		if (pw == NULL) {
			pw = getpwnam("nobody");
			if (pw == NULL)
				errx(1, "unknown user %s, or 'nobody'", user);
		}
		if (setgroups(1, &pw->pw_gid) != 0)
			err(1, "setgroups");
		if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0)
			err(1, "setresgid");
		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0)
			err(1, "setresuid");
	}

#ifdef __linux
	sandbox_child_debugging();
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		err(1, "prctl(PR_SET_NO_NEW_PRIVS)");
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
	    &preauth_program) == -1)
		err(1, "prctl(PR_SET_SECCOMP/SECCOMP_MODE_FILTER)");
#else
	if (kill(getpid(), SIGSTOP) != 0)
		err(1, "kill(SIGSTOP)");
#endif
	return (0);
}

int
sandbox_fork(const char *user)
{
	pid_t			 pid;
	int			 status, fd, i;
#ifdef __OpenBSD__
	int			 devfd;
	struct systrace_policy	 policy;
#endif

	switch (pid = fork()) {
	case -1:
		err(1, "fork");
	case 0:
		return (sandbox_child(user));
	}

#ifndef __linux
	do {
		pid = waitpid(pid, &status, WUNTRACED);
	} while (pid == -1 && errno == EINTR);
	if (!WIFSTOPPED(status))
		errx(1, "child not stopped");
#endif

#ifdef __OpenBSD__
	devfd = open("/dev/systrace", O_RDONLY);
	if (devfd == -1)
		err(1, "open(\"/dev/systrace\")");
	if (ioctl(devfd, STRIOCCLONE, &fd) == -1)
		err(1, "ioctl(STRIOCCLONE)");
	close(devfd);

	if (ioctl(fd, STRIOCATTACH, &pid) == -1)
		err(1, "ioctl(STRIOCATTACH)");

	memset(&policy, 0, sizeof policy);
	policy.strp_op = SYSTR_POLICY_NEW;
	policy.strp_maxents = SYS_MAXSYSCALL;
	if (ioctl(fd, STRIOCPOLICY, &policy) == -1)
		err(1, "ioctl(STRIOCPOLICY/NEW)");
	policy.strp_op = SYSTR_POLICY_ASSIGN;
	policy.strp_pid = pid;
	if (ioctl(fd, STRIOCPOLICY, &policy) == -1)
		err(1, "ioctl(STRIOCPOLICY/ASSIGN)");

	for (i = 0; i < SYS_MAXSYSCALL; i++) {
		policy.strp_op = SYSTR_POLICY_MODIFY;
		policy.strp_code = i;
		policy.strp_policy = sandbox_find(i);
		if (ioctl(fd, STRIOCPOLICY, &policy) == -1)
			err(1, "ioctl(STRIOCPOLICY/MODIFY)");
	}
#elif !__linux
	if (kill(pid, SIGCONT) != 0)
		err(1, "kill(SIGCONT)");
#endif /* __OpenBSD__ */
	return (pid);
}
