/*	$Id$ */
/*
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <unistd.h>

#include "magic.h"

int
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	/* All we accept. */
	assert(ruid == euid && euid == suid);

#ifdef HAVE_SETREUID
	if (setreuid(euid, euid) == -1) {
		warn("setreuid");
		return -1;
	}
#else
	if (seteuid(euid) == -1) {
		warn("seteuid");
		return -1;
	} else if (setuid(euid) == -1) {
		warn("setuid");
		return -1;
	}
#endif

	return 0;
}
