/* $OpenBSD: magic.h,v 1.15 2016/05/01 20:34:26 nicm Exp $ */

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

#ifndef MAGIC_H
#define MAGIC_H

#include <sys/types.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <regex.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef __dead
#define __dead
#endif
#ifndef __unused
#define __unused
#endif
#define DEF_WEAK(_x)

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#endif /* ! __APPLE__ */

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *_buf, size_t _len);
#endif
#ifndef HAVE_FREEZERO
void freezero(void *_ptr, size_t _size);
#endif
#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *_ptr, size_t _nmemb, size_t _size);
#endif
#ifndef HAVE_SETRESGID
int setresgid(gid_t _rgid, gid_t _egid, gid_t _sgid);
#endif
#ifndef HAVE_SETRESUID
int setresuid(uid_t _ruid, uid_t _euid, uid_t _suid);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *_dst, const char *_src, size_t _dstsize);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *_dst, const char *_src, size_t _dstsize);
#endif

#define MAGIC_STRING_SIZE 31
#define MAGIC_STRENGTH_MULTIPLIER 10

enum magic_type {
	MAGIC_TYPE_NONE = 0,
	MAGIC_TYPE_BYTE,
	MAGIC_TYPE_SHORT,
	MAGIC_TYPE_LONG,
	MAGIC_TYPE_QUAD,
	MAGIC_TYPE_UBYTE,
	MAGIC_TYPE_USHORT,
	MAGIC_TYPE_ULONG,
	MAGIC_TYPE_UQUAD,
	MAGIC_TYPE_FLOAT,
	MAGIC_TYPE_DOUBLE,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_PSTRING,
	MAGIC_TYPE_DATE,
	MAGIC_TYPE_QDATE,
	MAGIC_TYPE_LDATE,
	MAGIC_TYPE_QLDATE,
	MAGIC_TYPE_UDATE,
	MAGIC_TYPE_UQDATE,
	MAGIC_TYPE_ULDATE,
	MAGIC_TYPE_UQLDATE,
	MAGIC_TYPE_BESHORT,
	MAGIC_TYPE_BELONG,
	MAGIC_TYPE_BEQUAD,
	MAGIC_TYPE_UBESHORT,
	MAGIC_TYPE_UBELONG,
	MAGIC_TYPE_UBEQUAD,
	MAGIC_TYPE_BEFLOAT,
	MAGIC_TYPE_BEDOUBLE,
	MAGIC_TYPE_BEDATE,
	MAGIC_TYPE_BEQDATE,
	MAGIC_TYPE_BELDATE,
	MAGIC_TYPE_BEQLDATE,
	MAGIC_TYPE_UBEDATE,
	MAGIC_TYPE_UBEQDATE,
	MAGIC_TYPE_UBELDATE,
	MAGIC_TYPE_UBEQLDATE,
	MAGIC_TYPE_BESTRING16,
	MAGIC_TYPE_LESHORT,
	MAGIC_TYPE_LELONG,
	MAGIC_TYPE_LEQUAD,
	MAGIC_TYPE_ULESHORT,
	MAGIC_TYPE_ULELONG,
	MAGIC_TYPE_ULEQUAD,
	MAGIC_TYPE_LEFLOAT,
	MAGIC_TYPE_LEDOUBLE,
	MAGIC_TYPE_LEDATE,
	MAGIC_TYPE_LEQDATE,
	MAGIC_TYPE_LELDATE,
	MAGIC_TYPE_LEQLDATE,
	MAGIC_TYPE_ULEDATE,
	MAGIC_TYPE_ULEQDATE,
	MAGIC_TYPE_ULELDATE,
	MAGIC_TYPE_ULEQLDATE,
	MAGIC_TYPE_LESTRING16,
	MAGIC_TYPE_MELONG,
	MAGIC_TYPE_MEDATE,
	MAGIC_TYPE_MELDATE,
	MAGIC_TYPE_REGEX,
	MAGIC_TYPE_SEARCH,
	MAGIC_TYPE_DEFAULT,
	MAGIC_TYPE_CLEAR,
	MAGIC_TYPE_NAME,
	MAGIC_TYPE_USE,
};

TAILQ_HEAD(magic_lines, magic_line);
RB_HEAD(magic_tree, magic_line);
RB_HEAD(magic_named_tree, magic_line);

struct magic_line {
	struct magic		*root;
	u_int			 line;
	u_int			 strength;
	struct magic_line	*parent;

	char			 strength_operator;
	u_int			 strength_value;

	int			 text;

	int64_t			 offset;
	int			 offset_relative;

	char			 indirect_type;
	int			 indirect_relative;
	int64_t			 indirect_offset;
	char			 indirect_operator;
	int64_t			 indirect_operand;

	const char		*name;

	enum magic_type		 type;
	const char		*type_string;
	char			 type_operator;
	int64_t			 type_operand;

	char			 test_operator;
	int			 test_not;
	const char		*test_string;
	size_t			 test_string_size;
	uint64_t		 test_unsigned;
	int64_t			 test_signed;
	double			 test_double;

	int			 stringify;
	const char		*result;
	const char		*mimetype;

	struct magic_lines	 children;
	TAILQ_ENTRY(magic_line)	 entry;
	RB_ENTRY(magic_line)	 node;
};

struct magic {
	const char		*path;
	int			 warnings;

	struct magic_tree	 tree;
	struct magic_named_tree	 named;

	int			 compiled;
	regex_t			 format_short;
	regex_t			 format_long;
	regex_t			 format_quad;
	regex_t			 format_float;
	regex_t			 format_string;
};

struct magic_state {
	char			 out[4096];
	const char		*mimetype;
	int			 text;

	const char		*base;
	size_t			 size;
	size_t			 offset;
	int			 matched;

	size_t			 start;
	int			 reverse;
};

#define MAGIC_TEST_TEXT 0x1
#define MAGIC_TEST_MIME 0x2

int		 magic_compare(struct magic_line *, struct magic_line *);
RB_PROTOTYPE(magic_tree, magic_line, node, magic_compare);

int		 magic_named_compare(struct magic_line *, struct magic_line *);
RB_PROTOTYPE(magic_named_tree, magic_line, node, magic_named_compare);

char		*magic_strtoull(const char *, uint64_t *);
char		*magic_strtoll(const char *, int64_t *);
void		 magic_vwarnm(struct magic *, u_int, const char *, va_list);
void		 magic_warnm(struct magic *, u_int, const char *, ...)
		     __attribute__ ((format (printf, 3, 4)));
void		 magic_warn(struct magic_line *, const char *, ...)
		     __attribute__ ((format (printf, 2, 3)));

void		 magic_dump(struct magic *);
struct magic	*magic_load(FILE *, const char *, int);
const char	*magic_test(struct magic *, const void *, size_t, int);

#endif /* MAGIC_H */
