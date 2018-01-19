/*
 * Shared library add-on to iptables to add early socket matching support.
 *
 * Copyright (C) 2000-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 */
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_socket_kzorp.h>

enum {
	O_TRANSPARENT = 0,
	O_NOWILDCARD = 1,
	O_MARK = 2,
};

static const struct xt_option_entry socket_mt_opts[] = {
	{.name = "transparent", .id = O_TRANSPARENT, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static const struct xt_option_entry socket_mt_opts_v2[] = {
	{.name = "transparent", .id = O_TRANSPARENT, .type = XTTYPE_NONE},
	{.name = "nowildcard", .id = O_NOWILDCARD, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static const struct xt_option_entry socket_mt_opts_v3[] = {
	{.name = "transparent", .id = O_TRANSPARENT, .type = XTTYPE_NONE},
	{.name = "nowildcard", .id = O_NOWILDCARD, .type = XTTYPE_NONE},
	{.name = "mark", .id = O_MARK, .type = XTTYPE_MARKMASK32, .flags = XTOPT_INVERT},
	XTOPT_TABLEEND,
};

static void socket_mt_help(void)
{
	printf(
		"socket match options:\n"
		"  --transparent    Ignore non-transparent sockets\n\n");
}

static void socket_mt_help_v2(void)
{
	printf(
		"socket match options:\n"
		"  --nowildcard     Do not ignore LISTEN sockets bound on INADDR_ANY\n"
		"  --transparent    Ignore non-transparent sockets\n\n");
}

static void socket_mt_help_v3(void)
{
	printf(
		"socket match options:\n"
		"  --nowildcard              Do not ignore LISTEN sockets bound on INADDR_ANY\n"
		" [!] --mark value[/mask]    Match nfmark value with optional mask\n"
		"  --transparent             Ignore non-transparent sockets\n\n");
}

static void socket_mt_parse(struct xt_option_call *cb)
{
	struct xt_socket_mtinfo1 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKET_TRANSPARENT;
		break;
	}
}

static void socket_mt_parse_v2(struct xt_option_call *cb)
{
	struct xt_socket_mtinfo2 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKET_TRANSPARENT;
		break;
	case O_NOWILDCARD:
		info->flags |= XT_SOCKET_NOWILDCARD;
		break;
	}
}

static void socket_mark_mt_parse(struct xt_option_call *cb)
{
	struct xt_socket_mtinfo3 *info = cb->data;

	if (cb->invert)
		info->invert = true;
	info->mark = cb->val.mark;
	info->mask = cb->val.mask;
}

static void socket_mt_parse_v3(struct xt_option_call *cb)
{
	struct xt_socket_mtinfo3 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKET_TRANSPARENT;
		break;
	case O_NOWILDCARD:
		info->flags |= XT_SOCKET_NOWILDCARD;
		break;
	case O_MARK:
		info->flags |= XT_SOCKET_MARK;
		socket_mark_mt_parse(cb);
		break;
	}
}

static void
socket_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socket_mtinfo1 *info = (const void *)match->data;

	if (info->flags & XT_SOCKET_TRANSPARENT)
		printf(" --transparent");
}

static void
socket_mt_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	printf(" socket_kzorp");
	socket_mt_save(ip, match);
}

static void
socket_mt_save_v2(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socket_mtinfo2 *info = (const void *)match->data;

	if (info->flags & XT_SOCKET_TRANSPARENT)
		printf(" --transparent");
	if (info->flags & XT_SOCKET_NOWILDCARD)
		printf(" --nowildcard");
}

static void
socket_mt_print_v2(const void *ip, const struct xt_entry_match *match,
		   int numeric)
{
	printf(" socket_kzorp");
	socket_mt_save_v2(ip, match);
}

static void print_socket_mark(unsigned int mark, unsigned int mask)
{
	if (mask != 0xffffffffU)
		printf(" 0x%x/0x%x", mark, mask);
	else
		printf(" 0x%x", mark);
}

static void socket_mark_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socket_mtinfo3 *info = (const void *)match->data;

	if (info->invert)
		printf(" !");

	printf(" --mark");
	print_socket_mark(info->mark, info->mask);
}

static void
socket_mt_save_flags_v3(__u8 flags)
{
	if (flags & XT_SOCKET_TRANSPARENT)
		printf(" --transparent");
	if (flags & XT_SOCKET_NOWILDCARD)
		printf(" --nowildcard");
}

static void
socket_mt_save_v3(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socket_mtinfo3 *info = (const void *)match->data;

	socket_mt_save_flags_v3(info->flags);
	if (info->flags & XT_SOCKET_MARK)
		socket_mark_mt_save(ip, match);
}

static void
socket_mark_mt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_socket_mtinfo3 *info = (const void *)match->data;

	printf(" mark match");
	if (info->invert)
		printf(" !");
	print_socket_mark(info->mark, info->mask);
}

static void
socket_mt_print_v3(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_socket_mtinfo3 *info = (const void *)match->data;

	printf(" socket");
	socket_mt_save_flags_v3(info->flags);
	socket_mark_mt_print(ip, match, numeric);
}

static struct xtables_match socket_mt_reg[] = {
	{
		.name          = "socket_kzorp",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(0),
		.userspacesize = XT_ALIGN(0),
	},
	{
		.name          = "socket_kzorp",
		.revision      = 1,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socket_mtinfo1)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socket_mtinfo1)),
		.help          = socket_mt_help,
		.print         = socket_mt_print,
		.save          = socket_mt_save,
		.x6_parse      = socket_mt_parse,
		.x6_options    = socket_mt_opts,
	},
	{
		.name          = "socket_kzorp",
		.revision      = 2,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socket_mtinfo2)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socket_mtinfo2)),
		.help          = socket_mt_help_v2,
		.print         = socket_mt_print_v2,
		.save          = socket_mt_save_v2,
		.x6_parse      = socket_mt_parse_v2,
		.x6_options    = socket_mt_opts_v2,
	},
	{
		.name          = "socket_kzorp",
		.revision      = 3,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socket_mtinfo3)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socket_mtinfo3)),
		.help          = socket_mt_help_v3,
		.print         = socket_mt_print_v3,
		.save          = socket_mt_save_v3,
		.x6_parse      = socket_mt_parse_v3,
		.x6_options    = socket_mt_opts_v3,
	},
};

void _init(void)
{
	xtables_register_matches(socket_mt_reg, ARRAY_SIZE(socket_mt_reg));
}
