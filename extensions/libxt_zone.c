/*
 * Shared library add-on to iptables to match
 * packets based on KZorp zones
 *
 * Copyright (C) 2006-2009, BalaBit IT Ltd.
 * Author: KOVACS Krisztian <hidden@balabit.hu>,
 *         TOTH Laszlo Attila <panther@balabit.hu>
 */
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_zone.h"

static void zone_help_v0(void)
{
	printf(
"zone v%s options:\n"
" --src-zone zone	Match source zone\n"
" --dst-zone zone	Match destination zone\n"
" --children		Administrative children should match, too\n"
" --umbrella		Do not cross umbrella boundaries\n"
"NOTE: this kernel doesn't support multiple zones\n",
XTABLES_VERSION);
}

static void zone_help_v1(void)
{
	printf(
"zone v%s options:\n"
" --source-zones zone[,zone,zone,...]\n"
" --src-zones ...\n"
" --szones ...\n"
"			Match source zone(s)\n"
" --destination-zone zone[,zone,zone,...]\n"
" --dst-zones ...\n"
" --dzones ...\n"
"			Match destination zone(s)\n"
"  --children		Administrative children should match, too\n"
"  --umbrella		Do not cross umbrella boundaries\n",
XTABLES_VERSION);
}

static void zone_help_v2(void)
{
	printf(
"zone v%s options:\n"
" --source-zones zone[,zone,zone,...]\n"
" --src-zones ...\n"
" --szones ...\n"
"			Match source zone(s)\n"
" --destination-zones zone[,zone,zone,...]\n"
" --dst-zones ...\n"
" --dzones ...\n"
"			Match destination zone(s)\n"
"  --children		Administrative children should match, too\n"
"  --nocount		do not count matching zones\n",
XTABLES_VERSION);
}


static struct option zone_opts_v0[] = {
	{ .name = "src-zone", .has_arg = true, .val = '1' },
	{ .name = "dst-zone", .has_arg = true, .val = '2' },
	{ .name = "children", .has_arg = false, .val = '3' },
	{ .name = "umbrella", .has_arg = false, .val = '4' },
	{ .name = NULL }
};

static struct option zone_opts_v1[] = {
	{ .name = "source-zones", .has_arg = true, .val = '1' },
	{ .name = "src-zones", .has_arg = true, .val = '1' },
	{ .name = "src-zone", .has_arg = true, .val = '1' }, /* For backward compatibility */
	{ .name = "szones", .has_arg = true, .val = '1' },
	{ .name = "destination-zones", .has_arg = true, .val = '2' },
	{ .name = "dst-zones", .has_arg = true, .val = '2' },
	{ .name = "dst-zone", .has_arg = true, .val = '2' }, /* For backward compatibility */
	{ .name = "dzones", .has_arg = true, .val = '2' },
	{ .name = "children", .has_arg = false, .val = '3' },
	{ .name = "umbrella", .has_arg = false, .val = '4' },
	{ .name = NULL }
};

enum {
	O_SRC		= 0,
	O_DST		= 1,
	O_CHILDREN	= 2,
	O_UMBRELLA	= 3,
	O_NOCOUNT	= 4,
	F_SRC		= 1 << O_SRC,
	F_DST		= 1 << O_DST,
	F_CHILDREN	= 1 << O_CHILDREN,
	F_UMBRELLA	= 1 << O_UMBRELLA,
	F_NOCOUNT	= 1 << O_NOCOUNT,
};

static struct xt_option_entry zone_opts_v2[] = {
	{ .name = "source-zones",	.id = O_SRC,		.type = XTTYPE_STRING,	.excl = F_DST },
	{ .name = "src-zones",		.id = O_SRC,		.type = XTTYPE_STRING,	.excl = F_DST },
	{ .name = "szones",		.id = O_SRC,		.type = XTTYPE_STRING,	.excl = F_DST },
	{ .name = "destination-zones",	.id = O_DST,		.type = XTTYPE_STRING,	.excl = F_SRC },
	{ .name = "dst-zones",		.id = O_DST,		.type = XTTYPE_STRING,	.excl = F_SRC },
	{ .name = "dzones",		.id = O_DST,		.type = XTTYPE_STRING,	.excl = F_SRC },
	{ .name = "children",		.id = O_CHILDREN,	.type = XTTYPE_NONE },
	{ .name = "nocount",  		.id = O_NOCOUNT,	.type = XTTYPE_NONE },
	XTOPT_TABLEEND,
};


static unsigned int
parse_zone_names(const char *zonestring, struct xt_zone_info_v1 *info, size_t max_length)
{
	char *buffer, *cp, *next;
	unsigned int i;

	buffer = strdup(zonestring);
	if (!buffer) xtables_error(OTHER_PROBLEM, "strdup failed");

	for (cp=buffer, i=0; cp && i<XT_ZONE_NAME_COUNT; cp=next,++i) {
		next=strchr(cp, ',');
		if (next) *next++='\0';

		while (isspace(*cp)) cp++;

		strncpy((char *)info->names[i], cp, max_length);
		info->names[i][max_length] = '\0';
	}
	if (cp) xtables_error(PARAMETER_PROBLEM, "too many zones specified");
	free(buffer);
	return i;
}

static int
zone_parse_v0(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct xt_zone_info *info = (struct xt_zone_info *) (*match)->data;

	switch (c)
	{
	case '1': /* src-zone */
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--src-zone' "
				   "more than once\n");
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--src-zone' "
				   "together with `--dst-zone'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
			           "`--src-zone' must be accompanied by "
				   "a zone name\n");

		strncpy((char *)info->name, optarg, sizeof(info->name));
		info->name[XT_ZONE_NAME_LENGTH] = '\0';
		info->flags |= XT_ZONE_SRC;

		*flags |= F_SRC;
		break;

	case '2': /* dst-zone */
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--dst-zone' "
				   "more than once\n");
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--dst-zone' "
				   "together with `--src-zone'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
			           "`--dst-zone' must be accompanied by "
				   "a zone name\n");

		strncpy((char *)info->name, optarg, sizeof(info->name));
		info->name[XT_ZONE_NAME_LENGTH] = '\0';

		*flags |= F_DST;
		break;

	case '3':
		if (*flags & F_CHILDREN)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--children' "
				   "more than once\n");

		info->flags |= XT_ZONE_CHILDREN;

		*flags |= F_CHILDREN;
		break;

	case '4':
		if (*flags & F_UMBRELLA)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--umbrella' "
				   "more than once\n");

		info->flags |= XT_ZONE_UMBRELLA;

		*flags |= F_UMBRELLA;
		break;

	default:
		return 0;
	}

	return 1;
}

static int
zone_parse_v1(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct xt_zone_info_v1 *info = (struct xt_zone_info_v1 *) (*match)->data;

	switch (c)
	{
	case '1': /* src-zone */
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--source-zones' "
				   "more than once\n");
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--source-zones' "
				   "together with `--destination-zones'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--source-zones' must be accompanied "
				   "by a zone name\n");

		info->count = parse_zone_names(optarg,
		                               info,
					       sizeof(info->names[0]) - 1);
		info->flags |= XT_ZONE_SRC;

		*flags |= F_SRC;
		break;

	case '2': /* dst-zone */
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--destination-zones' "
				   "more than once\n");
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--destination-zones' "
				   "together with `--source-zones'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--destination-zones' must be accompanied "
				   "by a zone name\n");

		info->count = parse_zone_names(optarg,
					       info,
					       sizeof(info->names[0]) - 1);

		*flags |= F_DST;
		break;

	case '3':
		if (*flags & F_CHILDREN)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--children' "
				   "more than once\n");

		info->flags |= XT_ZONE_CHILDREN;

		*flags |= F_CHILDREN;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
zone_parse_zones(struct xt_zone_info_v1 *info, u_int8_t zone_type_flag)
{
	info->count = parse_zone_names(optarg,
	                               info,
				       sizeof(info->names[0]) - 1);
	if (zone_type_flag == F_SRC)
		info->flags |= XT_ZONE_SRC;
}

static void
zone_parse_v2 (struct xt_option_call *cb)
{
	struct xt_zone_info_v1 *info = cb->data;

	xtables_option_parse(cb);

	switch (cb->entry->id) {
	case O_SRC:
		zone_parse_zones(info, F_SRC);
		break;

	case O_DST:
		zone_parse_zones(info, F_DST);
		break;

	case O_CHILDREN:
		info->flags |= XT_ZONE_CHILDREN;
		break;

	case O_UMBRELLA:
		info->flags |= XT_ZONE_UMBRELLA;
		break;

	case O_NOCOUNT:
		info->flags |= XT_ZONE_NOCOUNT;
		break;
	}
}

static void
zone_final_check(unsigned int flags)
{
	if (!(flags & (F_SRC | F_DST)))
		xtables_error(PARAMETER_PROBLEM,
		           "You must specify either `--src-zone' "
			   "or `--dst-zone'\n");
	if ((flags & F_UMBRELLA) && !(flags & F_CHILDREN))
		xtables_error(PARAMETER_PROBLEM,
		           "Cannot specify `--umbrella' "
			   "without `--children'\n");
}

static void
zone_final_check_v2(struct xt_fcheck_call *cb)
{	
	if (!(cb->xflags & (F_SRC | F_DST)))
		xtables_error(PARAMETER_PROBLEM,
		           "You must specify either `--src-zone' "
			   "or `--dst-zone'\n");
}

static void
zone_print_v0(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_zone_info *info = (struct xt_zone_info *) match->data;

	if (info->flags & XT_ZONE_SRC)
		fputs(" source", stdout);
	else
		fputs(" destination", stdout);
	printf(" zone \"%s\"", info->name);

	if (info->flags & XT_ZONE_CHILDREN)
		fputs(" children", stdout);

	if (info->flags & XT_ZONE_UMBRELLA)
		fputs(" umbrella", stdout);
}

static void
zone_print_v1(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_zone_info_v1 *info = (struct xt_zone_info_v1 *) match->data;
	int i;

	if (info->flags & XT_ZONE_SRC)
		fputs(" source", stdout);
	else
		fputs(" destination", stdout);
	printf(" zones \"");

	for (i = 0; i!=info->count; ++i)
		printf ("%s%s", i ? "," : "", info->names[i]);

	printf("\"");

	if (info->flags & XT_ZONE_CHILDREN)
		fputs(" children", stdout);

	if (info->flags & XT_ZONE_UMBRELLA)
		fputs(" umbrella", stdout);
}

static void
zone_print_v2(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_zone_info *info = (struct xt_zone_info *) match->data;

	zone_print_v1(ip, match, numeric);

	if (info->flags & XT_ZONE_NOCOUNT)
		fputs(" nocount", stdout);
}

static void
zone_save_v0(const void *ip, const struct xt_entry_match *match)
{
	struct xt_zone_info *info = (struct xt_zone_info *) match->data;

	if (info->flags & XT_ZONE_SRC)
		fputs(" --src-zone", stdout);
	else
		fputs(" --dst-zone", stdout);
	printf(" \"%s\"", info->name);

	if (info->flags & XT_ZONE_CHILDREN)
		fputs(" --children", stdout);

	if (info->flags & XT_ZONE_UMBRELLA)
		fputs(" --umbrella", stdout);
}

static void
zone_save_v1(const void *ip, const struct xt_entry_match *match)
{
	struct xt_zone_info_v1 *info = (struct xt_zone_info_v1 *) match->data;
	int i;

	if (info->flags & XT_ZONE_SRC)
		fputs(" --szones", stdout);
	else
		fputs(" --dzones", stdout);

	printf(" \"");
	for (i = 0; i!=info->count; ++i)
		printf ("%s%s", i ? "," : "", info->names[i]);
	printf("\"");

	if (info->flags & XT_ZONE_CHILDREN)
		fputs(" --children", stdout);

	if (info->flags & XT_ZONE_UMBRELLA)
		fputs(" --umbrella", stdout);
}

static void
zone_save_v2(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_zone_info *info = (struct xt_zone_info *) match->data;

	zone_save_v1(ip, match);

	if (info->flags & XT_ZONE_NOCOUNT)
		fputs(" --nocount", stdout);
}

static struct xtables_match zone_match_v0 = {
	.name		= "zone",
	.family		= NFPROTO_IPV4,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_zone_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_zone_info)),
	.help		= zone_help_v0,
	.parse		= zone_parse_v0,
	.final_check	= zone_final_check,
	.print		= zone_print_v0,
	.save		= zone_save_v0,
	.extra_opts	= zone_opts_v0,
};

static struct xtables_match zone_match_v1 = {
	.name		= "zone",
	.family		= NFPROTO_UNSPEC,
	.revision	= 1,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_zone_info_v1)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_zone_info_v1)),
	.help		= zone_help_v1,
	.parse		= zone_parse_v1,
	.final_check	= zone_final_check,
	.print		= zone_print_v1,
	.save		= zone_save_v1,
	.extra_opts	= zone_opts_v1,
};

static struct xtables_match zone_match_v2 = {
	.name		= "zone",
	.family		= NFPROTO_UNSPEC,
	.revision	= 2,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_zone_info_v2)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_zone_info_v2)),
	.help		= zone_help_v2,
	.x6_parse	= zone_parse_v2,
	.x6_fcheck	= zone_final_check_v2,
	.print		= zone_print_v2,
	.save		= zone_save_v2,
	.x6_options	= zone_opts_v2,
};


void _init(void)
{
	xtables_register_match(&zone_match_v0);
	xtables_register_match(&zone_match_v1);
	xtables_register_match(&zone_match_v2);
}
