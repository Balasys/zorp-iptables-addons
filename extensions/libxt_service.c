/*
 * Shared library add-on to iptables to match
 * packets based on KZorp services
 *
 * Copyright (C) 2006,2009 BalaBit IT Ltd.
 * Author: KOVACS Krisztian <hidden@balabit.hu>
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_service.h"

static void
service_help(void)
{
	printf(
"service v%s options:\n"
"  --service-name <svc>		match service name\n"
"  --service-type <mode>	match service type: forward | proxy\n",
XTABLES_VERSION);
}

static struct option service_opts[] = {
	{ .name = "service-name", .has_arg = true, .val = '1' },
	{ .name = "service-type", .has_arg = true, .val = '2' },
	{ .name = NULL }
};

enum {
	O_NAME		= 0,
	O_TYPE		= 1,
	F_NAME		= 1 << O_NAME,
	F_TYPE		= 1 << O_TYPE,
};

#define s struct xt_service_info
static struct xt_option_entry service_opts_v2[] = {
	{ .name = "service-name",	.id = O_NAME,		.type = XTTYPE_STRING,
	  .flags = XTOPT_PUT, XTOPT_POINTER(s, name), .size = XT_SERVICE_NAME_LENGTH },
	{ .name = "service-type",	.id = O_TYPE,		.type = XTTYPE_STRING },
	{ .name = NULL }
};
#undef s

static int
service_parse(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct xt_service_info *info =
			(struct xt_service_info *) (*match)->data;

	switch (c) {
	case '1': /* service-name */
		if (*flags & F_NAME)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--service-name' "
				   "more than once\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--service-name' must be accompanied by "
				   "a service name\n");

		strncpy((char *)info->name, optarg, sizeof(info->name));
		info->name[XT_SERVICE_NAME_LENGTH] = '\0';

		if (strcmp(optarg, "*") == 0)
			info->name_match = XT_SERVICE_NAME_WILDCARD;
		else
			info->name_match = XT_SERVICE_NAME_MATCH;

		*flags |= F_NAME;
		break;

	case '2': /* service-type */
		if (*flags & F_TYPE)
			xtables_error(PARAMETER_PROBLEM,
				  "Cannot specify `--service-type' "
				  "more than once\n");

		if ((strlen(optarg) == 0) ||
		    ((strcmp(optarg, "forward") != 0) &&
		     (strcmp(optarg, "proxy") != 0)))
			xtables_error(PARAMETER_PROBLEM,
				   "`--service-type' must be accompanied "
				   "by a valid service type\n");

		if (strcmp(optarg, "forward") == 0)
			info->type = XT_SERVICE_TYPE_FORWARD;
		else
			info->type = XT_SERVICE_TYPE_PROXY;

		*flags |= F_TYPE;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
service_parse_v2(struct xt_option_call *cb)
{
	struct xt_service_info_v2 *info = cb->data;

	xtables_option_parse(cb);

	switch (cb->entry->id) {
	case O_NAME:
		if (strcmp(cb->arg, "*") == 0)
			info->name_match = XT_SERVICE_NAME_WILDCARD;
		else
			info->name_match = XT_SERVICE_NAME_MATCH;
		break;

	case O_TYPE:
		if (strcmp(optarg, "forward") == 0)
			info->type = XT_SERVICE_TYPE_FORWARD;
		else if (strcmp(optarg, "proxy") != 0)
			info->type = XT_SERVICE_TYPE_PROXY;
		else
			xtables_error(PARAMETER_PROBLEM,
				   "`--service-type' must be accompanied "
				   "by a valid service type\n");
		break;
	}
}


static void
service_final_check(unsigned int flags)
{
	if (!(flags & (F_NAME | F_TYPE)))
		xtables_error(PARAMETER_PROBLEM,
			   "You must specify either `--service-name' "
			   "or `--service-type'\n");
}

static void
service_final_check_v2(struct xt_fcheck_call *cb)
{
	service_final_check(cb->xflags);
}

static void
service_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_service_info *info = (struct xt_service_info *) match->data;

	fputs("service ", stdout);
	if (info->name_match != XT_SERVICE_NAME_ANY)
		printf(" name %s", info->name);
	if (info->type != XT_SERVICE_TYPE_ANY)
		printf(" type %s",
		       (info->type == XT_SERVICE_TYPE_PROXY) ? "proxy "
							      : "forward ");
}

static void
service_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_service_info *info = (struct xt_service_info *)match->data;

	if (info->name_match != XT_SERVICE_NAME_ANY)
		printf(" --service-name %s", info->name);
	if (info->type != XT_SERVICE_TYPE_ANY)
		printf(" --service-type %s",
		       (info->type == XT_SERVICE_TYPE_PROXY) ? "proxy "
							      : "forward ");
}

static struct xtables_match service_match = {
 	.name		= "service",
 	.family		= NFPROTO_UNSPEC,
	.revision	= 1,
 	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_service_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_service_info)),
 	.help		= service_help,
	.parse		= service_parse,
	.final_check	= service_final_check,
 	.print		= service_print,
 	.save		= service_save,
	.extra_opts	= service_opts
};

static struct xtables_match service_match_v2 = {
	.name		= "service",
	.family		= NFPROTO_UNSPEC,
	.revision	= 2,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_service_info_v2)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_service_info_v2)),
	.help		= service_help,
	.x6_parse	= service_parse_v2,
	.x6_fcheck	= service_final_check_v2,
	.print		= service_print,
	.save		= service_save,
	.x6_options	= service_opts_v2
};


void _init(void)
{
	xtables_register_match(&service_match);
	xtables_register_match(&service_match_v2);
}
