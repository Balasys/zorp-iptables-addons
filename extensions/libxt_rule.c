/*
 * Shared library add-on to iptables to match
 * packets based on KZorp rules
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
#include "xt_rule.h"

static void
rule_help(void)
{
	printf(
"rule v%s options:\n"
"  --rule-id <svc>		match rule id\n",
XTABLES_VERSION);
}

static struct option rule_opts[] = {
	{ .name = "rule-id", .has_arg = true, .val = '1' },
	{ .name = NULL }
};

enum {
	F_ID = 1 << 0,
};

static int
rule_parse(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct ipt_rule_info *info =
			(struct ipt_rule_info *) (*match)->data;

	switch (c) {
	case '1': /* rule-id */
		if (*flags & F_ID)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--rule-id' "
				   "more than once\n");
		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--rule-id' must be accompanied by "
				   "a rule id\n");
		info->id = atoi(optarg);
		if (info->id <= 0)
			xtables_error(PARAMETER_PROBLEM,
				   "rule id must be a positive integer "
				   "value\n");
		info->flags |= IPT_RULE_ID;
		*flags |= F_ID;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
rule_final_check(unsigned int flags)
{
	if (!(flags & F_ID))
		xtables_error(PARAMETER_PROBLEM,
			   "You must specify `--rule-id'\n");
}

static void
rule_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct ipt_rule_info *info = (struct ipt_rule_info *) match->data;

	printf(" rule");
	printf(" rule-id %d", info->id);
}

static void
rule_save(const void *ip, const struct xt_entry_match *match)
{
	struct ipt_rule_info *info = (struct ipt_rule_info *)match->data;

	printf(" --rule-id %d", info->id);
}

static struct xtables_match rule = {
	.name		= "rule",
	.family		= NFPROTO_UNSPEC,
	.version	= XTABLES_VERSION,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct ipt_rule_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_rule_info)),
	.help		= rule_help,
	.parse		= rule_parse,
	.final_check	= rule_final_check,
	.print		= rule_print,
	.save		= rule_save,
	.extra_opts	= rule_opts
};

void _init(void)
{
	xtables_register_match(&rule);
}
