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
"  --rule-id <id>		match rule id\n",
XTABLES_VERSION);
}

enum {
	O_RULE_ID 	= 0,
	F_ID 		= 1 << O_RULE_ID,
};

#define s struct xt_rule_info
static struct xt_option_entry rule_opts[] = {
	{ .name = "rule-id",	.id = O_RULE_ID,	.type = XTTYPE_UINT32,
	  .flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, id), .min = 1 },
	XTOPT_TABLEEND,
};
#undef s

static void
rule_parse(struct xt_option_call *cb)
{
        xtables_option_parse(cb);
}

static void
rule_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct xt_rule_info *info = (struct xt_rule_info *) match->data;

	printf(" rule");
	printf(" rule-id %d", info->id);
}

static void
rule_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_rule_info *info = (struct xt_rule_info *)match->data;

	printf(" --rule-id %d", info->id);
}

static struct xtables_match rule = {
	.name		= "rule",
	.family		= NFPROTO_UNSPEC,
	.version	= XTABLES_VERSION,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_rule_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_rule_info)),
	.help		= rule_help,
	.x6_parse	= rule_parse,
	.print		= rule_print,
	.save		= rule_save,
	.x6_options	= rule_opts
};

void _init(void)
{
	xtables_register_match(&rule);
}
