#ifndef _XT_RULE_H
#define _XT_RULE_H

enum {
	XT_RULE_ID = 1 << 0,
	XT_RULE_NOCOUNT = 1 << 1,
};

struct xt_rule_info {
	u_int8_t flags;
	u_int32_t id;
};

#endif
