#ifndef _XT_RULE_H
#define _XT_RULE_H

enum {
	XT_RULE_ID = 1 << 0,
};

struct xt_rule_info {
	u_int32_t id;
};

#endif
