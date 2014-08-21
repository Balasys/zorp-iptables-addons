#ifndef _XT_RULE_H
#define _XT_RULE_H

enum {
	IPT_RULE_ID = 1 << 0,
};

struct ipt_rule_info {
	u_int8_t flags;
	u_int32_t id;
};

#endif
