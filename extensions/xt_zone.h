#ifndef _XT_ZONE_H
#define _XT_ZONE_H

/* flags */
enum {
	XT_ZONE_SRC      = 1 << 0,
	XT_ZONE_CHILDREN = 1 << 1,
	XT_ZONE_UMBRELLA = 1 << 2,
	XT_ZONE_NOCOUNT  = 1 << 3,
};

#define XT_ZONE_NAME_LENGTH 126
#define XT_ZONE_NAME_COUNT 32

struct xt_zone_info {
	u_int8_t flags;
	unsigned char name[XT_ZONE_NAME_LENGTH + 1];
};

struct xt_zone_info_v1 {
	u_int8_t flags;
	u_int8_t count;
	unsigned char names[XT_ZONE_NAME_COUNT][XT_ZONE_NAME_LENGTH + 1];
};

struct xt_zone_info_v2 {
	u_int8_t flags;
	u_int8_t count;
	unsigned char names[XT_ZONE_NAME_COUNT][XT_ZONE_NAME_LENGTH + 1];
};

#endif
