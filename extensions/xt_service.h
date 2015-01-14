#ifndef _XT_SERVICE_H
#define _XT_SERVICE_H

enum xt_service_type {
	XT_SERVICE_TYPE_ANY = 0,
	XT_SERVICE_TYPE_PROXY,
	XT_SERVICE_TYPE_FORWARD,
	XT_SERVICE_TYPE_DENY,
};

enum {
	XT_SERVICE_NAME_ANY = 0,
	XT_SERVICE_NAME_WILDCARD,
	XT_SERVICE_NAME_MATCH,
};

enum {
	XT_SERVICE_NOCOUNT = 1 << 0,
};

#define XT_SERVICE_NAME_LENGTH 117

struct xt_service_info {
	u_int8_t type;
	u_int8_t name_match;
	unsigned char name[XT_SERVICE_NAME_LENGTH + 1];

	unsigned int generation;
	unsigned int service_id;
};

struct xt_service_info_v2 {
	u_int8_t type;
	u_int8_t flags;
	u_int8_t name_match;
	unsigned char name[XT_SERVICE_NAME_LENGTH + 1];

	unsigned int generation;
	unsigned int service_id;
};

#endif
