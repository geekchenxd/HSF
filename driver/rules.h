#ifndef _RULES_H__
#define _RULES_H__

enum _rules {
	RULES_ALL,
	RULES_NULL,
	RULES_LIST
};

struct ip_filter {
	struct list_head list;
	char ip[16];
};

struct port_filter {
	struct list_head list;
	__be16 port;
};

struct firmwall_rules {
	struct list_head ip_in_head;
	struct list_head ip_out_head;
	struct list_head port_in_head;
	struct list_head port_out_head;
	enum _rules port_in_rules;
	enum _rules port_out_rules;
	enum _rules ip_in_rules;
	enum _rules ip_out_rules;
	enum _rules default_rules;
};


#endif
