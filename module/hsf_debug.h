#ifndef _FIRMWALL_DEBUG_H__
#define _FIRMWALL_DEBUG_H__

#define FIREWALL_DEBUG_OPT 1

#if FIREWALL_DEBUG_OPT
#define FIREWALL_DEBUG printk
#else
#define FIREWALL_DEBUG(fmt, args...)
#endif

#endif
