#ifndef _FIRMWALL_DEBUG_H__
#define _FIRMWALL_DEBUG_H__

#define FIRMWALL_DEBUG 1

#if FIRMWALL_DEBUG
#define FIRMWALL_DEBUG printk
#else
#define FIRMWALL_DEBUG(fmt, args...)
#endif

#endif
