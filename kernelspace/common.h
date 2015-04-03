/*
  * common header
  */
#ifndef _WEBPATRIOT_COMMON_H_
#define _WEBPATRIOT_COMMON_H_

#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	         ((unsigned char *)&addr)[0], \
	         ((unsigned char *)&addr)[1], \
	         ((unsigned char *)&addr)[2], \
	         ((unsigned char *)&addr)[3]
#endif

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#endif // _WEBPATRIOT_COMMON_H_