#ifndef H_HEADERS
#define H_HEADERS

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

#define IP_HEADER_LENGTH(ip)    (((ip)->ip_vhl) & 0x0f)
#define IP_VERSION(ip)          (((ip)->ip_vhl) >> 4)


#endif