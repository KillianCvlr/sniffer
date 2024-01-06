#ifndef H_HEADERS
#define H_HEADERS

#include <sys/types.h>
#include <pcap.h>
#include <time.h>

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

// Headers for each protocols implemented :
// ethernet, arp, ipv4, ipv6, icmp, udp, tcp, 
// bootp, dhcp, dns, http, ftp, smtp, imap, telnet, pop3
#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/icmp.h"
#include "protocols/udp.h"
#include "protocols/tcp.h"
#include "protocols/bootp.h"
#include "protocols/bootp_bis.h"
#include "protocols/dns.h"
#include "protocols/http.h"
#include "protocols/ftp.h"
#include "protocols/smtp.h"
#include "protocols/imap.h"
#include "protocols/telnet.h"
#include "protocols/pop3.h"

#include "tool.h"

#endif
