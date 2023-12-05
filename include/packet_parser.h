#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H
#include "headers.h"
#include <pcap.h>

void parse_ethernet(const u_char *packet);
void parse_ip(const u_char *packet);
void parse_udp(const u_char *packet);
void parse_tcp(const u_char *packet);
void parse_icmp(const u_char *packet);
void parse_arp(const u_char *packet);
void parse_bootp(const u_char *packet);
void parse_dhcp(const u_char *packet);
void parse_dns(const u_char *packet);
void parse_http(const u_char *packet);
void parse_ftp(const u_char *packet);
void parse_smtp(const u_char *packet);
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif // PACKET_PARSER_H