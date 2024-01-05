/**
 * @file
 * @brief Functions for parsing ARP, IPv4, and IPv6 headers in network packets.
 */

#ifndef NETWORK_PARSER_H
#define NETWORK_PARSER_H

#include "tools.h" // Path: include/data_link_layer.h
#include "transport_layer.h"   // Path: include/transport_layer.h

/**
 * @brief Parse ARP header from a network packet.
 *
 * @param packet The network packet to parse.
 * @param ether_dhost Destination MAC address.
 * @param ether_shost Source MAC address.
 * @param verbose Verbosity level.
 * @param prof Profile level.
 */
void parse_arp(const u_char *packet, uint8_t *ether_dhost, uint8_t *ether_shost, int verbose, int prof);

/**
 * @brief Parse IPv4 header from a network packet.
 *
 * @param packet The network packet to parse.
 * @param verbose Verbosity level.
 * @param prof Profile level.
 */
void parse_ipv4(const u_char *packet, int verbose, int prof);

/**
 * @brief Parse IPv6 header from a network packet.
 *
 * @param packet The network packet to parse.
 * @param verbose Verbosity level.
 * @param prof Profile level.
 */
void parse_ipv6(const u_char *packet, int verbose, int prof);

#endif /* NETWORK_PARSER_H */
