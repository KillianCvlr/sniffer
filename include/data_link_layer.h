#ifndef DATA_LINK_LAYER_H
#define DATA_LINK_LAYER_H


#include "tools.h"        // Path: include/tools.h
#include "headers.h"      // Path: include/headers.h

/**
 * @brief Parse Ethernet header from a network packet.
 *
 * This function parses the Ethernet header from a given network packet and provides
 * detailed information about the Ethernet header fields. It also handles the
 * parsing of higher-layer protocols (ARP, IPv4, IPv6) based on the EtherType field.
 *
 * @param packet The network packet to parse.
 * @param verbose Verbosity level.
 * @param prof Profile level.
 */
void parse_ethernet(const u_char *packet, int verbose, int prof);

#endif 