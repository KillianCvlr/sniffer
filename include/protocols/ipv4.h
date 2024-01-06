#ifndef IPV4_PROTOCOL_H
#define IPV4_PROTOCOL_H

#include "headers.h"

#define IP_HEADER_LENGTH(ip)    (((ip)->ip_vhl) & 0x0f)
#define IP_VERSION(ip)          (((ip)->ip_vhl) >> 4)

/**
 * @file ipv4_protocol.h
 * @brief IPv4 Protocol Parsing Functions
 */

/**
 * @brief Parse the IPv4 protocol header
 *
 * This function parses the IPv4 protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_ipv4(const u_char *packet, int verbose, int prof);

#endif /* IPV4_PROTOCOL_H */
