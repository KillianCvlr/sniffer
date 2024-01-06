#ifndef IPV6_PROTOCOL_H
#define IPV6_PROTOCOL_H

#include "headers.h"

/**
 * @file ipv6_protocol.h
 * @brief IPv6 Protocol Parsing Functions
 */

/**
 * @brief Parse the IPv6 protocol header
 *
 * This function parses the IPv6 protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_ipv6(const u_char *packet, int verbose, int prof);

#endif /* IPV6_PROTOCOL_H */
