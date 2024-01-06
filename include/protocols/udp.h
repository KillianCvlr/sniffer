#ifndef UDP_PROTOCOL_H
#define UDP_PROTOCOL_H

#include "headers.h"

/**
 * @file udp_protocol.h
 * @brief UDP Protocol Parsing Functions
 */

/**
 * @brief Parse the UDP protocol header
 *
 * This function parses the UDP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the UDP packet
 */
void parse_udp(const u_char *packet, int verbose, int prof, int size);

#endif /* UDP_PROTOCOL_H */
