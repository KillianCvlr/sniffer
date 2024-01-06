#ifndef TCP_PROTOCOL_H
#define TCP_PROTOCOL_H

#include "headers.h"

/**
 * @file tcp_protocol.h
 * @brief TCP Protocol Parsing Functions
 */

/**
 * @brief Parse the TCP protocol header
 *
 * This function parses the TCP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the TCP packet
 */
void parse_tcp(const u_char *packet, int verbose, int prof, int size);

#endif /* TCP_PROTOCOL_H */
