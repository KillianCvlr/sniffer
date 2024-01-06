#ifndef ETHERNET_PROTOCOL_H
#define ETHERNET_PROTOCOL_H

#include "headers.h"

/**
 * @file ethernet_protocol.h
 * @brief Ethernet Protocol Parsing Functions
 */

/**
 * @brief Parse the Ethernet protocol header
 *
 * This function parses the Ethernet protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_ethernet(const u_char *packet, int verbose, int prof);

#endif /* ETHERNET_PROTOCOL_H */
