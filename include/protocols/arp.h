#ifndef ARP_PROTOCOL_H
#define ARP_PROTOCOL_H

#include "headers.h"

/**
 * @file arp_protocol.h
 * @brief ARP Protocol Parsing Functions
 */

/**
 * @brief Parse the ARP protocol header
 *
 * This function parses the ARP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_arp(const u_char *packet, int verbose, int prof);

#endif /* ARP_PROTOCOL_H */
