#ifndef IMAP_PROTOCOL_H
#define IMAP_PROTOCOL_H

#include "headers.h"

/**
 * @file imap_protocol.h
 * @brief IMAP Protocol Parsing Functions
 */

/**
 * @brief Parse the IMAP protocol header
 *
 * This function parses the IMAP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the IMAP packet
 */
void parse_imap(const u_char *packet, int verbose, int prof, int size);

/**
 * @brief Parse IMAP options
 *
 * This function parses IMAP options and prints relevant information.
 *
 * @param packet_arg The packet data
 * @param buff Buffer to store options
 */
void options_imap(const u_char *packet_arg, char *buff);

#endif /* IMAP_PROTOCOL_H */
