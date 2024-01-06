#ifndef POP3_PROTOCOL_H
#define POP3_PROTOCOL_H

#include "headers.h"

/**
 * @file pop3_protocol.h
 * @brief POP3 Protocol Parsing Functions
 */

/**
 * @brief Parse the POP3 protocol header
 *
 * This function parses the POP3 protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the POP3 packet
 */
void parse_pop3(const u_char *packet, int verbose, int prof, int size);

#endif /* POP3_PROTOCOL_H */
