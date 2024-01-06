#ifndef SMTP_PROTOCOL_H
#define SMTP_PROTOCOL_H

#include "headers.h"

/**
 * @file smtp_protocol.h
 * @brief SMTP Protocol Parsing Functions
 */

// Structure of the SMTP header
struct smtp_header {
    // SMTP command
    char command[10];       // SMTP command (EHLO, HELO, MAIL, RCPT, etc.)

    // SMTP command argument
    char argument[256];     // SMTP command argument

    // Additional SMTP parameters
    char params[512];       // Additional SMTP parameters

    // SMTP response
    uint16_t code;          // SMTP response code (e.g., 220, 500, etc.)
    char response[256];      // SMTP response message
};

/**
 * @brief Parse the SMTP protocol header
 *
 * This function parses the SMTP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the SMTP packet
 */
void parse_smtp(const u_char *packet, int verbose, int prof, int size);

#endif /* SMTP_PROTOCOL_H */
